use {
    crate::{
        add_tag_to_name, boxed_error, genesis::DEFAULT_INTERNAL_NODE_SOL_TO_STAKE_SOL_RATIO,
        k8s_helpers, SOLANA_ROOT,
    },
    k8s_openapi::{
        api::{
            apps::v1::ReplicaSet,
            core::v1::{
                EnvVar, EnvVarSource, ExecAction, Namespace, Node, ObjectFieldSelector, Probe,
                Secret, SecretVolumeSource, Service, Volume, VolumeMount,
            },
        },
        apimachinery::pkg::api::resource::Quantity,
        ByteString,
    },
    kube::{
        api::{Api, ListParams, PostParams},
        Client,
    },
    log::*,
    solana_sdk::{
        hash::Hash, pubkey::Pubkey, signature::keypair::read_keypair_file, signer::Signer,
    },
    std::{collections::BTreeMap, error::Error, path::PathBuf},
};

pub struct ValidatorConfig<'a> {
    pub tpu_enable_udp: bool,
    pub tpu_disable_quic: bool,
    pub gpu_mode: &'a str, // TODO: this is not implemented yet
    pub internal_node_sol: f64,
    pub internal_node_stake_sol: f64,
    pub wait_for_supermajority: Option<u64>,
    pub warp_slot: Option<u64>,
    pub shred_version: Option<u16>,
    pub bank_hash: Option<Hash>,
    pub max_ledger_size: Option<u64>,
    pub skip_poh_verify: bool,
    pub no_snapshot_fetch: bool,
    pub require_tower: bool,
    pub enable_full_rpc: bool,
    pub entrypoints: Vec<String>,
    pub known_validators: Option<Vec<Pubkey>>,
}

impl<'a> std::fmt::Display for ValidatorConfig<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let known_validators = match &self.known_validators {
            Some(validators) => validators
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            None => "None".to_string(),
        };
        write!(
            f,
            "Runtime Config\n\
             tpu_enable_udp: {}\n\
             tpu_disable_quic: {}\n\
             gpu_mode: {}\n\
             internal_node_sol: {}\n\
             internal_node_stake_sol: {}\n\
             wait_for_supermajority: {:?}\n\
             warp_slot: {:?}\n\
             shred_version: {:?}\n\
             bank_hash: {:?}\n\
             max_ledger_size: {:?}\n\
             skip_poh_verify: {}\n\
             no_snapshot_fetch: {}\n\
             require_tower: {}\n\
             enable_full_rpc: {}\n\
             entrypoints: {:?}\n\
             known_validators: {:?}",
            self.tpu_enable_udp,
            self.tpu_disable_quic,
            self.gpu_mode,
            self.internal_node_sol,
            self.internal_node_stake_sol,
            self.wait_for_supermajority,
            self.warp_slot,
            self.shred_version,
            self.bank_hash,
            self.max_ledger_size,
            self.skip_poh_verify,
            self.no_snapshot_fetch,
            self.require_tower,
            self.enable_full_rpc,
            self.entrypoints.join(", "),
            known_validators,
        )
    }
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub num_clients: i32,
    pub client_delay_start: u64,
    pub client_type: String,
    pub client_to_run: String,
    pub bench_tps_args: Option<Vec<String>>,
    pub target_node: Option<Pubkey>,
    pub duration: u64,
    pub num_nodes: Option<u64>,
    pub run_client: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    pub host: String,
    pub port: String,
    pub database: String,
    pub username: String,
    password: String,
}

impl Metrics {
    pub fn new(
        host: String,
        port: String,
        database: String,
        username: String,
        password: String,
    ) -> Self {
        Metrics {
            host,
            port,
            database,
            username,
            password,
        }
    }
    pub fn to_env_string(&self) -> String {
        format!(
            "host={}:{},db={},u={},p={}",
            self.host, self.port, self.database, self.username, self.password
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NodeAffinityConfig {
    node_type: Option<NodeType>,
    geographic_region: Option<GeographicRegion>,
}

impl NodeAffinityConfig {
    // choose region over node_type if both provided
    pub fn new(node_type: Option<NodeType>, region: Option<GeographicRegion>) -> Self {
        match (node_type, region) {
            (Some(node_type), None) => Self {
                node_type: Some(node_type),
                geographic_region: None,
            },
            (None, Some(region)) => Self {
                node_type: None,
                geographic_region: Some(region),
            },
            (Some(_), Some(region)) => Self {
                node_type: None,
                geographic_region: Some(region),
            },
            _ => Self {
                node_type: Some(NodeType::Mixed),
                geographic_region: None,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NodeType {
    Equinix,
    Lumen,
    Mixed,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Equinix => write!(f, "eq-"),
            NodeType::Lumen => write!(f, "lum-"),
            NodeType::Mixed => write!(f, "Mixed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GeographicRegion {
    HongKong,
}

impl std::fmt::Display for GeographicRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeographicRegion::HongKong => write!(f, "eq-hk"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PodRequests {
    requests: BTreeMap<String, Quantity>,
}

impl PodRequests {
    pub fn new(cpu_requests: String, memory_requests: String) -> PodRequests {
        PodRequests {
            requests: vec![
                ("cpu".to_string(), Quantity(cpu_requests)),
                ("memory".to_string(), Quantity(memory_requests)),
            ]
            .into_iter()
            .collect(),
        }
    }
}

pub struct Kubernetes<'a> {
    client: Client,
    namespace: &'a str,
    validator_config: &'a mut ValidatorConfig<'a>,
    client_config: ClientConfig,
    pub metrics: Option<Metrics>,
    nodes: Option<Vec<String>>,
    node_affinity: NodeAffinityConfig,
    deployment_tag: Option<String>,
    pod_requests: PodRequests,
}

impl<'a> Kubernetes<'a> {
    pub async fn new(
        namespace: &'a str,
        validator_config: &'a mut ValidatorConfig<'a>,
        client_config: ClientConfig,
        metrics: Option<Metrics>,
        node_affinity: NodeAffinityConfig,
        deployment_tag: Option<String>,
        pod_requests: PodRequests,
    ) -> Kubernetes<'a> {
        Kubernetes {
            client: Client::try_default().await.unwrap(),
            namespace,
            validator_config,
            client_config,
            metrics,
            nodes: None,
            node_affinity,
            deployment_tag,
            pod_requests,
        }
    }

    pub fn set_shred_version(&mut self, shred_version: u16) {
        self.validator_config.shred_version = Some(shred_version);
    }

    pub fn set_bank_hash(&mut self, bank_hash: Hash) {
        self.validator_config.bank_hash = Some(bank_hash);
    }

    fn generate_command_flags(&self, flags: &mut Vec<String>) {
        if self.validator_config.tpu_enable_udp {
            flags.push("--tpu-enable-udp".to_string());
        }
        if self.validator_config.tpu_disable_quic {
            flags.push("--tpu-disable-quic".to_string());
        }
        if self.validator_config.skip_poh_verify {
            flags.push("--skip-poh-verify".to_string());
        }
        if self.validator_config.no_snapshot_fetch {
            flags.push("--no-snapshot-fetch".to_string());
        }
        if self.validator_config.require_tower {
            flags.push("--require-tower".to_string());
        }
        if self.validator_config.enable_full_rpc {
            flags.push("--enable-rpc-transaction-history".to_string());
            flags.push("--enable-extended-tx-metadata-storage".to_string());
        }

        if let Some(limit_ledger_size) = self.validator_config.max_ledger_size {
            flags.push("--limit-ledger-size".to_string());
            flags.push(limit_ledger_size.to_string());
        }
    }

    fn generate_bootstrap_command_flags(&self) -> Vec<String> {
        let mut flags: Vec<String> = Vec::new();
        self.generate_command_flags(&mut flags);
        if let Some(slot) = self.validator_config.wait_for_supermajority {
            flags.push("--wait-for-supermajority".to_string());
            flags.push(slot.to_string());
        }

        if let Some(bank_hash) = self.validator_config.bank_hash {
            flags.push("--expected-bank-hash".to_string());
            flags.push(bank_hash.to_string());
        }

        if let Some(limit_ledger_size) = self.validator_config.max_ledger_size {
            flags.push("--limit-ledger-size".to_string());
            flags.push(limit_ledger_size.to_string());
        }

        flags
    }

    fn add_known_validators_if_exists(&self, flags: &mut Vec<String>) {
        if let Some(known_validators) = &self.validator_config.known_validators {
            for key in known_validators.iter() {
                flags.push("--known-validator".to_string());
                flags.push(key.to_string());
            }
        }
    }

    fn generate_validator_command_flags(&self, validator_stake: &Option<f64>) -> Vec<String> {
        let mut flags: Vec<String> = Vec::new();
        self.generate_command_flags(&mut flags);

        flags.push("--internal-node-stake-sol".to_string());
        if let Some(stake) = validator_stake {
            flags.push(stake.to_string());
        } else {
            flags.push(self.validator_config.internal_node_stake_sol.to_string());
        }

        flags.push("--internal-node-sol".to_string());
        if let Some(stake) = validator_stake {
            flags.push((DEFAULT_INTERNAL_NODE_SOL_TO_STAKE_SOL_RATIO * stake).to_string());
        } else {
            flags.push(self.validator_config.internal_node_sol.to_string());
        }

        if let Some(shred_version) = self.validator_config.shred_version {
            flags.push("--expected-shred-version".to_string());
            flags.push(shred_version.to_string());
        }

        self.add_known_validators_if_exists(&mut flags);

        flags
    }

    fn generate_non_voting_command_flags(&self) -> Vec<String> {
        let mut flags: Vec<String> = Vec::new();
        self.generate_command_flags(&mut flags);
        if let Some(shred_version) = self.validator_config.shred_version {
            flags.push("--expected-shred-version".to_string());
            flags.push(shred_version.to_string());
        }

        self.add_known_validators_if_exists(&mut flags);

        flags
    }

    fn generate_client_command_flags(&self) -> Vec<String> {
        let mut flags = vec![];

        flags.push(self.client_config.client_to_run.clone()); //client to run
        if let Some(bench_tps_args) = &self.client_config.bench_tps_args {
            flags.push(bench_tps_args.join(" "));
        }

        flags.push(self.client_config.client_type.clone());

        if let Some(target_node) = self.client_config.target_node {
            flags.push("--target-node".to_string());
            flags.push(target_node.to_string());
        }

        flags.push("--duration".to_string());
        flags.push(self.client_config.duration.to_string());

        if let Some(num_nodes) = self.client_config.num_nodes {
            flags.push("--num-nodes".to_string());
            flags.push(num_nodes.to_string());
        }

        flags
    }

    pub async fn namespace_exists(&self) -> Result<bool, kube::Error> {
        let namespaces: Api<Namespace> = Api::all(self.client.clone());
        let namespace_list = namespaces.list(&ListParams::default()).await?;

        for namespace in namespace_list.items {
            if let Some(ns) = namespace.metadata.name {
                if ns == *self.namespace {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn create_bootstrap_validator_replica_set(
        &mut self,
        container_name: &str,
        image_name: &str,
        secret_name: Option<String>,
        label_selector: &BTreeMap<String, String>,
    ) -> Result<ReplicaSet, Box<dyn Error>> {
        let mut env_vars = vec![EnvVar {
            name: "MY_POD_IP".to_string(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    field_path: "status.podIP".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }];

        if self.metrics.is_some() {
            env_vars.push(self.get_metrics_env_var_secret())
        }

        let accounts_volume = Some(vec![Volume {
            name: "bootstrap-accounts-volume".into(),
            secret: Some(SecretVolumeSource {
                secret_name,
                ..Default::default()
            }),
            ..Default::default()
        }]);

        let accounts_volume_mount = Some(vec![VolumeMount {
            name: "bootstrap-accounts-volume".to_string(),
            mount_path: "/home/solana/bootstrap-accounts".to_string(),
            ..Default::default()
        }]);

        let mut command =
            vec!["/home/solana/k8s-cluster-scripts/bootstrap-startup-script.sh".to_string()];
        command.extend(self.generate_bootstrap_command_flags());

        for c in command.iter() {
            debug!("bootstrap command: {}", c);
        }

        k8s_helpers::create_replica_set(
            "bootstrap-validator",
            self.namespace,
            label_selector,
            container_name,
            image_name,
            env_vars,
            &command,
            accounts_volume,
            accounts_volume_mount,
            None,
            self.nodes.clone(),
            self.pod_requests.requests.clone(),
        )
    }

    pub async fn deploy_secret(&self, secret: &Secret) -> Result<Secret, kube::Error> {
        let secrets_api: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
        secrets_api.create(&PostParams::default(), secret).await
    }

    pub fn create_metrics_secret(&self) -> Result<Secret, Box<dyn Error>> {
        let mut data = BTreeMap::new();
        if let Some(metrics) = &self.metrics {
            data.insert(
                "SOLANA_METRICS_CONFIG".to_string(),
                ByteString(metrics.to_env_string().into_bytes()),
            );
        } else {
            return Err(boxed_error!(format!(
                "Called create_metrics_secret() but metrics were not provided."
            )));
        }

        Ok(k8s_helpers::create_secret("solana-metrics-secret", data))
    }

    pub fn get_metrics_env_var_secret(&self) -> EnvVar {
        EnvVar {
            name: "SOLANA_METRICS_CONFIG".to_string(),
            value_from: Some(k8s_openapi::api::core::v1::EnvVarSource {
                secret_key_ref: Some(k8s_openapi::api::core::v1::SecretKeySelector {
                    name: Some("solana-metrics-secret".to_string()),
                    key: "SOLANA_METRICS_CONFIG".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub fn create_bootstrap_secret(&mut self, secret_name: &str) -> Result<Secret, Box<dyn Error>> {
        let faucet_key_path = SOLANA_ROOT.join("config-k8s/faucet.json");
        let identity_key_path = SOLANA_ROOT.join("config-k8s/bootstrap-validator/identity.json");
        let vote_key_path = SOLANA_ROOT.join("config-k8s/bootstrap-validator/vote-account.json");
        let stake_key_path = SOLANA_ROOT.join("config-k8s/bootstrap-validator/stake-account.json");

        let bootstrap_keypair = read_keypair_file(identity_key_path.clone())
            .expect("Failed to read bootstrap validator keypair file");

        //TODO: need to fix and not read the json path twice
        self.add_known_validator(bootstrap_keypair.pubkey());

        let key_files = vec![
            (faucet_key_path, "faucet"),
            (identity_key_path, "identity"),
            (vote_key_path, "vote"),
            (stake_key_path, "stake"),
        ];

        let mut secret_name_with_optional_tag = secret_name.to_string();
        if let Some(tag) = &self.deployment_tag {
            secret_name_with_optional_tag = add_tag_to_name(secret_name, tag);
        }

        k8s_helpers::create_secret_from_files(secret_name_with_optional_tag.as_str(), &key_files)
    }

    pub fn create_validator_secret(&self, validator_index: i32) -> Result<Secret, Box<dyn Error>> {
        let mut secret_name_with_optional_tag =
            format!("validator-accounts-secret-{}", validator_index);
        if let Some(tag) = &self.deployment_tag {
            secret_name_with_optional_tag =
                add_tag_to_name(secret_name_with_optional_tag.as_str(), tag);
        }

        let key_path = SOLANA_ROOT.join("config-k8s");

        let accounts = ["identity", "vote", "stake"];
        let key_files: Vec<(PathBuf, &str)> = accounts
            .iter()
            .map(|&account| {
                let mut validator_with_optional_tag = "validator".to_string();
                if let Some(tag) = &self.deployment_tag {
                    validator_with_optional_tag =
                        add_tag_to_name(validator_with_optional_tag.as_str(), tag);
                }

                let file_name = if account == "identity" {
                    format!(
                        "{}-{}-{}.json",
                        validator_with_optional_tag, account, validator_index
                    )
                } else {
                    format!(
                        "{}-{}-account-{}.json",
                        validator_with_optional_tag, account, validator_index
                    )
                };
                (key_path.join(file_name), account)
            })
            .collect();

        k8s_helpers::create_secret_from_files(&secret_name_with_optional_tag, &key_files)
    }

    // use validator identity for client 1
    // all clients get same identity which may not be good or desirable
    pub fn create_client_secret(&self, client_index: i32) -> Result<Secret, Box<dyn Error>> {
        let mut secret_name_with_optional_tag = format!("client-accounts-secret-{}", client_index);
        if let Some(tag) = &self.deployment_tag {
            secret_name_with_optional_tag =
                add_tag_to_name(secret_name_with_optional_tag.as_str(), tag);
        }

        // validator0 key being used as the identity key for the client
        let mut validator_with_optional_tag = "validator".to_string();
        if let Some(tag) = &self.deployment_tag {
            validator_with_optional_tag =
                add_tag_to_name(validator_with_optional_tag.as_str(), tag);
        }
        let identity_file = format!("{}-{}-{}.json", validator_with_optional_tag, "identity", 0);

        let faucet_key_path = SOLANA_ROOT.join("config-k8s/faucet.json");

        let key_path = SOLANA_ROOT.join("config-k8s");
        let identity_key_path = key_path.join(identity_file);

        let key_files = vec![(faucet_key_path, "faucet"), (identity_key_path, "identity")];

        k8s_helpers::create_secret_from_files(&secret_name_with_optional_tag, &key_files)
    }

    pub fn create_non_voting_secret(&self, nvv_index: i32) -> Result<Secret, Box<dyn Error>> {
        let mut secret_name_with_optional_tag =
            format!("non-voting-validator-accounts-secret-{}", nvv_index);
        if let Some(tag) = &self.deployment_tag {
            secret_name_with_optional_tag =
                add_tag_to_name(secret_name_with_optional_tag.as_str(), tag);
        }

        let config_path = SOLANA_ROOT.join("config-k8s");

        let accounts = ["identity", "stake"];
        let mut key_files: Vec<(PathBuf, &str)> = accounts
            .iter()
            .map(|&account| {
                let mut validator_with_optional_tag = "non-voting-validator".to_string();
                if let Some(tag) = &self.deployment_tag {
                    validator_with_optional_tag =
                        add_tag_to_name(validator_with_optional_tag.as_str(), tag);
                }

                let file_name = if account == "identity" {
                    format!(
                        "{}-{}-{}.json",
                        validator_with_optional_tag, account, nvv_index
                    )
                } else {
                    format!(
                        "{}-{}-account-{}.json",
                        validator_with_optional_tag, account, nvv_index
                    )
                };
                (config_path.join(file_name), account)
            })
            .collect();

        key_files.push((config_path.join("faucet.json"), "faucet"));

        k8s_helpers::create_secret_from_files(&secret_name_with_optional_tag, &key_files)
    }

    pub fn add_known_validator(&mut self, pubkey: Pubkey) {
        if let Some(ref mut known_validators) = self.validator_config.known_validators {
            known_validators.push(pubkey);
        } else {
            let new_known_validators = vec![pubkey];
            self.validator_config.known_validators = Some(new_known_validators);
        }

        info!("pubkey added to known validators: {:?}", pubkey);
    }

    pub async fn deploy_replicas_set(
        &self,
        replica_set: &ReplicaSet,
    ) -> Result<ReplicaSet, kube::Error> {
        let api: Api<ReplicaSet> = Api::namespaced(self.client.clone(), self.namespace);
        let post_params = PostParams::default();
        info!("creating replica set!");
        // Apply the ReplicaSet
        api.create(&post_params, replica_set).await
    }

    pub async fn deploy_service(&self, service: &Service) -> Result<Service, kube::Error> {
        let post_params = PostParams::default();
        // Create an API instance for Services in the specified namespace
        let service_api: Api<Service> = Api::namespaced(self.client.clone(), self.namespace);

        // Create the Service object in the cluster
        service_api.create(&post_params, service).await
    }

    pub async fn check_replica_set_ready(
        &self,
        replica_set_name: &str,
    ) -> Result<bool, kube::Error> {
        let replica_sets: Api<ReplicaSet> = Api::namespaced(self.client.clone(), self.namespace);
        let replica_set = replica_sets.get(replica_set_name).await?;

        let desired_validators = replica_set.spec.as_ref().unwrap().replicas.unwrap_or(1);
        let available_validators = replica_set
            .status
            .as_ref()
            .unwrap()
            .available_replicas
            .unwrap_or(0);

        Ok(available_validators >= desired_validators)
    }

    fn set_non_bootstrap_environment_variables(&self) -> Vec<EnvVar> {
        vec![
            k8s_helpers::create_environment_variable(
                "NAMESPACE",
                None,
                Some("metadata.namespace".to_string()),
            ),
            k8s_helpers::create_environment_variable(
                "BOOTSTRAP_RPC_ADDRESS",
                Some("bootstrap-validator-service.$(NAMESPACE).svc.cluster.local:8899".to_string()),
                None,
            ),
            k8s_helpers::create_environment_variable(
                "BOOTSTRAP_GOSSIP_ADDRESS",
                Some("bootstrap-validator-service.$(NAMESPACE).svc.cluster.local:8001".to_string()),
                None,
            ),
            k8s_helpers::create_environment_variable(
                "BOOTSTRAP_FAUCET_ADDRESS",
                Some("bootstrap-validator-service.$(NAMESPACE).svc.cluster.local:9900".to_string()),
                None,
            ),
        ]
    }

    fn set_load_balancer_environment_variables(&self) -> Vec<EnvVar> {
        vec![
            k8s_helpers::create_environment_variable(
                "LOAD_BALANCER_RPC_ADDRESS",
                Some(
                    "bootstrap-and-non-voting-lb-service.$(NAMESPACE).svc.cluster.local:8899"
                        .to_string(),
                ),
                None,
            ),
            k8s_helpers::create_environment_variable(
                "LOAD_BALANCER_GOSSIP_ADDRESS",
                Some(
                    "bootstrap-and-non-voting-lb-service.$(NAMESPACE).svc.cluster.local:8001"
                        .to_string(),
                ),
                None,
            ),
            k8s_helpers::create_environment_variable(
                "LOAD_BALANCER_FAUCET_ADDRESS",
                Some(
                    "bootstrap-and-non-voting-lb-service.$(NAMESPACE).svc.cluster.local:9900"
                        .to_string(),
                ),
                None,
            ),
        ]
    }

    pub fn node_count(&self) -> usize {
        if let Some(nodes) = &self.nodes {
            return nodes.len();
        }
        0
    }

    pub fn nodes(&self) -> Option<Vec<String>> {
        self.nodes.clone()
    }

    pub async fn set_nodes(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(region) = self.node_affinity.geographic_region {
            match self.get_nodes_by_region(region).await {
                Ok(nodes) => self.nodes = nodes,
                Err(err) => {
                    return Err(boxed_error!(format!(
                        "Failed to get {} nodes by region",
                        err
                    )))
                }
            };
        } else {
            if let Some(node_type) = self.node_affinity.node_type {
                match self.get_nodes_by_type(node_type).await {
                    Ok(nodes) => self.nodes = nodes,
                    Err(err) => {
                        return Err(boxed_error!(format!("Failed to get {} nodes by type", err)))
                    }
                }
            }
        }
        if let Some(nodes) = &self.nodes {
            for node in nodes.iter() {
                info!("node: {:?}", node);
            }
        } else {
            info!("nodes is empty!");
        }

        Ok(())
    }

    async fn get_nodes(&self, label_value: &str) -> Result<Option<Vec<String>>, Box<dyn Error>> {
        let nodes: Api<Node> = Api::all(self.client.clone());
        let lp = ListParams::default();
        let node_list = nodes.list(&lp).await?;

        // Filter nodes by label value pattern
        let mut matching_nodes = Vec::new();
        for node in node_list {
            if let Some(labels) = node.metadata.labels {
                for (key, value) in labels.iter() {
                    if key == "topology.kubernetes.io/region" && value.starts_with(label_value) {
                        if let Some(name) = &node.metadata.name {
                            matching_nodes.push(name.clone());
                        }
                    }
                }
            }
        }
        Ok(Some(matching_nodes))
    }

    async fn get_nodes_by_region(
        &self,
        region: GeographicRegion,
    ) -> Result<Option<Vec<String>>, Box<dyn Error>> {
        self.get_nodes(&region.to_string()).await
    }

    async fn get_nodes_by_type(
        &self,
        node_type: NodeType,
    ) -> Result<Option<Vec<String>>, Box<dyn Error>> {
        self.get_nodes(&node_type.to_string()).await
    }

    pub fn create_validator_replica_set(
        &mut self,
        container_name: &str,
        validator_index: i32,
        image_name: &str,
        secret_name: Option<String>,
        label_selector: &BTreeMap<String, String>,
        validator_stake: &Option<f64>,
    ) -> Result<ReplicaSet, Box<dyn Error>> {
        let mut env_vars = self.set_non_bootstrap_environment_variables();
        if self.metrics.is_some() {
            env_vars.push(self.get_metrics_env_var_secret())
        }
        env_vars.append(&mut self.set_load_balancer_environment_variables());

        let accounts_volume = Some(vec![Volume {
            name: format!("validator-accounts-volume-{}", validator_index),
            secret: Some(SecretVolumeSource {
                secret_name,
                ..Default::default()
            }),
            ..Default::default()
        }]);

        let accounts_volume_mount = Some(vec![VolumeMount {
            name: format!("validator-accounts-volume-{}", validator_index),
            mount_path: "/home/solana/validator-accounts".to_string(),
            ..Default::default()
        }]);

        let mut command =
            vec!["/home/solana/k8s-cluster-scripts/validator-startup-script.sh".to_string()];
        command.extend(self.generate_validator_command_flags(validator_stake));

        for c in command.iter() {
            debug!("validator command: {}", c);
        }

        let mut replica_set_name_with_optional_tag = "validator".to_string();
        if let Some(tag) = &self.deployment_tag {
            replica_set_name_with_optional_tag =
                add_tag_to_name(replica_set_name_with_optional_tag.as_str(), tag);
        }
        replica_set_name_with_optional_tag =
            format!("{}-{}", replica_set_name_with_optional_tag, validator_index);

        k8s_helpers::create_replica_set(
            replica_set_name_with_optional_tag.as_str(),
            self.namespace,
            label_selector,
            container_name,
            image_name,
            env_vars,
            &command,
            accounts_volume,
            accounts_volume_mount,
            None,
            self.nodes.clone(),
            self.pod_requests.requests.clone(),
        )
    }

    pub fn create_non_voting_validator_replica_set(
        &mut self,
        container_name: &str,
        nvv_index: i32,
        image_name: &str,
        secret_name: Option<String>,
        label_selector: &BTreeMap<String, String>,
    ) -> Result<ReplicaSet, Box<dyn Error>> {
        let mut env_vars = vec![EnvVar {
            name: "MY_POD_IP".to_string(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    field_path: "status.podIP".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }];
        env_vars.append(&mut self.set_non_bootstrap_environment_variables());
        env_vars.append(&mut self.set_load_balancer_environment_variables());

        if self.metrics.is_some() {
            env_vars.push(self.get_metrics_env_var_secret())
        }

        let accounts_volume = Some(vec![Volume {
            name: format!("non-voting-validator-accounts-volume-{}", nvv_index),
            secret: Some(SecretVolumeSource {
                secret_name,
                ..Default::default()
            }),
            ..Default::default()
        }]);

        let accounts_volume_mount = Some(vec![VolumeMount {
            name: format!("non-voting-validator-accounts-volume-{}", nvv_index),
            mount_path: "/home/solana/non-voting-validator-accounts".to_string(),
            ..Default::default()
        }]);

        let mut command = vec![
            "/home/solana/k8s-cluster-scripts/non-voting-validator-startup-script.sh".to_string(),
        ];
        command.extend(self.generate_non_voting_command_flags());

        for c in command.iter() {
            debug!("validator command: {}", c);
        }

        let exec_action = ExecAction {
            command: Some(vec![
                String::from("/bin/bash"),
                String::from("-c"),
                String::from("solana -u http://$MY_POD_IP:8899 balance -k non-voting-validator-accounts/identity.json"),
            ]),
        };

        let readiness_probe = Probe {
            exec: Some(exec_action),
            initial_delay_seconds: Some(20),
            period_seconds: Some(20),
            ..Default::default()
        };

        let mut replica_set_name_with_optional_tag = "non-voting".to_string();
        if let Some(tag) = &self.deployment_tag {
            replica_set_name_with_optional_tag =
                add_tag_to_name(replica_set_name_with_optional_tag.as_str(), tag);
        }
        replica_set_name_with_optional_tag =
            format!("{}-{}", replica_set_name_with_optional_tag, nvv_index);

        k8s_helpers::create_replica_set(
            replica_set_name_with_optional_tag.as_str(),
            self.namespace,
            label_selector,
            container_name,
            image_name,
            env_vars,
            &command,
            accounts_volume,
            accounts_volume_mount,
            Some(readiness_probe),
            self.nodes.clone(),
            self.pod_requests.requests.clone(),
        )
    }

    pub fn create_client_replica_set(
        &mut self,
        container_name: &str,
        client_index: i32,
        image_name: &str,
        secret_name: Option<String>,
        label_selector: &BTreeMap<String, String>,
    ) -> Result<ReplicaSet, Box<dyn Error>> {
        let mut env_vars = self.set_non_bootstrap_environment_variables();
        if self.metrics.is_some() {
            env_vars.push(self.get_metrics_env_var_secret())
        }
        env_vars.append(&mut self.set_load_balancer_environment_variables());

        let accounts_volume = Some(vec![Volume {
            name: format!("client-accounts-volume-{}", client_index),
            secret: Some(SecretVolumeSource {
                secret_name,
                ..Default::default()
            }),
            ..Default::default()
        }]);

        let accounts_volume_mount = Some(vec![VolumeMount {
            name: format!("client-accounts-volume-{}", client_index),
            mount_path: "/home/solana/client-accounts".to_string(),
            ..Default::default()
        }]);

        let mut command =
            vec!["/home/solana/k8s-cluster-scripts/client-startup-script.sh".to_string()];
        command.extend(self.generate_client_command_flags());

        for c in command.iter() {
            debug!("client command: {}", c);
        }

        let mut replica_set_name_with_optional_tag = "client".to_string();
        if let Some(tag) = &self.deployment_tag {
            replica_set_name_with_optional_tag =
                add_tag_to_name(replica_set_name_with_optional_tag.as_str(), tag);
        }
        replica_set_name_with_optional_tag =
            format!("{}-{}", replica_set_name_with_optional_tag, client_index);

        k8s_helpers::create_replica_set(
            replica_set_name_with_optional_tag.as_str(),
            self.namespace,
            label_selector,
            container_name,
            image_name,
            env_vars,
            &command,
            accounts_volume,
            accounts_volume_mount,
            None,
            self.nodes.clone(),
            self.pod_requests.requests.clone(),
        )
    }

    pub fn create_validator_service(
        &self,
        service_name: &str,
        label_selector: &BTreeMap<String, String>,
        index: i32,
    ) -> Service {
        let mut service_name_with_optional_tag = service_name.to_string();
        if let Some(tag) = &self.deployment_tag {
            service_name_with_optional_tag =
                add_tag_to_name(service_name_with_optional_tag.as_str(), tag);
        }
        service_name_with_optional_tag = format!("{}-{}", service_name_with_optional_tag, index);

        k8s_helpers::create_service(
            service_name_with_optional_tag.as_str(),
            self.namespace,
            label_selector,
            false,
        )
    }

    pub fn create_bootstrap_service(
        &self,
        service_name: &str,
        label_selector: &BTreeMap<String, String>,
    ) -> Service {
        k8s_helpers::create_service(service_name, self.namespace, label_selector, false)
    }

    pub fn create_validator_load_balancer(
        &self,
        service_name: &str,
        label_selector: &BTreeMap<String, String>,
    ) -> Service {
        k8s_helpers::create_service(service_name, self.namespace, label_selector, true)
    }

    pub fn create_selector(&self, key: &str, value: &str) -> BTreeMap<String, String> {
        k8s_helpers::create_selector(key, value)
    }
}
