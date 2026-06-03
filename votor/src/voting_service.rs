use {
    crate::{
        staked_validators_cache::StakedValidatorsCache,
        vote_history_storage::{SavedVoteHistoryVersions, VoteHistoryStorage},
    },
    agave_votor_messages::{certificate::Certificate, consensus_message::ConsensusMessage},
    bytes::Bytes,
    crossbeam_channel::Receiver,
    solana_client::connection_cache::ConnectionCache,
    solana_clock::Slot,
    solana_connection_cache::client_connection::ClientConnection,
    solana_gossip::cluster_info::ClusterInfo,
    solana_measure::measure::Measure,
    solana_pubkey::Pubkey,
    solana_quic_datagram::{endpoint::Datagram, StakedNodesAllowlist},
    solana_runtime::bank_forks::BankForks,
    solana_transaction_error::TransportError,
    std::{
        collections::{HashMap, HashSet},
        fmt,
        net::SocketAddr,
        sync::{Arc, RwLock},
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::sync::mpsc,
};

const STAKED_VALIDATORS_CACHE_TTL_S: u64 = 5;
/// Target number of epochs to keep in the staked validators cache. Due to lazy-lru eviction
/// semantics, the cache may hold up to `2 * STAKED_VALIDATORS_CACHE_NUM_EPOCH_TARGET` entries
/// before evicting down to this target.
const STAKED_VALIDATORS_CACHE_NUM_EPOCH_TARGET: usize = 3;

#[derive(Debug)]
pub enum BLSOp {
    PushVote {
        message: Arc<ConsensusMessage>,
        slot: Slot,
        saved_vote_history: SavedVoteHistoryVersions,
    },
    PushCertificate {
        certificate: Arc<Certificate>,
    },
}

#[derive(Debug)]
enum ConsensusSendError {
    Stream(TransportError),
    DatagramFull,
    DatagramClosed,
}

impl fmt::Display for ConsensusSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(err) => write!(f, "{err:?}"),
            Self::DatagramFull => f.write_str("datagram egress channel is full"),
            Self::DatagramClosed => f.write_str("datagram egress channel is closed"),
        }
    }
}

trait ConsensusMessageSender: Send + Sync + 'static {
    fn send_message(
        &self,
        peer: Pubkey,
        addr: SocketAddr,
        buf: Vec<u8>,
    ) -> Result<(), ConsensusSendError>;
}

struct ConnectionCacheMessageSender {
    connection_cache: Arc<ConnectionCache>,
}

impl ConsensusMessageSender for ConnectionCacheMessageSender {
    fn send_message(
        &self,
        _peer: Pubkey,
        addr: SocketAddr,
        buf: Vec<u8>,
    ) -> Result<(), ConsensusSendError> {
        let client = self.connection_cache.get_connection(&addr);

        client
            .send_data_async(Arc::new(buf))
            .map_err(ConsensusSendError::Stream)
    }
}

struct DatagramMessageSender {
    egress: mpsc::Sender<Datagram>,
}

impl ConsensusMessageSender for DatagramMessageSender {
    fn send_message(
        &self,
        peer: Pubkey,
        addr: SocketAddr,
        buf: Vec<u8>,
    ) -> Result<(), ConsensusSendError> {
        self.egress
            .try_send(Datagram {
                peer_pubkey: peer,
                peer_address: addr,
                message: Bytes::from(buf),
            })
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(_) => ConsensusSendError::DatagramFull,
                mpsc::error::TrySendError::Closed(_) => ConsensusSendError::DatagramClosed,
            })
    }
}

pub struct VotingService {
    thread_hdl: JoinHandle<()>,
}

/// Override for Alpenglow ports to allow testing with different ports
/// The last_modified is used to determine if the override has changed so
/// StakedValidatorsCache can refresh its cache.
/// Inside the map, the key is the validator's vote pubkey and the value
/// is the overridden socket address.
/// For example, if you want validator A to send messages for validator B's
/// Alpenglow port to a new_address, you would insert an entry into the A's
/// map like this: (B will not get the message as a result):
/// `override_map.insert(validator_b_pubkey, new_address);`
#[derive(Clone, Default)]
pub struct AlpenglowPortOverride {
    inner: Arc<RwLock<AlpenglowPortOverrideInner>>,
}

#[derive(Clone)]
struct AlpenglowPortOverrideInner {
    override_map: HashMap<Pubkey, SocketAddr>,
    last_modified: Instant,
}

impl Default for AlpenglowPortOverrideInner {
    fn default() -> Self {
        Self {
            override_map: HashMap::new(),
            last_modified: Instant::now(),
        }
    }
}

impl AlpenglowPortOverride {
    pub fn update_override(&self, new_override: HashMap<Pubkey, SocketAddr>) {
        let mut inner = self.inner.write().unwrap();
        inner.override_map = new_override;
        inner.last_modified = Instant::now();
    }

    pub fn has_new_override(&self, previous: Instant) -> bool {
        self.inner.read().unwrap().last_modified != previous
    }

    pub fn last_modified(&self) -> Instant {
        self.inner.read().unwrap().last_modified
    }

    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.override_map.clear();
        inner.last_modified = Instant::now();
    }

    pub fn get_override_map(&self) -> HashMap<Pubkey, SocketAddr> {
        self.inner.read().unwrap().override_map.clone()
    }
}

/// Test-only additional listener: the voting service will fan out every
/// consensus message to this `(pubkey, addr)` peer alongside the live
/// staked-validators list. The stream-mode sender only uses `addr`; the
/// pubkey is carried here so the later datagram path can target authenticated
/// peers without changing the fanout API again.
#[derive(Clone, Debug)]
pub struct AdditionalListener {
    pub pubkey: Pubkey,
    pub addr: SocketAddr,
}

#[derive(Clone)]
pub struct VotingServiceOverride {
    pub additional_listeners: Vec<AdditionalListener>,
    pub alpenglow_port_override: AlpenglowPortOverride,
}

impl VotingService {
    pub fn new(
        bls_receiver: Receiver<BLSOp>,
        cluster_info: Arc<ClusterInfo>,
        vote_history_storage: Arc<dyn VoteHistoryStorage>,
        connection_cache: Arc<ConnectionCache>,
        bank_forks: Arc<RwLock<BankForks>>,
        test_override: Option<VotingServiceOverride>,
    ) -> Self {
        Self::new_with_sender(
            bls_receiver,
            cluster_info,
            vote_history_storage,
            Arc::new(ConnectionCacheMessageSender { connection_cache }),
            None,
            HashSet::new(),
            bank_forks,
            test_override,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_datagram(
        bls_receiver: Receiver<BLSOp>,
        cluster_info: Arc<ClusterInfo>,
        vote_history_storage: Arc<dyn VoteHistoryStorage>,
        egress: mpsc::Sender<Datagram>,
        allowlist: Option<Arc<StakedNodesAllowlist>>,
        bank_forks: Arc<RwLock<BankForks>>,
        test_override: Option<VotingServiceOverride>,
    ) -> Self {
        let extra_admit = test_override
            .as_ref()
            .map(|override_| {
                override_
                    .additional_listeners
                    .iter()
                    .map(|listener| listener.pubkey)
                    .collect()
            })
            .unwrap_or_default();
        Self::new_with_sender(
            bls_receiver,
            cluster_info,
            vote_history_storage,
            Arc::new(DatagramMessageSender { egress }),
            allowlist,
            extra_admit,
            bank_forks,
            test_override,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_sender(
        bls_receiver: Receiver<BLSOp>,
        cluster_info: Arc<ClusterInfo>,
        vote_history_storage: Arc<dyn VoteHistoryStorage>,
        message_sender: Arc<dyn ConsensusMessageSender>,
        allowlist: Option<Arc<StakedNodesAllowlist>>,
        extra_admit: HashSet<Pubkey>,
        bank_forks: Arc<RwLock<BankForks>>,
        test_override: Option<VotingServiceOverride>,
    ) -> Self {
        let (additional_listeners, alpenglow_port_override) = match test_override {
            None => (Vec::new(), None),
            Some(VotingServiceOverride {
                additional_listeners,
                alpenglow_port_override,
            }) => (additional_listeners, Some(alpenglow_port_override)),
        };

        let thread_hdl = Builder::new()
            .name("solVotorVoteSvc".to_string())
            .spawn(move || {
                let mut staked_validators_cache = StakedValidatorsCache::new_with_allowlist(
                    bank_forks.clone(),
                    Duration::from_secs(STAKED_VALIDATORS_CACHE_TTL_S),
                    STAKED_VALIDATORS_CACHE_NUM_EPOCH_TARGET,
                    false,
                    alpenglow_port_override,
                    allowlist,
                    extra_admit,
                );

                info!("AlpenglowVotingService has started");
                while let Ok(bls_op) = bls_receiver.recv() {
                    Self::handle_bls_op(
                        &cluster_info,
                        vote_history_storage.as_ref(),
                        bls_op,
                        message_sender.as_ref(),
                        &additional_listeners,
                        &mut staked_validators_cache,
                    );
                }
                info!("AlpenglowVotingService has stopped");
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn broadcast_consensus_message(
        slot: Slot,
        cluster_info: &ClusterInfo,
        message: &ConsensusMessage,
        message_sender: &dyn ConsensusMessageSender,
        additional_listeners: &[AdditionalListener],
        staked_validators_cache: &mut StakedValidatorsCache,
    ) {
        let buf = match wincode::serialize(message) {
            Ok(buf) => buf,
            Err(err) => {
                error!("Failed to serialize alpenglow message: {err:?}");
                return;
            }
        };

        let (staked_validator_alpenglow_sockets, _) = staked_validators_cache
            .get_staked_validators_by_slot(slot, cluster_info, Instant::now());
        let peers = additional_listeners
            .iter()
            .map(|listener| (listener.pubkey, listener.addr))
            .chain(staked_validator_alpenglow_sockets.iter().copied());

        // We use send_message in a loop right now because we worry that sending packets too fast
        // will cause a packet spike and overwhelm the network. If we later find out that this is
        // not an issue, we can optimize this by using multi_targret_send or similar methods.
        for (pubkey, socket) in peers {
            if let Err(e) = message_sender.send_message(pubkey, socket, buf.clone()) {
                warn!("Failed to send alpenglow message to {socket}: {e}");
            }
        }
    }

    fn handle_bls_op(
        cluster_info: &ClusterInfo,
        vote_history_storage: &dyn VoteHistoryStorage,
        bls_op: BLSOp,
        message_sender: &dyn ConsensusMessageSender,
        additional_listeners: &[AdditionalListener],
        staked_validators_cache: &mut StakedValidatorsCache,
    ) {
        match bls_op {
            BLSOp::PushVote {
                message,
                slot,
                saved_vote_history,
            } => {
                let mut measure = Measure::start("alpenglow vote history save");
                if let Err(err) = vote_history_storage.store(&saved_vote_history) {
                    error!("Unable to save vote history to storage: {err:?}");
                    std::process::exit(1);
                }
                measure.stop();
                trace!("{measure}");

                Self::broadcast_consensus_message(
                    slot,
                    cluster_info,
                    &message,
                    message_sender,
                    additional_listeners,
                    staked_validators_cache,
                );
            }
            BLSOp::PushCertificate { certificate } => {
                let vote_slot = certificate.cert_type.slot();
                let message = ConsensusMessage::Certificate((*certificate).clone());
                Self::broadcast_consensus_message(
                    vote_slot,
                    cluster_info,
                    &message,
                    message_sender,
                    additional_listeners,
                    staked_validators_cache,
                );
            }
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::vote_history_storage::{
            NullVoteHistoryStorage, SavedVoteHistory, SavedVoteHistoryVersions,
        },
        agave_votor_messages::{
            certificate::{Certificate, CertificateType},
            consensus_message::{ConsensusMessage, VoteMessage},
            vote::Vote,
        },
        solana_bls_signatures::{Signature as BLSSignature, BLS_SIGNATURE_AFFINE_SIZE},
        solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
        solana_keypair::Keypair,
        solana_net_utils::{sockets::bind_to_localhost_unique, SocketAddrSpace},
        solana_runtime::{
            bank::Bank,
            bank_forks::BankForks,
            genesis_utils::{
                create_genesis_config_with_alpenglow_vote_accounts, ValidatorVoteKeypairs,
            },
        },
        solana_signer::Signer,
        solana_streamer::{
            nonblocking::swqos::SwQosConfig,
            quic::{spawn_stake_weighted_qos_server, QuicStreamerConfig, SpawnServerResult},
            streamer::StakedNodes,
        },
        std::sync::{Arc, RwLock},
        test_case::test_case,
        tokio_util::sync::CancellationToken,
    };

    fn create_voting_service(
        bls_receiver: Receiver<BLSOp>,
        listener: AdditionalListener,
    ) -> (VotingService, Vec<ValidatorVoteKeypairs>) {
        // Create 10 node validatorvotekeypairs vec
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new_rand())
            .collect::<Vec<_>>();
        let genesis = create_genesis_config_with_alpenglow_vote_accounts(
            1_000_000_000,
            &validator_keypairs,
            vec![100; validator_keypairs.len()],
        );
        let bank0 = Bank::new_for_tests(&genesis.genesis_config);
        let bank_forks = BankForks::new_rw_arc(bank0);
        let keypair = Keypair::new();
        let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), 0);
        let cluster_info = ClusterInfo::new(
            contact_info,
            Arc::new(keypair),
            SocketAddrSpace::Unspecified,
        );

        (
            VotingService::new(
                bls_receiver,
                Arc::new(cluster_info),
                Arc::new(NullVoteHistoryStorage::default()),
                Arc::new(ConnectionCache::new_quic(
                    "TestAlpenglowConnectionCache",
                    10,
                )),
                bank_forks,
                Some(VotingServiceOverride {
                    additional_listeners: vec![listener],
                    alpenglow_port_override: AlpenglowPortOverride::default(),
                }),
            ),
            validator_keypairs,
        )
    }

    fn create_datagram_voting_service(
        bls_receiver: Receiver<BLSOp>,
        listener: AdditionalListener,
        egress: mpsc::Sender<Datagram>,
    ) -> VotingService {
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new_rand())
            .collect::<Vec<_>>();
        let genesis = create_genesis_config_with_alpenglow_vote_accounts(
            1_000_000_000,
            &validator_keypairs,
            vec![100; validator_keypairs.len()],
        );
        let bank0 = Bank::new_for_tests(&genesis.genesis_config);
        let bank_forks = BankForks::new_rw_arc(bank0);
        let keypair = Keypair::new();
        let contact_info = ContactInfo::new_localhost(&keypair.pubkey(), 0);
        let cluster_info = ClusterInfo::new(
            contact_info,
            Arc::new(keypair),
            SocketAddrSpace::Unspecified,
        );

        VotingService::new_datagram(
            bls_receiver,
            Arc::new(cluster_info),
            Arc::new(NullVoteHistoryStorage::default()),
            egress,
            None,
            bank_forks,
            Some(VotingServiceOverride {
                additional_listeners: vec![listener],
                alpenglow_port_override: AlpenglowPortOverride::default(),
            }),
        )
    }

    #[test_case(BLSOp::PushVote {
        message: Arc::new(ConsensusMessage::Vote(VoteMessage {
            vote: Vote::new_skip_vote(5),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            rank: 1,
        })),
        slot: 5,
        saved_vote_history: SavedVoteHistoryVersions::Current(SavedVoteHistory::default()),
    }, ConsensusMessage::Vote(VoteMessage {
        vote: Vote::new_skip_vote(5),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        rank: 1,
    }))]
    #[test_case(BLSOp::PushCertificate {
        certificate: Arc::new(Certificate {
            cert_type: CertificateType::Skip(5),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            bitmap: Vec::new(),
        }),
    }, ConsensusMessage::Certificate(Certificate {
        cert_type: CertificateType::Skip(5),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        bitmap: Vec::new(),
    }))]
    fn test_send_message_datagram(bls_op: BLSOp, expected_message: ConsensusMessage) {
        let (bls_sender, bls_receiver) = crossbeam_channel::unbounded();
        let (egress, mut egress_rx) = mpsc::channel(8);
        let listener = AdditionalListener {
            pubkey: Pubkey::new_unique(),
            addr: bind_to_localhost_unique().unwrap().local_addr().unwrap(),
        };

        let _service = create_datagram_voting_service(bls_receiver, listener.clone(), egress);
        bls_sender.send(bls_op).unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let datagram = loop {
            match egress_rx.try_recv() {
                Ok(datagram) => break datagram,
                Err(mpsc::error::TryRecvError::Empty) => {
                    assert!(Instant::now() < deadline, "timed out waiting for datagram");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => panic!("egress disconnected"),
            }
        };
        assert_eq!(datagram.peer_pubkey, listener.pubkey);
        assert_eq!(datagram.peer_address, listener.addr);
        let received = wincode::deserialize::<ConsensusMessage>(&datagram.message).unwrap();
        assert_eq!(received, expected_message);
    }

    #[test_case(BLSOp::PushVote {
        message: Arc::new(ConsensusMessage::Vote(VoteMessage {
            vote: Vote::new_skip_vote(5),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            rank: 1,
        })),
        slot: 5,
        saved_vote_history: SavedVoteHistoryVersions::Current(SavedVoteHistory::default()),
    }, ConsensusMessage::Vote(VoteMessage {
        vote: Vote::new_skip_vote(5),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        rank: 1,
    }))]
    #[test_case(BLSOp::PushCertificate {
        certificate: Arc::new(Certificate {
            cert_type: CertificateType::Skip(5),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            bitmap: Vec::new(),
        }),
    }, ConsensusMessage::Certificate(Certificate {
        cert_type: CertificateType::Skip(5),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        bitmap: Vec::new(),
    }))]
    fn test_send_message(bls_op: BLSOp, expected_message: ConsensusMessage) {
        agave_logger::setup();
        let (bls_sender, bls_receiver) = crossbeam_channel::unbounded();
        // Create listener thread on a random port we allocated and return SocketAddr to create VotingService

        // Bind to a random UDP port
        let socket = bind_to_localhost_unique().unwrap();
        let listener_addr = socket.local_addr().unwrap();
        let listener = AdditionalListener {
            pubkey: Pubkey::new_unique(),
            addr: listener_addr,
        };

        // Create VotingService with the listener address
        let (_, validator_keypairs) = create_voting_service(bls_receiver, listener);

        // Send a BLS message via the VotingService
        assert!(bls_sender.send(bls_op).is_ok());

        // Start a quick streamer to handle quick control packets
        let (sender, receiver) = crossbeam_channel::unbounded();
        let stakes = validator_keypairs
            .iter()
            .map(|x| (x.node_keypair.pubkey(), 100))
            .collect();
        let staked_nodes: Arc<RwLock<StakedNodes>> = Arc::new(RwLock::new(StakedNodes::new(
            Arc::new(stakes),
            HashMap::<Pubkey, u64>::default(), // overrides
        )));
        let cancel = CancellationToken::new();
        let SpawnServerResult {
            endpoints: _,
            thread: quic_server_thread,
            key_updater: _,
        } = spawn_stake_weighted_qos_server(
            "AlpenglowLocalClusterTest",
            "voting_service_test",
            [socket.into()],
            &Keypair::new(),
            sender,
            staked_nodes,
            QuicStreamerConfig::default_for_tests(),
            SwQosConfig::default(),
            cancel.clone(),
        )
        .unwrap();

        let packets = receiver.recv().unwrap();
        let packet = packets.first().expect("No packets received");
        let received_message = packet
            .deserialize_slice::<ConsensusMessage, _>(..)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to deserialize BLSMessage: {:?} {:?}",
                    size_of::<ConsensusMessage>(),
                    err
                )
            });
        assert_eq!(received_message, expected_message);
        cancel.cancel();
        quic_server_thread.join().unwrap();
    }
}
