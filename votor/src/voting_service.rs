#[cfg(any(test, feature = "dev-context-only-utils"))]
use std::collections::HashSet;
use {
    crate::datagram_transport::{allowlist::StakedNodesAllowlist, endpoint::Datagram},
    crate::{
        staked_validators_cache::StakedValidatorsCache,
        vote_history_storage::{SavedVoteHistoryVersions, VoteHistoryStorage},
    },
    agave_votor_messages::{
        certificate::Certificate,
        consensus_message::{ConsensusMessage, VoteMessage},
    },
    bytes::Bytes,
    crossbeam_channel::Receiver,
    solana_client::connection_cache::ConnectionCache,
    solana_clock::Slot,
    solana_connection_cache::client_connection::ClientConnection,
    solana_gossip::cluster_info::ClusterInfo,
    solana_measure::measure::Measure,
    solana_pubkey::Pubkey,
    solana_runtime::bank_forks::BankForks,
    solana_transaction_error::TransportError,
    std::{
        collections::HashMap,
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
        vote: Arc<VoteMessage>,
        saved_vote_history: SavedVoteHistoryVersions,
    },
    PushCertificates {
        certificates: Vec<Arc<Certificate>>,
    },
}

fn send_message(
    buf: Vec<u8>,
    socket: &SocketAddr,
    connection_cache: &ConnectionCache,
) -> Result<(), TransportError> {
    let client = connection_cache.get_connection(socket);

    client.send_data_async(Arc::new(buf))
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

#[derive(Clone, Debug)]
pub struct AdditionalListener {
    pub pubkey: Pubkey,
    pub addr: SocketAddr,
}

#[derive(Clone)]
pub enum VotingTransport {
    Stream(Arc<ConnectionCache>),
    Datagram {
        egress: mpsc::Sender<Datagram>,
        allowlist: Option<Arc<StakedNodesAllowlist>>,
    },
}

impl VotingTransport {
    fn allowlist(&self) -> Option<Arc<StakedNodesAllowlist>> {
        match self {
            Self::Stream(_) => None,
            Self::Datagram { allowlist, .. } => allowlist.clone(),
        }
    }
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
        transport: VotingTransport,
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

        let allowlist = transport.allowlist();
        #[cfg(any(test, feature = "dev-context-only-utils"))]
        let extra_admit: HashSet<Pubkey> = additional_listeners
            .iter()
            .map(|listener| listener.pubkey)
            .collect();

        let thread_hdl = Builder::new()
            .name("solVotorVoteSvc".to_string())
            .spawn(move || {
                let mut staked_validators_cache = StakedValidatorsCache::new(
                    bank_forks.read().unwrap().sharable_banks(),
                    Duration::from_secs(STAKED_VALIDATORS_CACHE_TTL_S),
                    STAKED_VALIDATORS_CACHE_NUM_EPOCH_TARGET,
                    false,
                    alpenglow_port_override,
                    allowlist,
                    #[cfg(any(test, feature = "dev-context-only-utils"))]
                    extra_admit,
                );

                info!("AlpenglowVotingService has started");
                while let Ok(bls_op) = bls_receiver.recv() {
                    Self::handle_bls_op(
                        &cluster_info,
                        vote_history_storage.as_ref(),
                        bls_op,
                        &transport,
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
        transport: &VotingTransport,
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

        let (staked_validator_peers, _) = staked_validators_cache.get_staked_validators_by_slot(
            slot,
            cluster_info,
            Instant::now(),
        );
        match transport {
            VotingTransport::Stream(connection_cache) => {
                let sockets = additional_listeners
                    .iter()
                    .map(|listener| &listener.addr)
                    .chain(staked_validator_peers.iter().map(|(_, socket)| socket));

                // We use send_message in a loop right now because we worry that sending packets
                // too fast will cause a packet spike and overwhelm the network. If we later find
                // out that this is not an issue, we can optimize this by using multi_target_send
                // or a similar API.
                for socket in sockets {
                    if let Err(e) = send_message(buf.clone(), socket, connection_cache) {
                        warn!("Failed to send alpenglow message to {socket}: {e:?}");
                    }
                }
            }
            VotingTransport::Datagram { egress, .. } => {
                let buf = Bytes::from(buf);
                let peers = additional_listeners
                    .iter()
                    .map(|listener| (listener.pubkey, listener.addr))
                    .chain(staked_validator_peers.iter().copied());
                for (peer_pubkey, peer_address) in peers {
                    match egress.try_send(Datagram {
                        peer_pubkey,
                        peer_address,
                        message: buf.clone(),
                    }) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!("alpenglow egress channel full; dropping vote/cert");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            warn!("alpenglow egress channel closed; endpoint shutting down");
                            return;
                        }
                    }
                }
            }
        }
    }

    fn handle_bls_op(
        cluster_info: &ClusterInfo,
        vote_history_storage: &dyn VoteHistoryStorage,
        bls_op: BLSOp,
        transport: &VotingTransport,
        additional_listeners: &[AdditionalListener],
        staked_validators_cache: &mut StakedValidatorsCache,
    ) {
        match bls_op {
            BLSOp::PushVote {
                vote,
                saved_vote_history,
            } => {
                let mut measure = Measure::start("alpenglow vote history save");
                if let Err(err) = vote_history_storage.store(&saved_vote_history) {
                    error!("Unable to save vote history to storage: {err:?}");
                    std::process::exit(1);
                }
                measure.stop();
                trace!("{measure}");
                let slot = vote.vote.slot();
                let msg = ConsensusMessage::Vote(Arc::unwrap_or_clone(vote));
                Self::broadcast_consensus_message(
                    slot,
                    cluster_info,
                    &msg,
                    transport,
                    additional_listeners,
                    staked_validators_cache,
                );
            }
            BLSOp::PushCertificates { certificates } => {
                for certificate in certificates {
                    let slot = certificate.cert_type.slot();
                    let message = ConsensusMessage::Certificate(Arc::unwrap_or_clone(certificate));
                    Self::broadcast_consensus_message(
                        slot,
                        cluster_info,
                        &message,
                        transport,
                        additional_listeners,
                        staked_validators_cache,
                    );
                }
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
        crossbeam_channel::bounded,
        solana_bls_signatures::{BLS_SIGNATURE_AFFINE_SIZE, Signature as BLSSignature},
        solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
        solana_keypair::Keypair,
        solana_net_utils::{SocketAddrSpace, sockets::bind_to_localhost_unique},
        solana_runtime::{
            bank::Bank,
            bank_forks::BankForks,
            genesis_utils::{
                ValidatorVoteKeypairs, create_genesis_config_with_alpenglow_vote_accounts,
            },
        },
        solana_signer::Signer,
        solana_streamer::{
            nonblocking::swqos::SwQosConfig,
            quic::{QuicStreamerConfig, SpawnServerResult, spawn_stake_weighted_qos_server},
            streamer::StakedNodes,
        },
        std::sync::{Arc, RwLock},
        test_case::test_case,
        tokio_util::sync::CancellationToken,
    };

    fn create_voting_service(
        bls_receiver: Receiver<BLSOp>,
        listener: AdditionalListener,
        transport: VotingTransport,
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
                transport,
                bank_forks,
                Some(VotingServiceOverride {
                    additional_listeners: vec![listener],
                    alpenglow_port_override: AlpenglowPortOverride::default(),
                }),
            ),
            validator_keypairs,
        )
    }

    #[test_case(BLSOp::PushVote {
        vote: Arc::new(VoteMessage {
            vote: Vote::new_skip_vote(5),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            rank: 1,
        }),
        saved_vote_history: SavedVoteHistoryVersions::Current(SavedVoteHistory::default()),
    }, ConsensusMessage::Vote(VoteMessage {
        vote: Vote::new_skip_vote(5),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        rank: 1,
    }))]
    #[test_case(BLSOp::PushCertificates {
        certificates: vec![Arc::new(Certificate {
            cert_type: CertificateType::Skip(5),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            bitmap: Vec::new(),
        })],
    }, ConsensusMessage::Certificate(Certificate {
        cert_type: CertificateType::Skip(5),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        bitmap: Vec::new(),
    }))]
    fn test_send_message(bls_op: BLSOp, expected_message: ConsensusMessage) {
        agave_logger::setup();
        let (bls_sender, bls_receiver) = bounded(1024);
        // Create listener thread on a random port we allocated and return SocketAddr to create VotingService

        // Bind to a random UDP port
        let socket = bind_to_localhost_unique().unwrap();
        let listener_addr = socket.local_addr().unwrap();

        let listener = AdditionalListener {
            pubkey: Pubkey::new_unique(),
            addr: listener_addr,
        };
        let transport = VotingTransport::Stream(Arc::new(ConnectionCache::new_quic(
            "TestAlpenglowConnectionCache",
            10,
        )));
        let (_, validator_keypairs) = create_voting_service(bls_receiver, listener, transport);

        // Send a BLS message via the VotingService
        assert!(bls_sender.send(bls_op).is_ok());

        // Start a quick streamer to handle quick control packets
        let (sender, receiver) = bounded(1024);
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

    #[test_case(BLSOp::PushVote {
        vote: Arc::new(VoteMessage {
            vote: Vote::new_skip_vote(5),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            rank: 1,
        }),
        saved_vote_history: SavedVoteHistoryVersions::Current(SavedVoteHistory::default()),
    }, ConsensusMessage::Vote(VoteMessage {
        vote: Vote::new_skip_vote(5),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        rank: 1,
    }))]
    #[test_case(BLSOp::PushCertificates {
        certificates: vec![Arc::new(Certificate {
            cert_type: CertificateType::Skip(5),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            bitmap: Vec::new(),
        })],
    }, ConsensusMessage::Certificate(Certificate {
        cert_type: CertificateType::Skip(5),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        bitmap: Vec::new(),
    }))]
    fn test_send_datagram_message(bls_op: BLSOp, expected_message: ConsensusMessage) {
        let (bls_sender, bls_receiver) = bounded(1024);
        let (egress, mut egress_receiver) = mpsc::channel(1024);
        let listener = AdditionalListener {
            pubkey: Pubkey::new_unique(),
            addr: "127.0.0.1:12345".parse().unwrap(),
        };
        let transport = VotingTransport::Datagram {
            egress,
            allowlist: None,
        };
        let (_voting_service, _validator_keypairs) =
            create_voting_service(bls_receiver, listener.clone(), transport);

        assert!(bls_sender.send(bls_op).is_ok());

        let deadline = Instant::now() + Duration::from_secs(5);
        let datagram = loop {
            match egress_receiver.try_recv() {
                Ok(datagram) => break datagram,
                Err(mpsc::error::TryRecvError::Empty) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("failed to receive datagram: {err:?}"),
            }
        };
        assert_eq!(datagram.peer_pubkey, listener.pubkey);
        assert_eq!(datagram.peer_address, listener.addr);
        let received_message = wincode::deserialize::<ConsensusMessage>(&datagram.message)
            .expect("deserialize datagram message");
        assert_eq!(received_message, expected_message);
    }
}
