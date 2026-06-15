use {
    crate::{
        staked_validators_cache::StakedValidatorsCache,
        vote_history_storage::{SavedVoteHistoryVersions, VoteHistoryStorage},
    },
    agave_votor_messages::{
        certificate::Certificate,
        consensus_message::{ConsensusMessage, VoteMessage},
    },
    crossbeam_channel::{Receiver, TryRecvError},
    solana_client::connection_cache::ConnectionCache,
    solana_clock::Slot,
    solana_connection_cache::nonblocking::client_connection::ClientConnection,
    solana_gossip::cluster_info::ClusterInfo,
    solana_measure::measure::Measure,
    solana_pubkey::Pubkey,
    solana_runtime::bank_forks::BankForks,
    std::{
        collections::{HashMap, hash_map::DefaultHasher},
        hash::{Hash, Hasher},
        net::SocketAddr,
        sync::{Arc, RwLock},
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::{sync::mpsc, time::timeout},
};

const STAKED_VALIDATORS_CACHE_TTL_S: u64 = 5;
/// Target number of epochs to keep in the staked validators cache. Due to lazy-lru eviction
/// semantics, the cache may hold up to `2 * STAKED_VALIDATORS_CACHE_NUM_EPOCH_TARGET` entries
/// before evicting down to this target.
const STAKED_VALIDATORS_CACHE_NUM_EPOCH_TARGET: usize = 3;
const STREAM_SEND_WORKERS: usize = 64;
const STREAM_SEND_QUEUE_CAPACITY_PER_WORKER: usize = 256;
const STREAM_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const BLS_OP_RECEIVE_BATCH_SIZE: usize = 64;

#[derive(Debug)]
pub enum BLSOp {
    PushVote {
        vote: Arc<VoteMessage>,
        saved_vote_history: SavedVoteHistoryVersions,
    },
    PushCertificates {
        certificates: Vec<Arc<Certificate>>,
    },
    RefreshVotes {
        votes: Vec<Arc<VoteMessage>>,
    },
}

struct StreamSendRequest {
    socket: SocketAddr,
    payload: Arc<Vec<u8>>,
}

struct StreamSender {
    workers: Vec<mpsc::Sender<StreamSendRequest>>,
}

impl StreamSender {
    fn new(connection_cache: Arc<ConnectionCache>) -> Self {
        let mut workers = Vec::with_capacity(STREAM_SEND_WORKERS);
        for _ in 0..STREAM_SEND_WORKERS {
            let (sender, receiver) = mpsc::channel(STREAM_SEND_QUEUE_CAPACITY_PER_WORKER);
            tokio::spawn(stream_send_worker(connection_cache.clone(), receiver));
            workers.push(sender);
        }
        Self { workers }
    }

    fn try_send(
        &self,
        socket: SocketAddr,
        payload: Arc<Vec<u8>>,
    ) -> Result<(), mpsc::error::TrySendError<StreamSendRequest>> {
        let worker_index = socket_worker_index(&socket, self.workers.len());
        self.workers[worker_index].try_send(StreamSendRequest { socket, payload })
    }
}

fn socket_worker_index(socket: &SocketAddr, workers: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    socket.hash(&mut hasher);
    (hasher.finish() as usize) % workers
}

async fn stream_send_worker(
    connection_cache: Arc<ConnectionCache>,
    mut receiver: mpsc::Receiver<StreamSendRequest>,
) {
    while let Some(StreamSendRequest { socket, payload }) = receiver.recv().await {
        let client = connection_cache.get_nonblocking_connection(&socket);
        match timeout(
            STREAM_SEND_TIMEOUT,
            client.send_data(payload.as_ref().as_slice()),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!("Failed to send alpenglow message to {socket}: {err:?}");
            }
            Err(_) => {
                warn!("Timed out sending alpenglow message to {socket}");
            }
        }
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

#[derive(Clone)]
pub struct VotingServiceOverride {
    pub additional_listeners: Vec<SocketAddr>,
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
                let mut staked_validators_cache = StakedValidatorsCache::new(
                    bank_forks,
                    Duration::from_secs(STAKED_VALIDATORS_CACHE_TTL_S),
                    STAKED_VALIDATORS_CACHE_NUM_EPOCH_TARGET,
                    false,
                    alpenglow_port_override,
                );
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .thread_name("solVotorVoteRt")
                    .enable_time()
                    .build()
                    .unwrap();

                runtime.block_on(async move {
                    let stream_sender = StreamSender::new(connection_cache);
                    info!("AlpenglowVotingService has started");
                    loop {
                        let mut handled_message = false;
                        for _ in 0..BLS_OP_RECEIVE_BATCH_SIZE {
                            match bls_receiver.try_recv() {
                                Ok(bls_op) => {
                                    handled_message = true;
                                    Self::handle_bls_op(
                                        &cluster_info,
                                        vote_history_storage.as_ref(),
                                        bls_op,
                                        &stream_sender,
                                        &additional_listeners,
                                        &mut staked_validators_cache,
                                    );
                                }
                                Err(TryRecvError::Empty) => break,
                                Err(TryRecvError::Disconnected) => {
                                    info!("AlpenglowVotingService has stopped");
                                    return;
                                }
                            }
                        }

                        if handled_message {
                            tokio::task::yield_now().await;
                        } else {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                });
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn broadcast_consensus_message(
        slot: Slot,
        cluster_info: &ClusterInfo,
        message: &ConsensusMessage,
        sender: &StreamSender,
        additional_listeners: &[SocketAddr],
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
        let sockets = additional_listeners
            .iter()
            .chain(staked_validator_alpenglow_sockets.iter());

        let buf = Arc::new(buf);
        for socket in sockets {
            match sender.try_send(*socket, buf.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!("alpenglow stream send queue full; dropping message to {socket}");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!("alpenglow stream send queue closed; dropping message to {socket}");
                    return;
                }
            }
        }
    }

    fn handle_bls_op(
        cluster_info: &ClusterInfo,
        vote_history_storage: &dyn VoteHistoryStorage,
        bls_op: BLSOp,
        sender: &StreamSender,
        additional_listeners: &[SocketAddr],
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
                    sender,
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
                        sender,
                        additional_listeners,
                        staked_validators_cache,
                    );
                }
            }
            BLSOp::RefreshVotes { votes } => {
                for vote in votes {
                    let slot = vote.vote.slot();
                    let msg = ConsensusMessage::Vote(Arc::unwrap_or_clone(vote));
                    Self::broadcast_consensus_message(
                        slot,
                        cluster_info,
                        &msg,
                        connection_cache,
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
        std::{
            net::SocketAddr,
            sync::{Arc, RwLock},
        },
        test_case::test_case,
        tokio_util::sync::CancellationToken,
    };

    fn create_voting_service(
        bls_receiver: Receiver<BLSOp>,
        listener: SocketAddr,
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
    #[test_case(BLSOp::RefreshVotes {
        votes: vec![Arc::new(VoteMessage {
            vote: Vote::new_skip_vote(6),
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            rank: 1,
        })],
    }, ConsensusMessage::Vote(VoteMessage {
        vote: Vote::new_skip_vote(6),
        signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
        rank: 1,
    }))]
    fn test_send_message(bls_op: BLSOp, expected_message: ConsensusMessage) {
        agave_logger::setup();
        let (bls_sender, bls_receiver) = bounded(1024);
        // Create listener thread on a random port we allocated and return SocketAddr to create VotingService

        // Bind to a random UDP port
        let socket = bind_to_localhost_unique().unwrap();
        let listener_addr = socket.local_addr().unwrap();

        // Create VotingService with the listener address
        let (_, validator_keypairs) = create_voting_service(bls_receiver, listener_addr);

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
}
