use {
    crate::{
        quic_datagram_sender::{QuicDatagramSender, QuicDatagramSenderError},
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
    PushCertificate {
        certificate: Arc<Certificate>,
    },
}

pub use crate::quic_datagram_sender::{QuicDatagramClientKeyUpdater, QuicDatagramSenderConfig};

pub enum VotingServiceTransport {
    QuicStream(Arc<ConnectionCache>),
    QuicDatagram(QuicDatagramSenderConfig),
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
        transport: VotingServiceTransport,
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
                let staked_validators_cache = StakedValidatorsCache::new(
                    bank_forks,
                    Duration::from_secs(STAKED_VALIDATORS_CACHE_TTL_S),
                    STAKED_VALIDATORS_CACHE_NUM_EPOCH_TARGET,
                    false,
                    alpenglow_port_override,
                );

                match transport {
                    VotingServiceTransport::QuicStream(connection_cache) => {
                        Self::run_quic_stream_loop(
                            connection_cache,
                            bls_receiver,
                            cluster_info,
                            vote_history_storage,
                            additional_listeners,
                            staked_validators_cache,
                        )
                    }
                    VotingServiceTransport::QuicDatagram(config) => Self::run_quic_datagram_loop(
                        config,
                        bls_receiver,
                        cluster_info,
                        vote_history_storage,
                        additional_listeners,
                        staked_validators_cache,
                    ),
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn run_quic_stream_loop(
        connection_cache: Arc<ConnectionCache>,
        bls_receiver: Receiver<BLSOp>,
        cluster_info: Arc<ClusterInfo>,
        vote_history_storage: Arc<dyn VoteHistoryStorage>,
        additional_listeners: Vec<SocketAddr>,
        mut staked_validators_cache: StakedValidatorsCache,
    ) {
        info!("AlpenglowVotingService has started");
        while let Ok(bls_op) = bls_receiver.recv() {
            Self::handle_bls_op_stream(
                &cluster_info,
                vote_history_storage.as_ref(),
                bls_op,
                &connection_cache,
                &additional_listeners,
                &mut staked_validators_cache,
            );
        }
        info!("AlpenglowVotingService has stopped");
    }

    fn send_stream_message(
        buf: Vec<u8>,
        socket: &SocketAddr,
        connection_cache: &Arc<ConnectionCache>,
    ) -> Result<(), TransportError> {
        let client = connection_cache.get_connection(socket);
        client.send_data_async(Arc::new(buf))
    }

    fn broadcast_consensus_message_stream(
        slot: Slot,
        cluster_info: &ClusterInfo,
        message: &ConsensusMessage,
        connection_cache: &Arc<ConnectionCache>,
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

        // We use send_stream_message in a loop right now because we worry that sending packets too fast
        // will cause a packet spike and overwhelm the network. If we later find out that this is
        // not an issue, we can optimize this by using multi_targret_send or similar methods.
        for socket in sockets {
            if let Err(e) = Self::send_stream_message(buf.clone(), socket, connection_cache) {
                warn!("Failed to send alpenglow message to {socket}: {e:?}");
            }
        }
    }

    fn handle_bls_op_stream(
        cluster_info: &ClusterInfo,
        vote_history_storage: &dyn VoteHistoryStorage,
        bls_op: BLSOp,
        connection_cache: &Arc<ConnectionCache>,
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
                Self::broadcast_consensus_message_stream(
                    slot,
                    cluster_info,
                    &msg,
                    connection_cache,
                    additional_listeners,
                    staked_validators_cache,
                );
            }
            BLSOp::PushCertificate { certificate } => {
                let slot = certificate.cert_type.slot();
                let message = ConsensusMessage::Certificate(Arc::unwrap_or_clone(certificate));
                Self::broadcast_consensus_message_stream(
                    slot,
                    cluster_info,
                    &message,
                    connection_cache,
                    additional_listeners,
                    staked_validators_cache,
                );
            }
        }
    }

    fn run_quic_datagram_loop(
        config: QuicDatagramSenderConfig,
        bls_receiver: Receiver<BLSOp>,
        cluster_info: Arc<ClusterInfo>,
        vote_history_storage: Arc<dyn VoteHistoryStorage>,
        additional_listeners: Vec<SocketAddr>,
        mut staked_validators_cache: StakedValidatorsCache,
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .thread_name("solVotorVoteRt")
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let mut sender = match QuicDatagramSender::new(config) {
            Ok(sender) => sender,
            Err(err) => {
                Self::log_datagram_sender_start_error(err);
                return;
            }
        };
        drop(_guard);

        runtime.block_on(async move {
            info!("AlpenglowVotingService has started");
            loop {
                let mut handled_message = false;
                loop {
                    match bls_receiver.try_recv() {
                        Ok(bls_op) => {
                            handled_message = true;
                            Self::handle_bls_op_datagram(
                                &cluster_info,
                                vote_history_storage.as_ref(),
                                bls_op,
                                &mut sender,
                                &additional_listeners,
                                &mut staked_validators_cache,
                            )
                            .await;
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
    }

    fn log_datagram_sender_start_error(err: QuicDatagramSenderError) {
        error!("Failed to start AlpenglowVotingService QUIC datagram sender: {err}");
    }

    async fn broadcast_consensus_message_datagram(
        slot: Slot,
        cluster_info: &ClusterInfo,
        message: &ConsensusMessage,
        sender: &mut QuicDatagramSender,
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

        for socket in sockets {
            sender.send(*socket, &buf).await;
        }
    }

    async fn handle_bls_op_datagram(
        cluster_info: &ClusterInfo,
        vote_history_storage: &dyn VoteHistoryStorage,
        bls_op: BLSOp,
        sender: &mut QuicDatagramSender,
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
                Self::broadcast_consensus_message_datagram(
                    slot,
                    cluster_info,
                    &msg,
                    sender,
                    additional_listeners,
                    staked_validators_cache,
                )
                .await;
            }
            BLSOp::PushCertificate { certificate } => {
                let slot = certificate.cert_type.slot();
                let message = ConsensusMessage::Certificate(Arc::unwrap_or_clone(certificate));
                Self::broadcast_consensus_message_datagram(
                    slot,
                    cluster_info,
                    &message,
                    sender,
                    additional_listeners,
                    staked_validators_cache,
                )
                .await;
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
        quinn::{
            Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime,
            crypto::rustls::QuicServerConfig,
        },
        rustls::KeyLogFile,
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
        solana_streamer::{nonblocking::quic::ALPN_TPU_PROTOCOL_ID, packet::PACKET_DATA_SIZE},
        solana_tls_utils::{new_dummy_x509_certificate, tls_server_config_builder},
        std::{
            net::{SocketAddr, UdpSocket},
            sync::Arc,
            thread,
            time::Duration,
        },
        test_case::test_case,
    };

    fn create_voting_service(
        bls_receiver: Receiver<BLSOp>,
        listener: SocketAddr,
    ) -> (VotingService, Vec<ValidatorVoteKeypairs>) {
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
        let key_updater = Arc::new(QuicDatagramClientKeyUpdater::new(&keypair));
        let cluster_info = ClusterInfo::new(
            contact_info,
            Arc::new(keypair),
            SocketAddrSpace::Unspecified,
        );
        let transport = VotingServiceTransport::QuicDatagram(QuicDatagramSenderConfig {
            client_socket: bind_to_localhost_unique().unwrap(),
            key_updater,
        });

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

    fn spawn_quic_datagram_receiver(socket: UdpSocket) -> crossbeam_channel::Receiver<Vec<u8>> {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let (ready_sender, ready_receiver) = crossbeam_channel::bounded(1);
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _guard = runtime.enter();
            let endpoint = Endpoint::new(
                EndpointConfig::default(),
                Some(test_server_config(&Keypair::new())),
                socket,
                Arc::new(TokioRuntime),
            )
            .unwrap();
            drop(_guard);
            ready_sender.send(()).unwrap();
            runtime.block_on(async move {
                let incoming = endpoint.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                let datagram = connection.read_datagram().await.unwrap();
                sender.send(datagram.to_vec()).unwrap();
            });
        });
        ready_receiver.recv().unwrap();
        receiver
    }

    fn test_server_config(keypair: &Keypair) -> ServerConfig {
        let (cert, priv_key) = new_dummy_x509_certificate(keypair);
        let mut server_tls_config = tls_server_config_builder()
            .with_single_cert(vec![cert], priv_key)
            .unwrap();
        server_tls_config.alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID.to_vec()];
        server_tls_config.key_log = Arc::new(KeyLogFile::new());
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls_config).unwrap(),
        ));
        server_config.migration(false);
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0u32.into());
        transport_config.max_concurrent_bidi_streams(0u32.into());
        transport_config.datagram_receive_buffer_size(Some(PACKET_DATA_SIZE * 64));
        transport_config.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
        ));
        server_config
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
        let socket = bind_to_localhost_unique().unwrap();
        let listener_addr = socket.local_addr().unwrap();
        let datagram_receiver = spawn_quic_datagram_receiver(socket);
        let (voting_service, _validator_keypairs) =
            create_voting_service(bls_receiver, listener_addr);

        assert!(bls_sender.send(bls_op).is_ok());

        let datagram = datagram_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("No datagram received");
        let received_message =
            wincode::deserialize::<ConsensusMessage>(&datagram).unwrap_or_else(|err| {
                panic!(
                    "Failed to deserialize BLSMessage: {:?} {:?}",
                    size_of::<ConsensusMessage>(),
                    err
                )
            });
        assert_eq!(received_message, expected_message);
        drop(bls_sender);
        voting_service.join().unwrap();
    }
}
