use {
    bytes::Bytes,
    crossbeam_channel::{Sender, TrySendError},
    quinn::{
        Connection, Endpoint, EndpointConfig, IdleTimeout, Incoming, ServerConfig, TokioRuntime,
        VarInt,
        crypto::rustls::{NoInitialCipherSuite, QuicServerConfig},
    },
    rustls::KeyLogFile,
    solana_keypair::Keypair,
    solana_net_utils::token_bucket::TokenBucket,
    solana_packet::Meta,
    solana_perf::packet::{BytesPacket, PACKET_DATA_SIZE, PacketBatch},
    solana_pubkey::Pubkey,
    solana_runtime::bank::MAX_ALPENGLOW_VOTE_ACCOUNTS,
    solana_streamer::nonblocking::{quic::ALPN_TPU_PROTOCOL_ID, simple_qos::SimpleQosBanlist},
    solana_tls_utils::{
        NotifyKeyUpdate, get_remote_pubkey, new_dummy_x509_certificate, tls_server_config_builder,
    },
    std::{
        collections::HashMap,
        net::{SocketAddr, UdpSocket},
        sync::Arc,
        thread::{self, JoinHandle},
        time::Duration,
    },
    tokio::{sync::mpsc, time::timeout},
    tokio_util::sync::CancellationToken,
};

const QUIC_MAX_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_CONNECTION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const DATAGRAM_RECEIVE_BUFFER_SIZE: usize = PACKET_DATA_SIZE * 64;
const MAX_BLS_DATAGRAM_CONNECTIONS: usize = MAX_ALPENGLOW_VOTE_ACCOUNTS * 2;
const MAX_BLS_DATAGRAM_CONNECTIONS_PER_PEER: usize = 2;
const MAX_BLS_DATAGRAMS_PER_SECOND_PER_CONNECTION: f64 = 100.0;
const BLS_DATAGRAM_RATE_LIMIT_BURST: u64 = 1_000;
const BLS_DATAGRAM_DOS_BURST: u64 = 100_000;
const BLS_DATAGRAM_DOS_BAN_TIMEOUT: Duration = Duration::from_secs(48 * 60 * 60);
const BLS_DATAGRAM_BAN_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const CONNECTION_CLOSE_CODE_DISALLOWED: u32 = 2;
const CONNECTION_CLOSE_REASON_DISALLOWED: &[u8] = b"disallowed";
const CONNECTION_CLOSE_CODE_TOO_MANY: u32 = 4;
const CONNECTION_CLOSE_REASON_TOO_MANY: &[u8] = b"too_many";
const CONNECTION_CLOSE_CODE_PACKET_CHANNEL_CLOSED: u32 = 6;
const CONNECTION_CLOSE_REASON_PACKET_CHANNEL_CLOSED: &[u8] = b"packet_channel_closed";

pub(crate) type StakedPeerChecker = Arc<dyn Fn(&Pubkey) -> bool + Send + Sync + 'static>;

enum ServerEvent {
    Accepted {
        connection: Connection,
        remote_addr: SocketAddr,
        remote_pubkey: Pubkey,
    },
    Closed {
        remote_pubkey: Pubkey,
    },
}

pub(crate) struct SpawnBlsQuicDatagramServerResult {
    pub(crate) thread: JoinHandle<()>,
    pub(crate) key_updater: Arc<BlsQuicDatagramServerKeyUpdater>,
    pub(crate) banlist: Arc<SimpleQosBanlist>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BlsQuicDatagramServerError {
    #[error("endpoint creation failed: {0}")]
    EndpointFailed(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    TlsError(#[from] rustls::Error),
    #[error("no initial cipher suite")]
    NoInitialCipherSuite(#[from] NoInitialCipherSuite),
}

pub(crate) struct BlsQuicDatagramServerKeyUpdater {
    endpoint: Endpoint,
}

impl NotifyKeyUpdate for BlsQuicDatagramServerKeyUpdater {
    fn update_key(&self, key: &Keypair) -> Result<(), Box<dyn std::error::Error>> {
        self.endpoint
            .set_server_config(Some(configure_server(key)?));
        Ok(())
    }
}

pub(crate) fn spawn_bls_quic_datagram_server(
    name: &'static str,
    socket: UdpSocket,
    identity_keypair: &Keypair,
    packet_sender: Sender<PacketBatch>,
    is_staked_peer: StakedPeerChecker,
    cancel: CancellationToken,
) -> Result<SpawnBlsQuicDatagramServerResult, BlsQuicDatagramServerError> {
    info!(
        "Start {name} QUIC datagram server on {:?}",
        socket.local_addr()
    );
    let server_config = configure_server(identity_keypair)?;
    let (banlist, banlist_eviction_receiver) = SimpleQosBanlist::new();
    let banlist = Arc::new(banlist);
    let (init_sender, init_receiver) = std::sync::mpsc::sync_channel(1);
    let thread = thread::Builder::new()
        .name(name.to_string())
        .spawn({
            let banlist = banlist.clone();
            move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .thread_name(name)
                    .enable_all()
                    .build()
                    .unwrap();
                let guard = runtime.enter();
                let endpoint = Endpoint::new(
                    EndpointConfig::default(),
                    Some(server_config),
                    socket,
                    Arc::new(TokioRuntime),
                );
                let endpoint = match endpoint {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        let _ =
                            init_sender.send(Err(BlsQuicDatagramServerError::EndpointFailed(err)));
                        return;
                    }
                };
                let key_updater = Arc::new(BlsQuicDatagramServerKeyUpdater {
                    endpoint: endpoint.clone(),
                });
                let _ = init_sender.send(Ok(key_updater));
                drop(guard);

                runtime.block_on(run_server(
                    endpoint,
                    packet_sender,
                    is_staked_peer,
                    banlist,
                    banlist_eviction_receiver,
                    cancel,
                ));
            }
        })
        .unwrap();

    let key_updater = match init_receiver.recv().unwrap() {
        Ok(key_updater) => key_updater,
        Err(err) => {
            thread.join().unwrap();
            return Err(err);
        }
    };

    Ok(SpawnBlsQuicDatagramServerResult {
        thread,
        key_updater,
        banlist,
    })
}

fn configure_server(
    identity_keypair: &Keypair,
) -> Result<ServerConfig, BlsQuicDatagramServerError> {
    let (cert, priv_key) = new_dummy_x509_certificate(identity_keypair);
    let mut server_tls_config =
        tls_server_config_builder().with_single_cert(vec![cert], priv_key)?;
    server_tls_config.alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID.to_vec()];
    server_tls_config.key_log = Arc::new(KeyLogFile::new());

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls_config)?));
    server_config.migration(false);

    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0u32.into());
    transport_config.max_concurrent_bidi_streams(0u32.into());
    transport_config.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_SIZE));
    transport_config.max_idle_timeout(Some(IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap()));
    transport_config.enable_segmentation_offload(false);

    Ok(server_config)
}

async fn run_server(
    endpoint: Endpoint,
    packet_sender: Sender<PacketBatch>,
    is_staked_peer: StakedPeerChecker,
    banlist: Arc<SimpleQosBanlist>,
    mut banlist_eviction_receiver: tokio::sync::mpsc::Receiver<Pubkey>,
    cancel: CancellationToken,
) {
    let (server_event_sender, mut server_event_receiver) =
        mpsc::channel(MAX_BLS_DATAGRAM_CONNECTIONS);
    let mut active_connections = 0usize;
    let mut peer_connection_counts = HashMap::<Pubkey, usize>::new();
    let mut banlist_eviction_receiver_closed = false;

    loop {
        tokio::select! {
            maybe_incoming = endpoint.accept() => {
                let Some(incoming) = maybe_incoming else {
                    break;
                };
                tokio::spawn(handle_incoming(
                    incoming,
                    is_staked_peer.clone(),
                    banlist.clone(),
                    server_event_sender.clone(),
                ));
            }
            maybe_event = server_event_receiver.recv() => {
                let Some(event) = maybe_event else {
                    break;
                };
                handle_server_event(
                    event,
                    &packet_sender,
                    &banlist,
                    &mut active_connections,
                    &mut peer_connection_counts,
                    &server_event_sender,
                    cancel.clone(),
                );
            }
            maybe_banned_pubkey = banlist_eviction_receiver.recv(), if !banlist_eviction_receiver_closed => {
                banlist_eviction_receiver_closed = maybe_banned_pubkey.is_none();
            }
            _ = cancel.cancelled() => break,
        }
    }
    endpoint.close(VarInt::from_u32(0), b"shutdown");
}

async fn handle_incoming(
    incoming: Incoming,
    is_staked_peer: StakedPeerChecker,
    banlist: Arc<SimpleQosBanlist>,
    server_event_sender: mpsc::Sender<ServerEvent>,
) {
    let connection = match incoming.accept() {
        Ok(connecting) => match timeout(QUIC_CONNECTION_HANDSHAKE_TIMEOUT, connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(err)) => {
                debug!("votor QUIC datagram handshake failed: {err}");
                return;
            }
            Err(_) => {
                debug!("votor QUIC datagram handshake timed out");
                return;
            }
        },
        Err(err) => {
            debug!("votor QUIC datagram accept failed: {err}");
            return;
        }
    };

    let remote_addr = connection.remote_address();
    let Some(remote_pubkey) = get_remote_pubkey(&connection) else {
        close_disallowed(&connection);
        return;
    };
    if !is_staked_peer(&remote_pubkey) || banlist.is_banned(&remote_pubkey) {
        close_disallowed(&connection);
        return;
    }

    let event = ServerEvent::Accepted {
        connection,
        remote_addr,
        remote_pubkey,
    };
    let _ = server_event_sender.send(event).await;
}

fn handle_server_event(
    event: ServerEvent,
    packet_sender: &Sender<PacketBatch>,
    banlist: &Arc<SimpleQosBanlist>,
    active_connections: &mut usize,
    peer_connection_counts: &mut HashMap<Pubkey, usize>,
    server_event_sender: &mpsc::Sender<ServerEvent>,
    cancel: CancellationToken,
) {
    match event {
        ServerEvent::Accepted {
            connection,
            remote_addr,
            remote_pubkey,
        } => {
            if *active_connections >= MAX_BLS_DATAGRAM_CONNECTIONS
                || peer_connection_counts
                    .get(&remote_pubkey)
                    .copied()
                    .unwrap_or_default()
                    >= MAX_BLS_DATAGRAM_CONNECTIONS_PER_PEER
            {
                connection.close(
                    CONNECTION_CLOSE_CODE_TOO_MANY.into(),
                    CONNECTION_CLOSE_REASON_TOO_MANY,
                );
                return;
            }

            *active_connections += 1;
            *peer_connection_counts.entry(remote_pubkey).or_default() += 1;
            tokio::spawn(handle_connection_lifecycle(
                connection,
                remote_addr,
                remote_pubkey,
                packet_sender.clone(),
                banlist.clone(),
                server_event_sender.clone(),
                cancel,
            ));
        }
        ServerEvent::Closed { remote_pubkey } => {
            *active_connections = active_connections.saturating_sub(1);
            let Some(count) = peer_connection_counts.get_mut(&remote_pubkey) else {
                return;
            };
            *count = count.saturating_sub(1);
            if *count == 0 {
                peer_connection_counts.remove(&remote_pubkey);
            }
        }
    }
}

async fn handle_connection_lifecycle(
    connection: Connection,
    remote_addr: SocketAddr,
    remote_pubkey: Pubkey,
    packet_sender: Sender<PacketBatch>,
    banlist: Arc<SimpleQosBanlist>,
    server_event_sender: mpsc::Sender<ServerEvent>,
    cancel: CancellationToken,
) {
    handle_connection(
        connection,
        remote_addr,
        remote_pubkey,
        packet_sender,
        banlist,
        cancel,
    )
    .await;
    let _ = server_event_sender
        .send(ServerEvent::Closed { remote_pubkey })
        .await;
}

async fn handle_connection(
    connection: Connection,
    remote_addr: SocketAddr,
    remote_pubkey: Pubkey,
    packet_sender: Sender<PacketBatch>,
    banlist: Arc<SimpleQosBanlist>,
    cancel: CancellationToken,
) {
    let receive_rate_limiter = TokenBucket::new(
        BLS_DATAGRAM_RATE_LIMIT_BURST,
        BLS_DATAGRAM_RATE_LIMIT_BURST,
        MAX_BLS_DATAGRAMS_PER_SECOND_PER_CONNECTION,
    );
    let dos_rate_limiter = TokenBucket::new(
        BLS_DATAGRAM_DOS_BURST,
        BLS_DATAGRAM_DOS_BURST,
        MAX_BLS_DATAGRAMS_PER_SECOND_PER_CONNECTION,
    );
    let mut ban_check = tokio::time::interval(BLS_DATAGRAM_BAN_CHECK_INTERVAL);
    ban_check.tick().await;

    loop {
        if banlist.is_banned(&remote_pubkey) {
            close_disallowed(&connection);
            return;
        }

        let datagram = tokio::select! {
            datagram = connection.read_datagram() => match datagram {
                Ok(datagram) => datagram,
                Err(err) => {
                    debug!("votor QUIC datagram read failed from {remote_addr}: {err}");
                    return;
                }
            },
            _ = cancel.cancelled() => return,
            _ = ban_check.tick() => continue,
        };
        if banlist.is_banned(&remote_pubkey) {
            close_disallowed(&connection);
            return;
        }

        if dos_rate_limiter.consume_tokens(1).is_err() {
            if !banlist.ban(remote_pubkey, BLS_DATAGRAM_DOS_BAN_TIMEOUT) {
                warn!(
                    "banned votor QUIC datagram sender {remote_pubkey} at {remote_addr} for \
                     receive rate abuse"
                );
            }
            close_disallowed(&connection);
            return;
        }

        if receive_rate_limiter.consume_tokens(1).is_err() {
            debug!("dropping rate-limited votor QUIC datagram from {remote_addr}");
            continue;
        }

        if datagram.len() > PACKET_DATA_SIZE {
            debug!(
                "dropping oversized votor QUIC datagram from {remote_addr}: {} bytes",
                datagram.len()
            );
            continue;
        }

        let packet = datagram_to_packet(datagram, remote_addr, remote_pubkey);
        if let Err(err) = packet_sender.try_send(PacketBatch::Single(packet)) {
            match err {
                TrySendError::Full(_) => {
                    debug!("dropping votor QUIC datagram from {remote_addr}: packet channel full");
                }
                TrySendError::Disconnected(_) => {
                    connection.close(
                        CONNECTION_CLOSE_CODE_PACKET_CHANNEL_CLOSED.into(),
                        CONNECTION_CLOSE_REASON_PACKET_CHANNEL_CLOSED,
                    );
                    return;
                }
            }
        }
    }
}

fn datagram_to_packet(
    datagram: Bytes,
    remote_addr: SocketAddr,
    remote_pubkey: Pubkey,
) -> BytesPacket {
    let mut meta = Meta::default();
    meta.size = datagram.len();
    meta.set_socket_addr(&remote_addr);
    meta.set_from_staked_node(true);
    meta.set_remote_pubkey(remote_pubkey);
    BytesPacket::new(datagram, meta)
}

fn close_disallowed(connection: &Connection) {
    connection.close(
        CONNECTION_CLOSE_CODE_DISALLOWED.into(),
        CONNECTION_CLOSE_REASON_DISALLOWED,
    );
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        quinn::{ClientConfig, TransportConfig, crypto::rustls::QuicClientConfig},
        solana_net_utils::sockets::bind_to_localhost_unique,
        solana_signer::Signer,
        solana_tls_utils::{
            QuicClientCertificate, socket_addr_to_quic_server_name, tls_client_config_builder,
        },
        std::collections::HashMap,
    };

    #[test]
    fn test_datagram_server_receives_staked_packet() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgram",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();

        let payload = Bytes::from_static(b"votor datagram");
        send_test_datagram(server_addr, &client_keypair, payload.clone());

        let packet_batch = packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("datagram packet");
        let packet = packet_batch.first().expect("packet");
        assert_eq!(packet.meta().remote_pubkey(), Some(client_keypair.pubkey()));
        assert!(packet.meta().is_from_staked_node());
        assert_eq!(packet.data(..).unwrap(), payload.as_ref());

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_limits_connections_per_peer() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(10);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramPeerCap",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let mut held_connections = Vec::new();

        for i in 0..MAX_BLS_DATAGRAM_CONNECTIONS_PER_PEER {
            let payload = Bytes::from(format!("accepted-{i}").into_bytes());
            let client = runtime.block_on(async {
                let client = connect_test_client(server_addr, &client_keypair).await;
                client.1.send_datagram(payload.clone()).unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                client
            });
            held_connections.push(client);
            let packet_batch = packet_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("accepted datagram packet");
            let packet = packet_batch.first().expect("packet");
            assert_eq!(packet.meta().remote_pubkey(), Some(client_keypair.pubkey()));
            assert_eq!(packet.data(..).unwrap(), payload.as_ref());
        }

        let client = runtime.block_on(async {
            let client = connect_test_client(server_addr, &client_keypair).await;
            client
                .1
                .send_datagram(Bytes::from_static(b"rejected"))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            client
        });
        held_connections.push(client);
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );

        drop(held_connections);
        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_closes_banned_connection() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramBanClose",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_endpoint, connection) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));

        connection
            .send_datagram(Bytes::from_static(b"probe"))
            .unwrap();
        packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("probe datagram packet");

        server
            .banlist
            .ban(client_keypair.pubkey(), Duration::from_secs(30));
        let _ = connection.send_datagram(Bytes::from_static(b"after-ban"));
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );
        runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), connection.closed()).await
            })
            .expect("banned connection should close");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_accepts_peer_after_ban_expires() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramBanExpires",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();

        server
            .banlist
            .ban(client_keypair.pubkey(), Duration::from_millis(200));
        send_test_datagram(server_addr, &client_keypair, Bytes::from_static(b"banned"));
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );

        std::thread::sleep(Duration::from_millis(250));
        send_test_datagram(
            server_addr,
            &client_keypair,
            Bytes::from_static(b"unbanned"),
        );

        let packet_batch = packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("unbanned datagram packet");
        let packet = packet_batch.first().expect("packet");
        assert_eq!(packet.meta().remote_pubkey(), Some(client_keypair.pubkey()));
        assert_eq!(packet.data(..).unwrap(), b"unbanned");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_rate_limits_peer_burst() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::unbounded();
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramRateLimit",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_endpoint, connection) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));
        let burst = (BLS_DATAGRAM_RATE_LIMIT_BURST as usize) * 4;

        runtime.block_on(async {
            for i in 0..burst {
                connection
                    .send_datagram(Bytes::from(format!("burst-{i}").into_bytes()))
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let mut delivered = 0usize;
        while packet_receiver
            .recv_timeout(Duration::from_millis(20))
            .is_ok()
        {
            delivered = delivered.saturating_add(1);
        }

        assert!(delivered < burst);
        assert!(delivered <= BLS_DATAGRAM_RATE_LIMIT_BURST as usize + 20);
        assert!(!server.banlist.is_banned(&client_keypair.pubkey()));

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_rejects_unstaked_peer() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::new());
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramUnstaked",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_endpoint, connection) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));

        let _ = connection.send_datagram(Bytes::from_static(b"unstaked"));
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );
        runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), connection.closed()).await
            })
            .expect("unstaked connection should close");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_rejects_missing_client_identity() {
        let server_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = Arc::new(|_: &Pubkey| true) as StakedPeerChecker;
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramNoCert",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        if let Some((_endpoint, connection)) = runtime.block_on(connect_test_client_with_config(
            server_addr,
            test_client_config_without_client_cert(),
        )) {
            let _ = connection.send_datagram(Bytes::from_static(b"no-cert"));
            runtime
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(5), connection.closed()).await
                })
                .expect("connection without client identity should close");
        }
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_rejects_wrong_alpn_and_continues() {
        let server_keypair = Keypair::new();
        let bad_client_keypair = Keypair::new();
        let good_client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::from([
            (bad_client_keypair.pubkey(), 100),
            (good_client_keypair.pubkey(), 100),
        ]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramWrongAlpn",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        if let Some((_endpoint, connection)) = runtime.block_on(connect_test_client_with_config(
            server_addr,
            test_client_config_with_alpn(&bad_client_keypair, b"not-votor"),
        )) {
            let _ = connection.send_datagram(Bytes::from_static(b"wrong-alpn"));
        }
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );

        send_test_datagram(
            server_addr,
            &good_client_keypair,
            Bytes::from_static(b"valid-after-wrong-alpn"),
        );
        let packet_batch = packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("valid datagram after wrong ALPN attempt");
        let packet = packet_batch.first().expect("packet");
        assert_eq!(
            packet.meta().remote_pubkey(),
            Some(good_client_keypair.pubkey())
        );
        assert_eq!(packet.data(..).unwrap(), b"valid-after-wrong-alpn");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_sender_rejects_oversized_datagram_and_keeps_connection_open() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramOversized",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_endpoint, connection) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));

        assert!(matches!(
            connection.send_datagram(Bytes::from(vec![7; PACKET_DATA_SIZE + 1])),
            Err(quinn::SendDatagramError::TooLarge)
        ));
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );

        connection
            .send_datagram(Bytes::from_static(b"after-oversized"))
            .unwrap();
        let packet_batch = packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("valid packet after oversized datagram");
        let packet = packet_batch.first().expect("packet");
        assert_eq!(packet.data(..).unwrap(), b"after-oversized");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_drops_when_packet_channel_full_and_keeps_connection_open() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramPktFull",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_endpoint, connection) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));

        runtime.block_on(async {
            connection
                .send_datagram(Bytes::from_static(b"first"))
                .unwrap();
            connection
                .send_datagram(Bytes::from_static(b"dropped-full"))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let packet_batch = packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("first packet");
        let packet = packet_batch.first().expect("packet");
        assert_eq!(packet.data(..).unwrap(), b"first");
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(300))
                .is_err()
        );

        connection
            .send_datagram(Bytes::from_static(b"after-full"))
            .unwrap();
        let packet_batch = packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("packet after channel-full drop");
        let packet = packet_batch.first().expect("packet");
        assert_eq!(packet.data(..).unwrap(), b"after-full");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_closes_when_packet_channel_disconnected_without_exiting_thread() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        drop(packet_receiver);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramPktClosed",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_endpoint, connection) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));

        let _ = connection.send_datagram(Bytes::from_static(b"disconnected"));
        runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), connection.closed()).await
            })
            .expect("connection should close when packet channel is disconnected");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!server.thread.is_finished());

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_closes_idle_banned_connection_on_tick() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramIdleBan",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (_endpoint, connection) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));

        connection
            .send_datagram(Bytes::from_static(b"before-idle-ban"))
            .unwrap();
        packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("probe datagram packet");
        server
            .banlist
            .ban(client_keypair.pubkey(), Duration::from_secs(30));

        runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), connection.closed()).await
            })
            .expect("idle banned connection should close on ban-check tick");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_rejects_reconnect_while_banned() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramBanReconnect",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        server
            .banlist
            .ban(client_keypair.pubkey(), Duration::from_secs(30));
        let (_endpoint, connection) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));
        let _ = connection.send_datagram(Bytes::from_static(b"banned-reconnect"));
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );
        runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), connection.closed()).await
            })
            .expect("reconnected banned peer should be closed");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_same_pubkey_flood_does_not_evict_existing_connections() {
        let server_keypair = Keypair::new();
        let client_keypair = Arc::new(Keypair::new());
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(16);
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramSamePubkeyFlood",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let mut held_connections = Vec::new();

        for i in 0..MAX_BLS_DATAGRAM_CONNECTIONS_PER_PEER {
            let (_endpoint, connection) =
                runtime.block_on(connect_test_client(server_addr, &client_keypair));
            connection
                .send_datagram(Bytes::from(format!("held-{i}").into_bytes()))
                .unwrap();
            held_connections.push(connection);
            packet_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("held connection probe");
        }

        runtime.block_on(async {
            let mut handles = Vec::new();
            for i in 0..16usize {
                let payload = Bytes::from(format!("flood-{i}").into_bytes());
                handles.push(tokio::spawn(try_send_test_datagram(
                    server_addr,
                    Arc::clone(&client_keypair),
                    payload,
                )));
            }
            for handle in handles {
                let _ = handle.await;
            }
        });
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );

        held_connections[0]
            .send_datagram(Bytes::from_static(b"after-flood"))
            .unwrap();
        let packet_batch = packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("held connection should survive same-pubkey flood");
        let packet = packet_batch.first().expect("packet");
        assert_eq!(packet.data(..).unwrap(), b"after-flood");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_handles_many_concurrent_staked_connections() {
        const PEERS: usize = 32;
        let server_keypair = Keypair::new();
        let client_keypairs: Vec<_> = (0..PEERS).map(|_| Keypair::new()).collect();
        let stakes = client_keypairs
            .iter()
            .map(|keypair| (keypair.pubkey(), 100))
            .collect::<HashMap<_, _>>();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(PEERS);
        let is_staked_peer = staked_peer_checker(stakes);
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramManyStaked",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut handles = Vec::new();
            for (i, client_keypair) in client_keypairs.into_iter().enumerate() {
                let payload = Bytes::from(format!("peer-{i}").into_bytes());
                handles.push(tokio::spawn(try_send_test_datagram(
                    server_addr,
                    Arc::new(client_keypair),
                    payload,
                )));
            }
            for handle in handles {
                handle.await.unwrap();
            }
        });

        let mut delivered = 0usize;
        while delivered < PEERS {
            let packet_batch = packet_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("concurrent staked datagram");
            let packet = packet_batch.first().expect("packet");
            assert!(packet.meta().remote_pubkey().is_some());
            assert!(packet.meta().is_from_staked_node());
            delivered += 1;
        }

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_unstaked_flood_does_not_starve_staked_peer() {
        const UNSTAKED_PEERS: usize = 32;
        let server_keypair = Keypair::new();
        let staked_client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::bounded(1);
        let is_staked_peer =
            staked_peer_checker(HashMap::from([(staked_client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramUnstakedFlood",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut handles = Vec::new();
            for i in 0..UNSTAKED_PEERS {
                handles.push(tokio::spawn(try_send_test_datagram(
                    server_addr,
                    Arc::new(Keypair::new()),
                    Bytes::from(format!("unstaked-{i}").into_bytes()),
                )));
            }
            for handle in handles {
                let _ = handle.await;
            }
        });
        assert!(
            packet_receiver
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );

        send_test_datagram(
            server_addr,
            &staked_client_keypair,
            Bytes::from_static(b"staked-after-flood"),
        );
        let packet_batch = packet_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("staked datagram after unstaked flood");
        let packet = packet_batch.first().expect("packet");
        assert_eq!(
            packet.meta().remote_pubkey(),
            Some(staked_client_keypair.pubkey())
        );
        assert_eq!(packet.data(..).unwrap(), b"staked-after-flood");

        cancel.cancel();
        server.thread.join().unwrap();
    }

    #[test]
    fn test_datagram_server_rate_limits_each_allowed_connection() {
        let server_keypair = Keypair::new();
        let client_keypair = Keypair::new();
        let server_socket = bind_to_localhost_unique().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let (packet_sender, packet_receiver) = crossbeam_channel::unbounded();
        let is_staked_peer = staked_peer_checker(HashMap::from([(client_keypair.pubkey(), 100)]));
        let cancel = CancellationToken::new();
        let server = spawn_bls_quic_datagram_server(
            "testBlsDgramTwoConnRateLimit",
            server_socket,
            &server_keypair,
            packet_sender,
            is_staked_peer,
            cancel.clone(),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (_endpoint_a, connection_a) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));
        let (_endpoint_b, connection_b) =
            runtime.block_on(connect_test_client(server_addr, &client_keypair));
        let burst = (BLS_DATAGRAM_RATE_LIMIT_BURST as usize) * 4;

        runtime.block_on(async {
            for i in 0..burst {
                connection_a
                    .send_datagram(Bytes::from(format!("a-{i}").into_bytes()))
                    .unwrap();
                connection_b
                    .send_datagram(Bytes::from(format!("b-{i}").into_bytes()))
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let mut delivered = 0usize;
        while packet_receiver
            .recv_timeout(Duration::from_millis(20))
            .is_ok()
        {
            delivered = delivered.saturating_add(1);
        }

        assert!(delivered < burst * 2);
        assert!(delivered <= (BLS_DATAGRAM_RATE_LIMIT_BURST as usize * 2) + 40);
        assert!(!server.banlist.is_banned(&client_keypair.pubkey()));

        cancel.cancel();
        server.thread.join().unwrap();
    }

    fn staked_peer_checker(stakes: HashMap<Pubkey, u64>) -> StakedPeerChecker {
        Arc::new(move |pubkey| stakes.get(pubkey).copied().unwrap_or_default() > 0)
    }

    async fn connect_test_client(
        server_addr: SocketAddr,
        client_keypair: &Keypair,
    ) -> (Endpoint, Connection) {
        connect_test_client_with_config(server_addr, test_client_config(client_keypair))
            .await
            .expect("test client connection")
    }

    async fn connect_test_client_with_config(
        server_addr: SocketAddr,
        client_config: ClientConfig,
    ) -> Option<(Endpoint, Connection)> {
        let client_socket = bind_to_localhost_unique().unwrap();
        let mut endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            client_socket,
            Arc::new(TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(client_config);
        let server_name = socket_addr_to_quic_server_name(server_addr);
        let connecting = endpoint.connect(server_addr, &server_name).ok()?;
        let connection = connecting.await.ok()?;
        Some((endpoint, connection))
    }

    async fn try_send_test_datagram(
        server_addr: SocketAddr,
        client_keypair: Arc<Keypair>,
        payload: Bytes,
    ) {
        if let Some((_endpoint, connection)) =
            connect_test_client_with_config(server_addr, test_client_config(&client_keypair)).await
        {
            let _ = connection.send_datagram(payload);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn send_test_datagram(server_addr: SocketAddr, client_keypair: &Keypair, payload: Bytes) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (_endpoint, connection) = connect_test_client(server_addr, client_keypair).await;
            connection.send_datagram(payload).unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    }

    fn test_client_config(keypair: &Keypair) -> ClientConfig {
        test_client_config_with_alpn(keypair, ALPN_TPU_PROTOCOL_ID)
    }

    fn test_client_config_with_alpn(keypair: &Keypair, alpn: &[u8]) -> ClientConfig {
        let client_certificate = QuicClientCertificate::new(Some(keypair));
        let mut crypto = tls_client_config_builder()
            .with_client_auth_cert(vec![client_certificate.certificate], client_certificate.key)
            .unwrap();
        crypto.alpn_protocols = vec![alpn.to_vec()];
        test_client_config_from_crypto(crypto)
    }

    fn test_client_config_without_client_cert() -> ClientConfig {
        let mut crypto = tls_client_config_builder().with_no_client_auth();
        crypto.alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID.to_vec()];
        test_client_config_from_crypto(crypto)
    }

    fn test_client_config_from_crypto(crypto: rustls::ClientConfig) -> ClientConfig {
        let mut transport_config = TransportConfig::default();
        transport_config.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_SIZE));
        let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
        config.transport_config(Arc::new(transport_config));
        config
    }
}

#[cfg(all(test, feature = "shuttle-test"))]
mod shuttle_tests {
    use std::collections::{HashMap, HashSet};

    #[derive(Clone, Copy, Debug)]
    enum ModelEvent {
        Accepted { peer: u8, connection_id: u8 },
        Closed { peer: u8, connection_id: u8 },
        Banned(u8),
        Datagram(u8),
    }

    #[derive(Debug)]
    struct ConnectionControllerModel {
        active_connections: usize,
        peer_connection_ids: HashMap<u8, HashSet<u8>>,
        admitted_connection_ids: HashSet<u8>,
        banned: HashSet<u8>,
        forwarded: usize,
        banned_datagrams_dropped: usize,
        dropped: usize,
        global_cap: usize,
        per_peer_cap: usize,
    }

    impl ConnectionControllerModel {
        fn new(global_cap: usize, per_peer_cap: usize) -> Self {
            Self {
                active_connections: 0,
                peer_connection_ids: HashMap::new(),
                admitted_connection_ids: HashSet::new(),
                banned: HashSet::new(),
                forwarded: 0,
                banned_datagrams_dropped: 0,
                dropped: 0,
                global_cap,
                per_peer_cap,
            }
        }

        fn apply(&mut self, event: ModelEvent) {
            match event {
                ModelEvent::Accepted {
                    peer,
                    connection_id,
                } => {
                    let peer_count = self
                        .peer_connection_ids
                        .get(&peer)
                        .map(HashSet::len)
                        .unwrap_or_default();
                    if self.banned.contains(&peer)
                        || self.active_connections >= self.global_cap
                        || peer_count >= self.per_peer_cap
                        || self.admitted_connection_ids.contains(&connection_id)
                    {
                        self.dropped += 1;
                    } else {
                        self.active_connections += 1;
                        self.admitted_connection_ids.insert(connection_id);
                        self.peer_connection_ids
                            .entry(peer)
                            .or_default()
                            .insert(connection_id);
                    }
                }
                ModelEvent::Closed {
                    peer,
                    connection_id,
                } => {
                    if self.admitted_connection_ids.remove(&connection_id) {
                        self.active_connections = self.active_connections.saturating_sub(1);
                        if let Some(peer_connections) = self.peer_connection_ids.get_mut(&peer) {
                            peer_connections.remove(&connection_id);
                            if peer_connections.is_empty() {
                                self.peer_connection_ids.remove(&peer);
                            }
                        }
                    } else {
                        self.dropped += 1;
                    }
                }
                ModelEvent::Banned(peer) => {
                    self.banned.insert(peer);
                }
                ModelEvent::Datagram(peer) => {
                    if self.banned.contains(&peer) {
                        self.banned_datagrams_dropped += 1;
                        self.dropped += 1;
                    } else if self
                        .peer_connection_ids
                        .get(&peer)
                        .map(HashSet::is_empty)
                        .unwrap_or(true)
                    {
                        self.dropped += 1;
                    } else {
                        self.forwarded += 1;
                    }
                }
            }
            self.assert_invariants();
        }

        fn assert_invariants(&self) {
            assert!(self.active_connections <= self.global_cap);
            assert!(
                self.peer_connection_ids
                    .values()
                    .all(|connections| connections.len() <= self.per_peer_cap)
            );
            let per_peer_sum = self
                .peer_connection_ids
                .values()
                .map(HashSet::len)
                .sum::<usize>();
            assert_eq!(per_peer_sum, self.active_connections);
            assert_eq!(self.admitted_connection_ids.len(), self.active_connections);
        }
    }

    fn drain_model_events(
        receiver: shuttle::sync::mpsc::Receiver<ModelEvent>,
        global_cap: usize,
        per_peer_cap: usize,
    ) -> ConnectionControllerModel {
        let mut model = ConnectionControllerModel::new(global_cap, per_peer_cap);
        while let Ok(event) = receiver.recv() {
            model.apply(event);
            shuttle::thread::yield_now();
        }
        model
    }

    #[test]
    fn shuttle_test_connection_caps_hold_under_accept_close_races() {
        shuttle::check_random(
            || {
                let (sender, receiver) = shuttle::sync::mpsc::sync_channel(2);
                for (connection_id, peer) in [0, 0, 0, 1, 1, 2, 3].into_iter().enumerate() {
                    let sender = sender.clone();
                    shuttle::thread::spawn(move || {
                        let connection_id = connection_id as u8;
                        sender
                            .send(ModelEvent::Accepted {
                                peer,
                                connection_id,
                            })
                            .unwrap();
                        shuttle::thread::yield_now();
                        sender
                            .send(ModelEvent::Closed {
                                peer,
                                connection_id,
                            })
                            .unwrap();
                    });
                }
                drop(sender);

                let model = drain_model_events(receiver, 3, 2);
                assert_eq!(model.forwarded, 0);
            },
            500,
        );
    }

    #[test]
    fn shuttle_test_duplicate_close_events_do_not_underflow_controller_state() {
        shuttle::check_random(
            || {
                let (sender, receiver) = shuttle::sync::mpsc::sync_channel(1);
                for event in [
                    ModelEvent::Accepted {
                        peer: 0,
                        connection_id: 1,
                    },
                    ModelEvent::Closed {
                        peer: 0,
                        connection_id: 1,
                    },
                    ModelEvent::Closed {
                        peer: 0,
                        connection_id: 1,
                    },
                    ModelEvent::Accepted {
                        peer: 0,
                        connection_id: 2,
                    },
                    ModelEvent::Datagram(0),
                ] {
                    let sender = sender.clone();
                    shuttle::thread::spawn(move || {
                        sender.send(event).unwrap();
                    });
                }
                drop(sender);

                let model = drain_model_events(receiver, 1, 1);
                assert!(model.active_connections <= 1);
                assert!(
                    model
                        .peer_connection_ids
                        .get(&0)
                        .map(HashSet::len)
                        .unwrap_or_default()
                        <= 1
                );
            },
            500,
        );
    }

    #[test]
    fn shuttle_test_ban_datagram_interleavings_never_forward_after_ban_is_observed() {
        shuttle::check_random(
            || {
                let (sender, receiver) = shuttle::sync::mpsc::sync_channel(2);
                {
                    let sender = sender.clone();
                    shuttle::thread::spawn(move || {
                        sender
                            .send(ModelEvent::Accepted {
                                peer: 0,
                                connection_id: 1,
                            })
                            .unwrap();
                        shuttle::thread::yield_now();
                        sender.send(ModelEvent::Banned(0)).unwrap();
                        shuttle::thread::yield_now();
                        sender.send(ModelEvent::Datagram(0)).unwrap();
                        sender
                            .send(ModelEvent::Closed {
                                peer: 0,
                                connection_id: 1,
                            })
                            .unwrap();
                    });
                }
                {
                    let sender = sender.clone();
                    shuttle::thread::spawn(move || {
                        sender.send(ModelEvent::Datagram(0)).unwrap();
                    });
                }
                drop(sender);

                let model = drain_model_events(receiver, 2, 2);
                assert!(model.banned_datagrams_dropped >= 1);
            },
            1_000,
        );
    }

    #[test]
    fn shuttle_test_bounded_event_channel_backpressure_does_not_deadlock_model() {
        shuttle::check_random(
            || {
                let (sender, receiver) = shuttle::sync::mpsc::sync_channel(1);
                for peer in 0..4 {
                    let sender = sender.clone();
                    shuttle::thread::spawn(move || {
                        sender
                            .send(ModelEvent::Accepted {
                                peer,
                                connection_id: peer,
                            })
                            .unwrap();
                        sender.send(ModelEvent::Datagram(peer)).unwrap();
                        sender
                            .send(ModelEvent::Closed {
                                peer,
                                connection_id: peer,
                            })
                            .unwrap();
                    });
                }
                drop(sender);

                let model = drain_model_events(receiver, 2, 1);
                assert!(model.forwarded <= 4);
                assert!(model.active_connections <= 2);
            },
            500,
        );
    }
}
