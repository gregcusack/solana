use {
    arc_swap::ArcSwap,
    bytes::Bytes,
    quinn::{
        ClientConfig, ConnectError, Connection, ConnectionError, Endpoint, EndpointConfig,
        IdleTimeout, SendDatagramError, TokioRuntime, TransportConfig,
        crypto::rustls::QuicClientConfig,
    },
    rustls::KeyLogFile,
    solana_keypair::Keypair,
    solana_streamer::{nonblocking::quic::ALPN_TPU_PROTOCOL_ID, packet::PACKET_DATA_SIZE},
    solana_tls_utils::{
        NotifyKeyUpdate, QuicClientCertificate, socket_addr_to_quic_server_name,
        tls_client_config_builder,
    },
    std::{
        collections::HashMap,
        net::{SocketAddr, UdpSocket},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    },
    tokio::{task::JoinHandle, time::timeout},
};

const QUIC_MAX_TIMEOUT: Duration = Duration::from_secs(10);
const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(1);
const QUIC_CONNECTION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const DATAGRAM_RECEIVE_BUFFER_SIZE: usize = PACKET_DATA_SIZE * 64;
const CONNECTION_CLOSE_CODE: u32 = 0;
const CONNECTION_CLOSE_REASON_KEY_UPDATE: &[u8] = b"key_update";

pub struct QuicDatagramSenderConfig {
    pub client_socket: UdpSocket,
    pub key_updater: Arc<QuicDatagramClientKeyUpdater>,
}

pub struct QuicDatagramClientKeyUpdater {
    client_certificate: ArcSwap<QuicClientCertificate>,
    dirty: AtomicBool,
}

impl QuicDatagramClientKeyUpdater {
    pub fn new(keypair: &Keypair) -> Self {
        Self {
            client_certificate: ArcSwap::new(Arc::new(QuicClientCertificate::new(Some(keypair)))),
            dirty: AtomicBool::new(false),
        }
    }

    fn client_config(&self) -> ClientConfig {
        let client_certificate = self.client_certificate.load_full();
        client_config(client_certificate.as_ref())
    }

    fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::AcqRel)
    }
}

impl NotifyKeyUpdate for QuicDatagramClientKeyUpdater {
    fn update_key(&self, key: &Keypair) -> Result<(), Box<dyn std::error::Error>> {
        self.client_certificate
            .store(Arc::new(QuicClientCertificate::new(Some(key))));
        self.dirty.store(true, Ordering::Release);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuicDatagramSenderError {
    #[error("QUIC endpoint creation failed: {0}")]
    EndpointFailed(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
enum ConnectAndSendError {
    #[error("connect failed: {0}")]
    Connect(#[from] ConnectError),
    #[error("connection failed: {0}")]
    Connection(#[from] ConnectionError),
    #[error("datagram send failed: {0}")]
    SendDatagram(#[from] SendDatagramError),
    #[error("connection timed out")]
    Timeout,
}

enum PeerConnection {
    Connected(Connection),
    Connecting(JoinHandle<Result<Connection, ConnectAndSendError>>),
}

pub(crate) struct QuicDatagramSender {
    endpoint: Endpoint,
    key_updater: Arc<QuicDatagramClientKeyUpdater>,
    connections: HashMap<SocketAddr, PeerConnection>,
}

impl QuicDatagramSender {
    pub(crate) fn new(config: QuicDatagramSenderConfig) -> Result<Self, QuicDatagramSenderError> {
        let QuicDatagramSenderConfig {
            client_socket,
            key_updater,
        } = config;
        let mut endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            client_socket,
            Arc::new(TokioRuntime),
        )?;
        endpoint.set_default_client_config(key_updater.client_config());
        Ok(Self {
            endpoint,
            key_updater,
            connections: HashMap::new(),
        })
    }

    pub(crate) async fn send(&mut self, addr: SocketAddr, data: &[u8]) {
        self.apply_key_update_if_needed();

        let data = Bytes::copy_from_slice(data);
        match self.connections.remove(&addr) {
            Some(PeerConnection::Connected(connection)) => {
                self.send_on_connection(addr, connection, data);
            }
            Some(PeerConnection::Connecting(handle)) => {
                if handle.is_finished() {
                    match handle.await {
                        Ok(Ok(connection)) => self.send_on_connection(addr, connection, data),
                        Ok(Err(err)) => {
                            warn!("Failed to connect votor QUIC datagram peer {addr}: {err}");
                            self.start_connecting(addr, data);
                        }
                        Err(err) => {
                            warn!("Votor QUIC datagram connect task failed for {addr}: {err}");
                            self.start_connecting(addr, data);
                        }
                    }
                } else {
                    debug!("dropping votor QUIC datagram to {addr}: connection in progress");
                    self.connections
                        .insert(addr, PeerConnection::Connecting(handle));
                }
            }
            None => self.start_connecting(addr, data),
        }
    }

    fn apply_key_update_if_needed(&mut self) {
        if !self.key_updater.take_dirty() {
            return;
        }
        self.endpoint
            .set_default_client_config(self.key_updater.client_config());
        for (_, connection) in self.connections.drain() {
            match connection {
                PeerConnection::Connected(connection) => connection.close(
                    CONNECTION_CLOSE_CODE.into(),
                    CONNECTION_CLOSE_REASON_KEY_UPDATE,
                ),
                PeerConnection::Connecting(handle) => handle.abort(),
            }
        }
    }

    fn send_on_connection(&mut self, addr: SocketAddr, connection: Connection, data: Bytes) {
        match connection.send_datagram(data.clone()) {
            Ok(()) => {
                self.connections
                    .insert(addr, PeerConnection::Connected(connection));
            }
            Err(SendDatagramError::ConnectionLost(err)) => {
                warn!("Lost votor QUIC datagram connection to {addr}: {err}");
                self.start_connecting(addr, data);
            }
            Err(err) => {
                warn!("Failed to send votor QUIC datagram to {addr}: {err}");
                self.connections
                    .insert(addr, PeerConnection::Connected(connection));
            }
        }
    }

    fn start_connecting(&mut self, addr: SocketAddr, data: Bytes) {
        let endpoint = self.endpoint.clone();
        let handle = tokio::spawn(connect_and_send(endpoint, addr, data));
        self.connections
            .insert(addr, PeerConnection::Connecting(handle));
    }
}

fn client_config(client_certificate: &QuicClientCertificate) -> ClientConfig {
    let mut crypto = tls_client_config_builder()
        .with_client_auth_cert(
            vec![client_certificate.certificate.clone()],
            client_certificate.key.clone_key(),
        )
        .expect("valid votor QUIC client certificate");
    crypto.enable_early_data = true;
    crypto.alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID.to_vec()];
    crypto.key_log = Arc::new(KeyLogFile::new());

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap()));
    transport_config.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
    transport_config.send_fairness(false);
    transport_config.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_SIZE));

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    config.transport_config(Arc::new(transport_config));
    config
}

async fn connect_and_send(
    endpoint: Endpoint,
    addr: SocketAddr,
    data: Bytes,
) -> Result<Connection, ConnectAndSendError> {
    let server_name = socket_addr_to_quic_server_name(addr);
    let connecting = endpoint.connect(addr, &server_name)?;
    let connection = timeout(QUIC_CONNECTION_HANDSHAKE_TIMEOUT, connecting)
        .await
        .map_err(|_| ConnectAndSendError::Timeout)??;
    connection.send_datagram(data)?;
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        quinn::{ServerConfig, crypto::rustls::QuicServerConfig},
        solana_net_utils::sockets::bind_to_localhost_unique,
        solana_tls_utils::{new_dummy_x509_certificate, tls_server_config_builder},
    };

    #[test]
    fn test_send_drops_datagrams_while_connecting() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let server_keypair = Keypair::new();
            let server_socket = bind_to_localhost_unique().unwrap();
            let server_addr = server_socket.local_addr().unwrap();
            let endpoint = Endpoint::new(
                EndpointConfig::default(),
                Some(test_server_config(&server_keypair)),
                server_socket,
                Arc::new(TokioRuntime),
            )
            .unwrap();
            let client_keypair = Keypair::new();
            let mut sender = QuicDatagramSender::new(QuicDatagramSenderConfig {
                client_socket: bind_to_localhost_unique().unwrap(),
                key_updater: Arc::new(QuicDatagramClientKeyUpdater::new(&client_keypair)),
            })
            .unwrap();

            sender.send(server_addr, b"first").await;
            sender.send(server_addr, b"second").await;

            let incoming = endpoint.accept().await.unwrap();
            let connection = timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let first = timeout(Duration::from_secs(5), connection.read_datagram())
                .await
                .unwrap()
                .unwrap();
            let second = timeout(Duration::from_millis(200), connection.read_datagram()).await;

            assert_eq!(first.as_ref(), b"first");
            assert!(second.is_err());
        });
    }

    fn test_server_config(keypair: &Keypair) -> ServerConfig {
        let (cert, priv_key) = new_dummy_x509_certificate(keypair);
        let mut server_tls_config = tls_server_config_builder()
            .with_single_cert(vec![cert], priv_key)
            .unwrap();
        server_tls_config.alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID.to_vec()];
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls_config).unwrap(),
        ));
        server_config.migration(false);
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0u32.into());
        transport_config.max_concurrent_bidi_streams(0u32.into());
        transport_config.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_SIZE));
        transport_config.max_idle_timeout(Some(IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap()));
        server_config
    }
}
