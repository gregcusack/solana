//! Votor-specific QUIC datagram transport.

use {
    arc_swap::ArcSwap,
    bytes::Bytes,
    crossbeam_channel::{Sender, TrySendError},
    quinn::{
        AckFrequencyConfig, ClientConfig, Connection, Endpoint, EndpointConfig, IdleTimeout,
        Incoming, SendDatagramError, ServerConfig, TokioRuntime, TransportConfig, VarInt,
        congestion::{Controller, ControllerFactory},
        crypto::rustls::{QuicClientConfig, QuicServerConfig},
    },
    quinn_proto::RttEstimator,
    rustls::pki_types::{CertificateDer, PrivateKeyDer},
    solana_keypair::{Keypair, Signer},
    solana_metrics::datapoint_info,
    solana_net_utils::{banlist::Banlist, token_bucket::TokenBucket},
    solana_pubkey::Pubkey,
    solana_runtime::bank_forks::SharableBanks,
    solana_tls_utils::{
        NotifyKeyUpdate, get_remote_pubkey, new_dummy_x509_certificate,
        socket_addr_to_quic_server_name, tls_client_config_builder, tls_server_config_builder,
    },
    std::{
        any::Any,
        collections::{HashMap, hash_map::Entry},
        net::{SocketAddr, UdpSocket},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    },
    tokio::{
        sync::{mpsc, watch},
        time::MissedTickBehavior,
    },
    tokio_util::sync::CancellationToken,
};

const ALPENGLOW_ALPN: &[u8] = b"alpenglow-v1";

const MAX_PEERS: u64 = 2000;
const EGRESS_CHANNEL_CAP: usize = 4 * MAX_PEERS as usize;
const CONN_EVENT_CHANNEL_CAP: usize = MAX_PEERS as usize;
const MAX_INBOUND_CONNECTIONS_PER_PEER: usize = 2;
const HANDSHAKE_GLOBAL_BURST: u64 = 200;
const HANDSHAKE_GLOBAL_REFILL_PER_SECOND: f64 = 40.0;
const MAX_DATAGRAMS_PER_SECOND_PER_PEER: f64 = 30.0;
const PEER_RATE_LIMIT_BURST: u64 = 100;
const PEER_RATE_LIMIT_BURST_DOS: u64 = 100_000;
const BAN_DURATION_DOS: Duration = Duration::from_secs(48 * 60 * 60);
const ALLOWLIST_CHECK_INTERVAL: Duration = Duration::from_secs(10);
const BANLIST_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const METRICS_INTERVAL: Duration = Duration::from_secs(2);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(600);
const MAX_ACK_DELAY: Duration = Duration::from_millis(400);
const INITIAL_MTU: u16 = 1280;
const MIN_MTU: u16 = 1280;
const NOP_CONGESTION_WINDOW: u64 = 8 * 1024 * 1024;
const DATAGRAM_RECEIVE_BUFFER: usize = MAX_PEERS as usize * 8;
const DATAGRAM_SEND_BUFFER: usize = MAX_PEERS as usize * 2;

const CLOSE_INVALID_IDENTITY: VarInt = VarInt::from_u32(2);
const CLOSE_NOT_ADMITTED: VarInt = VarInt::from_u32(3);
const CLOSE_BANNED: VarInt = VarInt::from_u32(4);
const CLOSE_TABLE_FULL: VarInt = VarInt::from_u32(5);
const CLOSE_IDENTITY_ROTATED: VarInt = VarInt::from_u32(11);
const CLOSE_PEER_MOVED: VarInt = VarInt::from_u32(12);

#[derive(Debug)]
pub struct Datagram {
    pub peer_pubkey: Pubkey,
    pub peer_address: SocketAddr,
    pub message: Bytes,
}

#[derive(Default)]
pub struct StakedNodesAllowlist {
    inner: ArcSwap<HashMap<Pubkey, u64>>,
    allow_all: bool,
}

impl StakedNodesAllowlist {
    pub fn new(peers: HashMap<Pubkey, u64>) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(peers)),
            allow_all: false,
        }
    }

    pub fn allow_all_for_tests() -> Self {
        Self {
            inner: ArcSwap::default(),
            allow_all: true,
        }
    }

    pub fn swap(&self, peers: HashMap<Pubkey, u64>) {
        self.inner.store(Arc::new(peers));
    }

    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    pub fn is_empty(&self) -> bool {
        !self.allow_all && self.inner.load().is_empty()
    }

    pub fn allow(&self, peer: &Pubkey) -> bool {
        self.allow_all || self.inner.load().contains_key(peer)
    }
}

pub fn current_admit_set(banks: &SharableBanks) -> HashMap<Pubkey, u64> {
    let bank = banks.working();
    let epoch = bank.epoch();
    bank.epoch_staked_nodes(epoch)
        .map(|nodes| {
            nodes
                .iter()
                .filter(|(_, stake)| **stake > 0)
                .map(|(pubkey, stake)| (*pubkey, *stake))
                .collect()
        })
        .unwrap_or_default()
}

pub fn build_allowlist(banks: &SharableBanks) -> Arc<StakedNodesAllowlist> {
    Arc::new(StakedNodesAllowlist::new(current_admit_set(banks)))
}

struct IdentitySnapshot {
    pubkey: Pubkey,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl IdentitySnapshot {
    fn from_keypair(keypair: &Keypair) -> Self {
        let (cert, key) = new_dummy_x509_certificate(keypair);
        Self {
            pubkey: keypair.pubkey(),
            cert,
            key,
        }
    }
}

pub struct KeyUpdater {
    tx: watch::Sender<Option<Arc<IdentitySnapshot>>>,
}

impl NotifyKeyUpdate for KeyUpdater {
    fn update_key(&self, keypair: &Keypair) -> Result<(), Box<dyn std::error::Error>> {
        self.tx
            .send(Some(Arc::new(IdentitySnapshot::from_keypair(keypair))))
            .map_err(|_| "votor datagram endpoint is shut down".into())
    }
}

#[derive(Default)]
struct DatagramStats {
    peak_connections: AtomicU64,
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    connection_lost: AtomicU64,
    connect_failed: AtomicU64,
    egress_dropped_dial_in_progress: AtomicU64,
    datagram_rate_limited: AtomicU64,
    ingress_dropped_channel_full: AtomicU64,
    handshake_rejected_global_limit: AtomicU64,
    handshake_rejected_unauthorized: AtomicU64,
    handshake_rejected_overload: AtomicU64,
    connection_evicted_identity_rotated: AtomicU64,
    connection_evicted_allowlist: AtomicU64,
    connection_evicted_peer_moved: AtomicU64,
}

impl DatagramStats {
    fn record_connection_count(&self, count: u64) {
        self.peak_connections.fetch_max(count, Ordering::Relaxed);
    }
}

fn add(metric: &AtomicU64) {
    metric.fetch_add(1, Ordering::Relaxed);
}

fn take_peak(stats: &DatagramStats, live_connections: u64) -> i64 {
    stats
        .peak_connections
        .swap(live_connections, Ordering::Relaxed)
        .max(live_connections) as i64
}

fn swap(metric: &AtomicU64) -> i64 {
    metric.swap(0, Ordering::Relaxed) as i64
}

fn report_client(stats: &DatagramStats, live_connections: u64) {
    datapoint_info!(
        "votor_datagram_client",
        ("connections_peak", take_peak(stats, live_connections), i64),
        ("datagrams_sent", swap(&stats.datagrams_sent), i64),
        ("connect_failed", swap(&stats.connect_failed), i64),
        ("connection_lost", swap(&stats.connection_lost), i64),
        (
            "egress_dropped_dial_in_progress",
            swap(&stats.egress_dropped_dial_in_progress),
            i64
        ),
        (
            "connection_evicted_peer_moved",
            swap(&stats.connection_evicted_peer_moved),
            i64
        ),
        (
            "connection_evicted_identity_rotated",
            swap(&stats.connection_evicted_identity_rotated),
            i64
        ),
    );
}

fn report_server(stats: &DatagramStats, live_connections: u64) {
    datapoint_info!(
        "votor_datagram_server",
        ("connections_peak", take_peak(stats, live_connections), i64),
        ("datagrams_received", swap(&stats.datagrams_received), i64),
        ("connect_failed", swap(&stats.connect_failed), i64),
        ("connection_lost", swap(&stats.connection_lost), i64),
        (
            "datagram_rate_limited",
            swap(&stats.datagram_rate_limited),
            i64
        ),
        (
            "datagram_ingress_dropped_channel_full",
            swap(&stats.ingress_dropped_channel_full),
            i64
        ),
        (
            "handshake_rejected_global_limit",
            swap(&stats.handshake_rejected_global_limit),
            i64
        ),
        (
            "handshake_rejected_unauthorized",
            swap(&stats.handshake_rejected_unauthorized),
            i64
        ),
        (
            "handshake_rejected_overload",
            swap(&stats.handshake_rejected_overload),
            i64
        ),
        (
            "connection_evicted_allowlist",
            swap(&stats.connection_evicted_allowlist),
            i64
        ),
        (
            "connection_evicted_identity_rotated",
            swap(&stats.connection_evicted_identity_rotated),
            i64
        ),
    );
}

pub struct VotorDatagramEndpoint {
    pub egress: mpsc::Sender<Datagram>,
    pub key_updater: Arc<KeyUpdater>,
    shutdown: CancellationToken,
}

impl VotorDatagramEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: &tokio::runtime::Handle,
        keypair: &Keypair,
        socket: UdpSocket,
        ingress: Sender<Datagram>,
        allowlist: Arc<StakedNodesAllowlist>,
        banlist: Arc<Banlist<Pubkey>>,
    ) -> std::io::Result<Self> {
        let local_pubkey = keypair.pubkey();
        let (cert, key) = new_dummy_x509_certificate(keypair);
        let server_config = new_server_config(cert.clone(), key.clone_key());
        let client_config = new_client_config(cert, key);

        let mut endpoint = {
            let _guard = runtime.enter();
            Endpoint::new(
                EndpointConfig::default(),
                Some(server_config),
                socket,
                Arc::new(TokioRuntime),
            )?
        };
        endpoint.set_default_client_config(client_config);

        let (egress_tx, egress_rx) = mpsc::channel(EGRESS_CHANNEL_CAP);
        let (out_events_tx, out_events_rx) = mpsc::channel(CONN_EVENT_CHANNEL_CAP);
        let (in_events_tx, in_events_rx) = mpsc::channel(CONN_EVENT_CHANNEL_CAP);
        let (id_tx, identity_rx) = watch::channel(None);
        let key_updater = Arc::new(KeyUpdater { tx: id_tx });
        let shutdown = CancellationToken::new();

        runtime.spawn(
            OutboundLoop {
                endpoint: endpoint.clone(),
                local_pubkey,
                generation: 0,
                egress_rx,
                banlist: banlist.clone(),
                identity_rx: identity_rx.clone(),
                outgoing: HashMap::new(),
                events_tx: out_events_tx,
                events_rx: out_events_rx,
                shutdown: shutdown.clone(),
                stats: Arc::default(),
            }
            .run(),
        );
        runtime.spawn(
            InboundLoop {
                endpoint,
                generation: 0,
                ingress,
                allowlist,
                banlist,
                identity_rx,
                incoming: HashMap::new(),
                events_tx: in_events_tx,
                events_rx: in_events_rx,
                handshake_global_limiter: TokenBucket::new(
                    HANDSHAKE_GLOBAL_BURST,
                    HANDSHAKE_GLOBAL_BURST,
                    HANDSHAKE_GLOBAL_REFILL_PER_SECOND,
                ),
                stats: Arc::default(),
                shutdown: shutdown.clone(),
            }
            .run(),
        );

        Ok(Self {
            egress: egress_tx,
            key_updater,
            shutdown,
        })
    }

    pub fn close(&self) {
        self.shutdown.cancel();
    }
}

enum OutgoingEntry {
    Dialing,
    Established(Connection),
}

enum OutboundEvent {
    Dialed {
        peer: Pubkey,
        generation: u64,
        outcome: Option<Connection>,
    },
    Closed {
        peer: Pubkey,
        generation: u64,
        stable_id: usize,
    },
}

struct OutboundLoop {
    endpoint: Endpoint,
    local_pubkey: Pubkey,
    generation: u64,
    egress_rx: mpsc::Receiver<Datagram>,
    banlist: Arc<Banlist<Pubkey>>,
    identity_rx: watch::Receiver<Option<Arc<IdentitySnapshot>>>,
    outgoing: HashMap<Pubkey, OutgoingEntry>,
    events_tx: mpsc::Sender<OutboundEvent>,
    events_rx: mpsc::Receiver<OutboundEvent>,
    shutdown: CancellationToken,
    stats: Arc<DatagramStats>,
}

impl OutboundLoop {
    async fn run(mut self) {
        let mut metrics = tokio::time::interval(METRICS_INTERVAL);
        metrics.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut identity_closed = false;
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                changed = self.identity_rx.changed(), if !identity_closed => {
                    if changed.is_err() {
                        identity_closed = true;
                        continue;
                    }
                    let snapshot = self.identity_rx.borrow_and_update().clone();
                    if let Some(snapshot) = snapshot {
                        self.apply_identity_change(snapshot);
                    }
                }
                Some(event) = self.events_rx.recv() => self.handle_event(event),
                maybe_datagram = self.egress_rx.recv() => {
                    let Some(datagram) = maybe_datagram else { break };
                    self.handle_datagram(datagram);
                }
                _ = metrics.tick() => report_client(&self.stats, self.outgoing.len() as u64),
            }
        }
    }

    fn apply_identity_change(&mut self, snapshot: Arc<IdentitySnapshot>) {
        self.endpoint.set_default_client_config(new_client_config(
            snapshot.cert.clone(),
            snapshot.key.clone_key(),
        ));
        self.local_pubkey = snapshot.pubkey;
        self.generation = self.generation.wrapping_add(1);
        let evicted = self
            .outgoing
            .drain()
            .filter_map(|(_, entry)| match entry {
                OutgoingEntry::Established(conn) => Some(conn),
                OutgoingEntry::Dialing => None,
            })
            .inspect(|conn| conn.close(CLOSE_IDENTITY_ROTATED, b"IDENTITY_ROTATED"))
            .count() as u64;
        self.stats
            .connection_evicted_identity_rotated
            .fetch_add(evicted, Ordering::Relaxed);
    }

    fn handle_datagram(&mut self, datagram: Datagram) {
        let Datagram {
            peer_pubkey: peer,
            peer_address: addr,
            message,
        } = datagram;
        if peer == self.local_pubkey || self.banlist.is_banned(&peer) {
            return;
        }
        if self.send_outbound(peer, addr, &message) {
            tokio::spawn(
                OutboundDial {
                    endpoint: self.endpoint.clone(),
                    peer,
                    addr,
                    generation: self.generation,
                    trigger: message,
                    events: self.events_tx.clone(),
                    stats: self.stats.clone(),
                }
                .run(),
            );
        }
    }

    fn send_outbound(&mut self, peer: Pubkey, addr: SocketAddr, bytes: &Bytes) -> bool {
        match self.outgoing.entry(peer) {
            Entry::Vacant(slot) => {
                slot.insert(OutgoingEntry::Dialing);
                true
            }
            Entry::Occupied(mut slot) => match slot.get() {
                OutgoingEntry::Dialing => {
                    add(&self.stats.egress_dropped_dial_in_progress);
                    false
                }
                OutgoingEntry::Established(conn) if conn.remote_address() == addr => {
                    match conn.send_datagram(bytes.clone()) {
                        Ok(()) => {
                            add(&self.stats.datagrams_sent);
                            false
                        }
                        Err(SendDatagramError::ConnectionLost(_)) => {
                            add(&self.stats.connection_lost);
                            *slot.get_mut() = OutgoingEntry::Dialing;
                            true
                        }
                        Err(_) => {
                            add(&self.stats.connect_failed);
                            false
                        }
                    }
                }
                OutgoingEntry::Established(_) => {
                    let old = std::mem::replace(slot.get_mut(), OutgoingEntry::Dialing);
                    if let OutgoingEntry::Established(conn) = old {
                        conn.close(CLOSE_PEER_MOVED, b"PEER_MOVED");
                        add(&self.stats.connection_evicted_peer_moved);
                    }
                    true
                }
            },
        }
    }

    fn handle_event(&mut self, event: OutboundEvent) {
        let generation = match &event {
            OutboundEvent::Dialed { generation, .. } | OutboundEvent::Closed { generation, .. } => {
                *generation
            }
        };
        if generation != self.generation {
            if let OutboundEvent::Dialed {
                outcome: Some(conn),
                ..
            } = event
            {
                conn.close(CLOSE_IDENTITY_ROTATED, b"IDENTITY_ROTATED");
                add(&self.stats.connection_evicted_identity_rotated);
            }
            return;
        }

        match event {
            OutboundEvent::Dialed {
                peer,
                outcome: Some(conn),
                ..
            } => match self.outgoing.get_mut(&peer) {
                Some(slot @ OutgoingEntry::Dialing) => {
                    *slot = OutgoingEntry::Established(conn.clone());
                    self.stats
                        .record_connection_count(self.outgoing.len() as u64);
                    self.spawn_close_watcher(peer, conn);
                }
                _ => conn.close(CLOSE_IDENTITY_ROTATED, b"IDENTITY_ROTATED"),
            },
            OutboundEvent::Dialed {
                peer,
                outcome: None,
                ..
            } => {
                if let Entry::Occupied(slot) = self.outgoing.entry(peer)
                    && matches!(slot.get(), OutgoingEntry::Dialing)
                {
                    slot.remove();
                }
            }
            OutboundEvent::Closed {
                peer, stable_id, ..
            } => {
                if let Entry::Occupied(slot) = self.outgoing.entry(peer)
                    && matches!(slot.get(), OutgoingEntry::Established(conn) if conn.stable_id() == stable_id)
                {
                    slot.remove();
                }
            }
        }
    }

    fn spawn_close_watcher(&self, peer: Pubkey, conn: Connection) {
        let events = self.events_tx.clone();
        let generation = self.generation;
        tokio::spawn(async move {
            let stable_id = conn.stable_id();
            conn.closed().await;
            let _ = events
                .send(OutboundEvent::Closed {
                    peer,
                    generation,
                    stable_id,
                })
                .await;
        });
    }
}

struct OutboundDial {
    endpoint: Endpoint,
    peer: Pubkey,
    addr: SocketAddr,
    generation: u64,
    trigger: Bytes,
    events: mpsc::Sender<OutboundEvent>,
    stats: Arc<DatagramStats>,
}

impl OutboundDial {
    async fn run(self) {
        let outcome = match self.dial().await {
            Some(conn) => {
                match conn.send_datagram(self.trigger) {
                    Ok(()) => add(&self.stats.datagrams_sent),
                    Err(SendDatagramError::ConnectionLost(_)) => add(&self.stats.connection_lost),
                    Err(_) => add(&self.stats.connect_failed),
                }
                Some(conn)
            }
            None => None,
        };
        let _ = self
            .events
            .send(OutboundEvent::Dialed {
                peer: self.peer,
                generation: self.generation,
                outcome,
            })
            .await;
    }

    async fn dial(&self) -> Option<Connection> {
        let server_name = socket_addr_to_quic_server_name(self.addr);
        let connecting = self.endpoint.connect(self.addr, &server_name).ok()?;
        let conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(_)) | Err(_) => {
                add(&self.stats.connect_failed);
                return None;
            }
        };
        let Some(remote_pubkey) = get_remote_pubkey(&conn) else {
            conn.close(CLOSE_INVALID_IDENTITY, b"INVALID_IDENTITY");
            add(&self.stats.connect_failed);
            return None;
        };
        if remote_pubkey != self.peer {
            conn.close(CLOSE_INVALID_IDENTITY, b"INVALID_IDENTITY");
            add(&self.stats.connect_failed);
            return None;
        }
        Some(conn)
    }
}

enum InboundEvent {
    Accepted {
        peer: Pubkey,
        conn: Connection,
        generation: u64,
    },
    Closed {
        peer: Pubkey,
        generation: u64,
        stable_id: usize,
    },
}

struct InboundLoop {
    endpoint: Endpoint,
    generation: u64,
    ingress: Sender<Datagram>,
    allowlist: Arc<StakedNodesAllowlist>,
    banlist: Arc<Banlist<Pubkey>>,
    identity_rx: watch::Receiver<Option<Arc<IdentitySnapshot>>>,
    incoming: HashMap<Pubkey, Vec<Connection>>,
    events_tx: mpsc::Sender<InboundEvent>,
    events_rx: mpsc::Receiver<InboundEvent>,
    handshake_global_limiter: TokenBucket,
    stats: Arc<DatagramStats>,
    shutdown: CancellationToken,
}

impl InboundLoop {
    async fn run(mut self) {
        let mut prune = tokio::time::interval(BANLIST_PRUNE_INTERVAL);
        prune.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut metrics = tokio::time::interval(METRICS_INTERVAL);
        metrics.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut identity_closed = false;

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                changed = self.identity_rx.changed(), if !identity_closed => {
                    if changed.is_err() {
                        identity_closed = true;
                        continue;
                    }
                    let snapshot = self.identity_rx.borrow_and_update().clone();
                    if let Some(snapshot) = snapshot {
                        self.apply_identity_change(snapshot);
                    }
                }
                Some(event) = self.events_rx.recv() => self.handle_event(event),
                maybe_incoming = self.endpoint.accept() => {
                    let Some(incoming) = maybe_incoming else { break };
                    self.maybe_accept_connection(incoming);
                }
                _ = prune.tick() => self.banlist.prune(),
                _ = metrics.tick() => report_server(&self.stats, self.incoming_len()),
            }
        }
    }

    fn incoming_len(&self) -> u64 {
        self.incoming.values().map(Vec::len).sum::<usize>() as u64
    }

    fn apply_identity_change(&mut self, snapshot: Arc<IdentitySnapshot>) {
        self.endpoint.set_server_config(Some(new_server_config(
            snapshot.cert.clone(),
            snapshot.key.clone_key(),
        )));
        self.generation = self.generation.wrapping_add(1);
        let evicted = self
            .incoming
            .drain()
            .flat_map(|(_, conns)| conns)
            .inspect(|conn| conn.close(CLOSE_IDENTITY_ROTATED, b"IDENTITY_ROTATED"))
            .count() as u64;
        self.stats
            .connection_evicted_identity_rotated
            .fetch_add(evicted, Ordering::Relaxed);
    }

    fn maybe_accept_connection(&mut self, incoming: Incoming) {
        let remote_addr = incoming.remote_address();
        if remote_addr.is_ipv6() || remote_addr.ip().is_multicast() {
            incoming.ignore();
            return;
        }
        if !remote_addr.ip().is_loopback()
            && self.handshake_global_limiter.consume_tokens(1).is_err()
        {
            add(&self.stats.handshake_rejected_global_limit);
            incoming.ignore();
            return;
        }
        tokio::spawn(
            InboundAccept {
                incoming,
                generation: self.generation,
                events: self.events_tx.clone(),
                stats: self.stats.clone(),
            }
            .run(),
        );
    }

    fn handle_event(&mut self, event: InboundEvent) {
        let generation = match &event {
            InboundEvent::Accepted { generation, .. } | InboundEvent::Closed { generation, .. } => {
                *generation
            }
        };
        if generation != self.generation {
            if let InboundEvent::Accepted { conn, .. } = event {
                conn.close(CLOSE_IDENTITY_ROTATED, b"IDENTITY_ROTATED");
                add(&self.stats.connection_evicted_identity_rotated);
            }
            return;
        }
        match event {
            InboundEvent::Accepted { peer, conn, .. } => self.maybe_admit_inbound(peer, conn),
            InboundEvent::Closed {
                peer, stable_id, ..
            } => self.reap_incoming(peer, stable_id),
        }
    }

    fn maybe_admit_inbound(&mut self, peer: Pubkey, conn: Connection) {
        if self.banlist.is_banned(&peer) {
            conn.close(CLOSE_BANNED, b"BANNED");
            add(&self.stats.handshake_rejected_unauthorized);
            return;
        }
        if !self.allowlist.allow(&peer) {
            conn.close(CLOSE_NOT_ADMITTED, b"NOT_ADMITTED");
            add(&self.stats.handshake_rejected_unauthorized);
            return;
        }
        if self.insert_inbound(peer, conn.clone()).is_err() {
            conn.close(CLOSE_TABLE_FULL, b"TABLE_FULL");
            add(&self.stats.handshake_rejected_overload);
            return;
        }
        self.stats.record_connection_count(self.incoming_len());
        let remote_addr = conn.remote_address();
        tokio::spawn(read_datagram_loop(
            conn,
            peer,
            remote_addr,
            self.generation,
            self.ingress.clone(),
            self.allowlist.clone(),
            self.banlist.clone(),
            self.events_tx.clone(),
            self.stats.clone(),
        ));
    }

    fn insert_inbound(&mut self, peer: Pubkey, conn: Connection) -> Result<(), ()> {
        match self.incoming.entry(peer) {
            Entry::Vacant(slot) => {
                slot.insert(vec![conn]);
                Ok(())
            }
            Entry::Occupied(mut slot) => {
                if slot.get().len() < MAX_INBOUND_CONNECTIONS_PER_PEER {
                    slot.get_mut().push(conn);
                    Ok(())
                } else {
                    Err(())
                }
            }
        }
    }

    fn reap_incoming(&mut self, peer: Pubkey, stable_id: usize) {
        if let Entry::Occupied(mut slot) = self.incoming.entry(peer) {
            slot.get_mut().retain(|conn| conn.stable_id() != stable_id);
            if slot.get().is_empty() {
                slot.remove();
            }
        }
    }
}

struct InboundAccept {
    incoming: Incoming,
    generation: u64,
    events: mpsc::Sender<InboundEvent>,
    stats: Arc<DatagramStats>,
}

impl InboundAccept {
    async fn run(self) {
        let conn = match self.incoming.accept() {
            Ok(connecting) => match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(_)) | Err(_) => {
                    add(&self.stats.connect_failed);
                    return;
                }
            },
            Err(_) => {
                add(&self.stats.connect_failed);
                return;
            }
        };
        let Some(peer) = get_remote_pubkey(&conn) else {
            conn.close(CLOSE_INVALID_IDENTITY, b"INVALID_IDENTITY");
            add(&self.stats.connect_failed);
            return;
        };
        let _ = self
            .events
            .send(InboundEvent::Accepted {
                peer,
                conn,
                generation: self.generation,
            })
            .await;
    }
}

async fn read_datagram_loop(
    connection: Connection,
    peer: Pubkey,
    remote_addr: SocketAddr,
    generation: u64,
    ingress: Sender<Datagram>,
    allowlist: Arc<StakedNodesAllowlist>,
    banlist: Arc<Banlist<Pubkey>>,
    events: mpsc::Sender<InboundEvent>,
    stats: Arc<DatagramStats>,
) {
    let stable_id = connection.stable_id();
    const RATE_LIMIT_WATERMARK: u64 = PEER_RATE_LIMIT_BURST_DOS - PEER_RATE_LIMIT_BURST;
    let rate_limit = TokenBucket::new(
        PEER_RATE_LIMIT_BURST_DOS,
        PEER_RATE_LIMIT_BURST_DOS,
        MAX_DATAGRAMS_PER_SECOND_PER_PEER,
    );
    let mut allowlist_check = tokio::time::interval(ALLOWLIST_CHECK_INTERVAL);
    allowlist_check.tick().await;
    loop {
        tokio::select! {
            result = connection.read_datagram() => {
                match result {
                    Ok(message) => {
                        if banlist.is_banned(&peer) {
                            connection.close(CLOSE_BANNED, b"BANNED");
                            break;
                        }
                        match rate_limit.consume_tokens(1) {
                            Ok(remaining) if remaining > RATE_LIMIT_WATERMARK => {}
                            Ok(_) => {
                                add(&stats.datagram_rate_limited);
                                continue;
                            }
                            Err(_) => {
                                banlist.ban(peer, BAN_DURATION_DOS);
                                connection.close(CLOSE_BANNED, b"BANNED");
                                break;
                            }
                        }
                        match ingress.try_send(Datagram {
                            peer_pubkey: peer,
                            peer_address: remote_addr,
                            message,
                        }) {
                            Ok(()) => add(&stats.datagrams_received),
                            Err(TrySendError::Full(_)) => add(&stats.ingress_dropped_channel_full),
                            Err(TrySendError::Disconnected(_)) => break,
                        }
                    }
                    Err(_) => {
                        add(&stats.connection_lost);
                        break;
                    }
                }
            }
            _ = allowlist_check.tick() => {
                if !allowlist.allow(&peer) {
                    connection.close(CLOSE_NOT_ADMITTED, b"NOT_ADMITTED");
                    add(&stats.connection_evicted_allowlist);
                    break;
                }
            }
        }
    }
    let _ = events
        .send(InboundEvent::Closed {
            peer,
            generation,
            stable_id,
        })
        .await;
}

#[derive(Clone)]
struct NopCongestion;

impl Controller for NopCongestion {
    fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: u64) {}

    fn on_ack(&mut self, _: Instant, _: Instant, _: u64, _: bool, _: &RttEstimator) {}

    fn on_mtu_update(&mut self, _: u16) {}

    fn window(&self) -> u64 {
        NOP_CONGESTION_WINDOW
    }

    fn initial_window(&self) -> u64 {
        NOP_CONGESTION_WINDOW
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl ControllerFactory for NopCongestion {
    fn build(self: Arc<Self>, _: Instant, _: u16) -> Box<dyn Controller> {
        Box::new(NopCongestion)
    }
}

fn new_transport_config() -> TransportConfig {
    let max_idle =
        IdleTimeout::try_from(MAX_IDLE_TIMEOUT).expect("MAX_IDLE_TIMEOUT fits IdleTimeout");
    let mut ack_freq = AckFrequencyConfig::default();
    ack_freq.max_ack_delay(Some(MAX_ACK_DELAY));
    ack_freq.ack_eliciting_threshold(VarInt::from_u32(512));
    ack_freq.reordering_threshold(VarInt::from_u32(0));

    let mut config = TransportConfig::default();
    config
        .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER)
        .initial_mtu(INITIAL_MTU)
        .min_mtu(MIN_MTU)
        .mtu_discovery_config(None)
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .max_idle_timeout(Some(max_idle))
        .ack_frequency_config(Some(ack_freq))
        .congestion_controller_factory(Arc::new(NopCongestion))
        .max_concurrent_bidi_streams(VarInt::from(0u8))
        .max_concurrent_uni_streams(VarInt::from(0u8));
    config
}

fn new_server_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> ServerConfig {
    let mut tls = tls_server_config_builder()
        .with_single_cert(vec![cert], key)
        .expect("rustls accepts votor datagram cert/key");
    tls.alpn_protocols = vec![ALPENGLOW_ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(tls).expect("server TLS config is valid");
    let mut config = ServerConfig::with_crypto(Arc::new(quic));
    config
        .transport_config(Arc::new(new_transport_config()))
        .migration(false);
    config
}

fn new_client_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> ClientConfig {
    let mut tls = tls_client_config_builder()
        .with_client_auth_cert(vec![cert], key)
        .expect("rustls accepts votor datagram cert/key");
    tls.enable_early_data = true;
    tls.alpn_protocols = vec![ALPENGLOW_ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(tls).expect("client TLS config is valid");
    let mut config = ClientConfig::new(Arc::new(quic));
    config.transport_config(Arc::new(new_transport_config()));
    config
}
