//! Inbound (server) direction: we-accept, receive-only.

use {
    crate::datagram_transport::{
        ALLOWLIST_CHECK_INTERVAL, BAN_DURATION_DOS, MAX_DATAGRAMS_PER_SECOND_PER_PEER,
        MAX_INBOUND_CONNECTIONS_PER_PEER, PEER_RATE_LIMIT_BURST, PEER_RATE_LIMIT_BURST_DOS,
        allowlist::Allowlist,
        close_codes,
        endpoint::{Datagram, METRICS_INTERVAL},
        error::Error,
        stats::{self, QuicDatagramStats, add, record_error},
        transport::{IdentitySnapshot, new_server_config},
    },
    crossbeam_channel::{Sender, TrySendError},
    log::{debug, info, warn},
    quinn::{Connection, Endpoint, Incoming},
    solana_net_utils::{banlist::Banlist, token_bucket::TokenBucket},
    solana_pubkey::Pubkey,
    solana_tls_utils::get_remote_pubkey,
    std::{
        collections::{HashMap, hash_map::Entry},
        net::SocketAddr,
        sync::{Arc, atomic::Ordering},
        time::Duration,
    },
    tokio::{
        sync::{mpsc, watch},
        time::MissedTickBehavior,
    },
    tokio_util::sync::CancellationToken,
};

/// Interval of pruning for banlist entries that are no longer valid.
const BANLIST_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Event reported by an accept or read task to the inbound control loop.
pub(crate) enum InboundEvent {
    /// A TLS handshake completed and yielded an authenticated peer.
    Accepted {
        peer: Pubkey,
        conn: Connection,
        generation: u64,
    },
    /// An inbound (we-accepted) connection ended. The read loop reports this
    /// so the control loop can reap the table slot.
    Closed {
        peer: Pubkey,
        generation: u64,
        stable_id: usize,
    },
}

impl InboundLoop {
    /// Live inbound connections (each pubkey may hold several). Sampled for the
    /// peak-occupancy high-water mark.
    fn incoming_len(&self) -> u64 {
        self.incoming.values().map(Vec::len).sum::<usize>() as u64
    }

    /// Install a freshly-accepted receive-only connection for `peer`. We keep
    /// up to [`MAX_INBOUND_CONNECTIONS_PER_PEER`] connections per pubkey so a
    /// same-identity hot-spare can coexist with the original without a
    /// handover. Returns:
    /// - `Ok(())` if the connection took a slot (a fresh pubkey, or an
    ///   additional connection for a pubkey already present).
    /// - `Err(())` if this pubkey already holds the per-peer maximum; caller
    ///   must close `conn` with `TABLE_FULL`. This should be rare in normal
    ///   operation. The count of distinct inbound pubkeys is not checked here:
    ///   admission control (allowlist) already bounds it to the staked set.
    fn insert_inbound(&mut self, peer: Pubkey, conn: Connection) -> Result<(), ()> {
        match self.incoming.entry(peer) {
            Entry::Vacant(slot) => {
                slot.insert(vec![conn]);
                Ok(())
            }
            Entry::Occupied(mut slot) => {
                let conns = slot.get_mut();
                if conns.len() < MAX_INBOUND_CONNECTIONS_PER_PEER {
                    conns.push(conn);
                    Ok(())
                } else {
                    Err(())
                }
            }
        }
    }

    /// Remove the connection with the given `stable_id` from `peer`'s inbound
    /// set when its read loop exits; drop the map entry once its last
    /// connection is gone. Called by the read loop on exit. No-op if the
    /// connection was already removed (e.g. by an identity rotation).
    fn reap_incoming(&mut self, peer: &Pubkey, stable_id: usize) {
        if let Entry::Occupied(mut slot) = self.incoming.entry(*peer) {
            let conns = slot.get_mut();
            conns.retain(|c| c.stable_id() != stable_id);
            if conns.is_empty() {
                slot.remove();
            }
        }
    }
}

/// An inbound accept: run the handshake and hand the connection (plus its
/// attested pubkey) to the control loop for admission.
pub(crate) struct ServerConnection {
    pub(crate) incoming: Incoming,
    pub(crate) generation: u64,
    pub(crate) events: mpsc::Sender<InboundEvent>,
    pub(crate) stats: Arc<QuicDatagramStats>,
}

impl ServerConnection {
    async fn run(self) {
        let remote_addr = self.incoming.remote_address();
        let conn = match async { self.incoming.accept()?.await }.await {
            Ok(conn) => conn,
            Err(e) => {
                record_error(&Error::from(e), &self.stats);
                return;
            }
        };
        let Some(peer) = get_remote_pubkey(&conn) else {
            close_codes::INVALID_IDENTITY.close(&conn);
            record_error(&Error::InvalidIdentity(remote_addr), &self.stats);
            return;
        };
        // Hand the connection to the loop for admission. The loop is the sole
        // consumer of this channel and never sends into it, so awaiting here
        // cannot deadlock - a momentarily-full channel just parks this task
        // until the loop drains. If the send fails the loop is gone (shutdown)
        // and dropping `conn` closes it.
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

/// Drive the per-connection read loop for an incoming connection.
/// Returns when the connection closes. On exit it reliably reports
/// [`InboundEvent::Closed`] so the control loop can reap the table entry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_datagram_loop(
    connection: Connection,
    peer: Pubkey,
    remote_addr: SocketAddr,
    generation: u64,
    ingress: Sender<Datagram>,
    allowlist: Arc<dyn Allowlist>,
    banlist: Arc<Banlist<Pubkey>>,
    events: mpsc::Sender<InboundEvent>,
    stats: Arc<QuicDatagramStats>,
) {
    let stable_id = connection.stable_id();
    // Per-connection rate limiter. Any datagram arriving with the bucket
    // below RATE_LIMIT_WATERMARK is dropped, since honest peers
    // legitimately burst above the refill rate during catch-up.
    // Any packet arriving when bucket is empty is *closed*.
    const RATE_LIMIT_WATERMARK: u64 = PEER_RATE_LIMIT_BURST_DOS - PEER_RATE_LIMIT_BURST;
    let rate_limit = TokenBucket::new(
        PEER_RATE_LIMIT_BURST_DOS,
        PEER_RATE_LIMIT_BURST_DOS,
        MAX_DATAGRAMS_PER_SECOND_PER_PEER,
    );
    let mut allowlist_check = tokio::time::interval(ALLOWLIST_CHECK_INTERVAL);
    allowlist_check.tick().await; // skip the immediate first fire
    loop {
        tokio::select! {
            result = connection.read_datagram() => {
                match result {
                    Ok(bytes) => {
                        // Banlist check happens AFTER the read so a ban that
                        // lands while we're awaiting can't let a follow-up
                        // datagram leak through to ingress.
                        if banlist.is_banned(&peer) {
                            close_codes::BANNED.close(&connection);
                            break;
                        }
                        match rate_limit.consume_tokens(1) {
                            // green corridor - sender is behaving
                            Ok(remaining) if remaining > RATE_LIMIT_WATERMARK => {}
                            // red corridor - sender is bursting above normal
                            Ok(_) => {
                                drop(bytes);
                                stats.datagram_rate_limited.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            // we are under attack - kick the sender.
                            Err(_) => {
                                drop(bytes);
                                banlist.ban(peer, BAN_DURATION_DOS);
                                close_codes::BANNED.close(&connection);
                                break;
                            }
                        }

                        match ingress.try_send(Datagram {
                            peer_pubkey: peer,
                            peer_address: remote_addr,
                            message: bytes,
                        }) {
                            Ok(()) => {
                                stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Full(_)) => {
                                stats
                                    .datagram_ingress_dropped_channel_full
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                debug!("ingress disconnected; reader for {peer} exiting");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // The peer (or we) closed this inbound, or it timed
                        // out. Record and exit; the control loop reaps the
                        // table slot from the `Closed` event below.
                        record_error(&Error::from(e), &stats);
                        break;
                    }
                }
            }
            _ = allowlist_check.tick() => {
                if !allowlist.allow(&peer) {
                    close_codes::NOT_ADMITTED.close(&connection);
                    stats.connection_evicted_allowlist.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    // Send the notification to control that this connection died.
    let _ = events
        .send(InboundEvent::Closed {
            peer,
            generation,
            stable_id,
        })
        .await;
}

/// Inbound control loop: server accept (we-accept, receive-only). Owns the
/// incoming table, the handshake DoS gate, admission, banlist eviction, and
/// read-loop reaping; spawned by [`crate::datagram_transport::endpoint::QuicDatagramEndpoint::new`].
pub(crate) struct InboundLoop {
    pub(crate) endpoint: Endpoint,
    /// Identity-rotation counter
    pub(crate) generation: u64,
    pub(crate) ingress: Sender<Datagram>,
    pub(crate) banlist: Arc<Banlist<Pubkey>>,
    /// Policy for which peers may occupy a slot. Consulted by the admission
    /// gate and handed to each read loop for its periodic re-check.
    pub(crate) allowlist: Arc<dyn Allowlist>,
    pub(crate) identity_rx: watch::Receiver<Option<Arc<IdentitySnapshot>>>,
    /// Inbound table (per-peer accepted receive-only connections), owned solely
    /// by this loop.
    pub(crate) incoming: HashMap<Pubkey, Vec<Connection>>,
    /// Cloned into every accept / read task so it can report its [`InboundEvent`].
    pub(crate) events_tx: mpsc::Sender<InboundEvent>,
    pub(crate) events_rx: mpsc::Receiver<InboundEvent>,
    /// Global cap on inbound handshake rate across all source IPs.
    pub(crate) handshake_global_limiter: TokenBucket,
    pub(crate) stats: Arc<QuicDatagramStats>,
    /// Held so an identity rotation can rebuild the server TLS config.
    pub(crate) alpn: &'static [u8],
    pub(crate) shutdown: CancellationToken,
}

impl InboundLoop {
    pub(crate) async fn run(mut self) {
        let mut prune = tokio::time::interval(BANLIST_PRUNE_INTERVAL);
        prune.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut metrics = tokio::time::interval(METRICS_INTERVAL);
        metrics.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // TODO: this flag is a workaround for some local-cluster tests that are a
        // nightmare to refactor. But they really should be.
        let mut id_closed = false;
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                changed = self.identity_rx.changed(), if !id_closed => {
                    if changed.is_err() {
                        warn!("identity rotation channel closed; inbound loop running without rotation support");
                        id_closed = true;
                        continue;
                    }
                    let snap = self.identity_rx.borrow_and_update().clone();
                    if let Some(snap) = snap {
                        self.apply_identity_change(snap);
                    }
                }
                // Lifecycle results keep the table coherent; drained above
                // accept so a flood of inbounds can't starve the reaping of
                // dead connections. `recv()` never yields `None` - the loop
                // holds an `events_tx`.
                Some(event) = self.events_rx.recv() => self.handle_event(event),
                maybe_incoming = self.endpoint.accept() => {
                    let Some(incoming) = maybe_incoming else { break };
                    self.maybe_accept_connection(incoming);
                }
                // when idle we can take care of bookkeeping. If these are delayed
                // it is usually not a problem.
                _ = prune.tick() => self.banlist.prune(),
                _ = metrics.tick() => stats::report_server(&self.stats, self.incoming_len()),
            }
        }
    }

    /// Rebuild the server TLS config against the new identity, swap it into the
    /// quinn endpoint, and evict the inbound table so peers re-handshake.
    fn apply_identity_change(&mut self, snap: Arc<IdentitySnapshot>) {
        let server_config = new_server_config(snap.cert.clone(), snap.key.clone_key(), self.alpn);
        self.endpoint.set_server_config(Some(server_config));
        // Bump first so any in-flight accept that completes after this point is
        // dropped at the event boundary (its event carries the old generation).
        self.generation = self.generation.wrapping_add(1);
        let evicted = self
            .incoming
            .drain()
            .flat_map(|(_, conns)| conns)
            .inspect(|conn| close_codes::IDENTITY_ROTATED.close(conn))
            .count() as u64;
        self.stats
            .connection_evicted_identity_rotated
            .fetch_add(evicted, Ordering::Relaxed);
        info!(
            "inbound identity rotated to {} ({} connection(s) evicted)",
            snap.pubkey, evicted
        );
    }

    /// Apply a connection-lifecycle result.
    fn handle_event(&mut self, event: InboundEvent) {
        let generation = match &event {
            InboundEvent::Accepted { generation, .. } | InboundEvent::Closed { generation, .. } => {
                *generation
            }
        };
        if generation != self.generation {
            // Close any live connection carried by a stale-generation event so a
            // connection authenticated under a now-rotated identity is not leaked.
            if let InboundEvent::Accepted { conn, .. } = event {
                close_codes::IDENTITY_ROTATED.close(&conn);
                self.stats
                    .connection_evicted_identity_rotated
                    .fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        match event {
            InboundEvent::Accepted { peer, conn, .. } => self.maybe_admit_inbound(peer, conn),
            InboundEvent::Closed {
                peer, stable_id, ..
            } => self.reap_incoming(&peer, stable_id),
        }
    }

    /// Performs the non-expensive checks to handle incoming connections.
    /// Then spawns the statemachine to handle the handshake and serve connection.
    fn maybe_accept_connection(&mut self, incoming: Incoming) {
        let remote_addr = incoming.remote_address();
        if remote_addr.is_ipv6() || remote_addr.ip().is_multicast() {
            incoming.ignore();
            return;
        }
        // TODO: add Retry challenge here.
        let ip = remote_addr.ip();
        // Apply rate-limit before spending TLS CPU.
        // Loopback is exempt (for local-cluster / tests).
        if !ip.is_loopback() && self.handshake_global_limiter.consume_tokens(1).is_err() {
            add(&self.stats.handshake_rejected_global_limit);
            incoming.ignore();
            return;
        }
        tokio::spawn(
            ServerConnection {
                incoming,
                generation: self.generation,
                events: self.events_tx.clone(),
                stats: self.stats.clone(),
            }
            .run(),
        );
    }

    /// Admission checks for a freshly handshaked inbound (we-accepted,
    /// receive-only) connection. The split-direction model has no lex-pubkey
    /// tiebreaker: we accept an inbound from any admitted peer regardless of
    /// pubkey ordering, and install it into the receive-only `incoming` map.
    fn maybe_admit_inbound(&mut self, peer: Pubkey, conn: Connection) {
        if self.banlist.is_banned(&peer) {
            close_codes::BANNED.close(&conn);
            record_error(&Error::Banned(peer), &self.stats);
            return;
        }
        if !self.allowlist.allow(&peer) {
            close_codes::NOT_ADMITTED.close(&conn);
            record_error(&Error::NotAdmitted(peer), &self.stats);
            return;
        }
        let remote_addr = conn.remote_address();
        if self.insert_inbound(peer, conn.clone()).is_err() {
            close_codes::TABLE_FULL.close(&conn);
            record_error(&Error::TableFull, &self.stats);
            return;
        }
        self.stats.record_connection_count(self.incoming_len());
        // The read loop reports [`InboundEvent::Closed`] when it exits so this
        // loop can reap the table slot.
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
}

#[cfg(test)]
mod tests {
    use {
        crate::datagram_transport::{
            MAX_DATAGRAMS_PER_SECOND_PER_PEER, PEER_RATE_LIMIT_BURST,
            allowlist::{AllowAll, StakedNodesAllowlist},
            endpoint::Datagram,
            testutils::{
                drain_matching, make_runtime, recv_until, send_until_received, spawn_node,
            },
        },
        bytes::Bytes,
        solana_keypair::{Keypair, Signer},
        std::{collections::HashMap, sync::Arc, time::Duration},
    };

    #[test]
    fn staked_peer_is_admitted_unstaked_is_rejected() {
        let rt = make_runtime();

        let server_kp = Keypair::new();
        let a_kp = Keypair::new();
        let a_pk = a_kp.pubkey();
        let admit_map: HashMap<_, _> = std::iter::once((a_pk, 100u64)).collect();
        let server = spawn_node(
            &rt,
            Arc::new(StakedNodesAllowlist::new(admit_map)),
            server_kp,
        );

        // Client A - admitted by the allowlist.
        let client_a = spawn_node(&rt, Arc::new(AllowAll), a_kp);
        // Client B - not admitted by the allowlist.
        let client_b = spawn_node(&rt, Arc::new(AllowAll), Keypair::new());

        let payload_a = Bytes::from_static(b"hello-from-A");
        send_until_received(
            &rt,
            &client_a.endpoint,
            server.pubkey(),
            server.addr,
            payload_a.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.peer_pubkey == a_pk && d.message == payload_a).then_some(()),
            "server never received payload from admitted peer A",
        );
        // send_until_received may have left retry duplicates of payload_a
        // in the channel; drain them before asserting B's rejection.
        drain_matching(&server.ingress_rx, Duration::from_millis(200), |d| {
            d.message == payload_a
        });

        let payload_b = Bytes::from_static(b"hello-from-B");
        rt.block_on(async {
            client_b
                .endpoint
                .egress
                .send(Datagram {
                    peer_pubkey: server.pubkey(),
                    peer_address: server.addr,
                    message: payload_b.clone(),
                })
                .await
                .expect("egress send B");
        });

        // Server must close the handshake before any datagram from B is queued.
        let bad = server.ingress_rx.recv_timeout(Duration::from_millis(800));
        assert!(
            bad.is_err(),
            "unstaked peer B's datagram should not reach server ingress, got {bad:?}"
        );
    }

    #[test]
    fn ban_evicts_existing_and_blocks_rehandshake() {
        let rt = make_runtime();
        let server = spawn_node(&rt, Arc::new(AllowAll), Keypair::new());
        // No lex tiebreaker in the split-direction model: the client dials, the
        // server accepts a receive-only inbound. Any distinct keypair works.
        let client = spawn_node(&rt, Arc::new(AllowAll), Keypair::new());

        // Establish a connection by driving send-until-receive: the trigger
        // packet is dropped; the retry through the now-Established slot lands.
        let probe = Bytes::from_static(b"probe");
        send_until_received(
            &rt,
            &client.endpoint,
            server.pubkey(),
            server.addr,
            probe.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == probe).then_some(()),
            "first datagram never arrived",
        );
        drain_matching(&server.ingress_rx, Duration::from_millis(200), |d| {
            d.message == probe
        });

        // Ban the client at the server side. Eviction task should close the
        // server-side connection; client's read loop sees ConnectionClosed and
        // exits, dropping its cache entry on the way out.
        server.banlist.ban(client.pubkey(), Duration::from_secs(5));

        // Best-effort wait for eviction to flush. The eviction task is async; on
        // a quiet system it observes the channel within a few ms.
        std::thread::sleep(Duration::from_millis(200));

        // Now have the client send again. The send path dials a new connection
        // (server-side cache no longer holds the old one); but the server is
        // banning this pubkey, so handshake closes with BANNED and no datagram
        // ever reaches ingress.
        let again = Bytes::from_static(b"after-ban");
        rt.block_on(async {
            client
                .endpoint
                .egress
                .send(Datagram {
                    peer_pubkey: server.pubkey(),
                    peer_address: server.addr,
                    message: again.clone(),
                })
                .await
                .unwrap();
        });

        let bad = server.ingress_rx.recv_timeout(Duration::from_millis(1500));
        assert!(
            bad.is_err(),
            "banned client must not deliver datagrams to server; got {bad:?}"
        );
    }

    #[test]
    /// Two client instances sharing one identity (hot-spare promotion) each
    /// dial the server. In the split-direction model with no handover, both
    /// inbound connections *coexist* (capped at
    /// `MAX_INBOUND_CONNECTIONS_PER_PEER`): neither displaces the other, and
    /// nobody is soft-banned. Both clients deliver, and the first keeps
    /// delivering after the second connects.
    fn two_connections_same_identity_coexist() {
        let rt = make_runtime();
        let server = spawn_node(&rt, Arc::new(AllowAll), Keypair::new());

        let shared = Keypair::new();
        let server_pk = server.pubkey();
        let c1 = spawn_node(&rt, Arc::new(AllowAll), shared.insecure_clone());
        let c2 = spawn_node(&rt, Arc::new(AllowAll), shared.insecure_clone());

        // C1 establishes its inbound to the server and delivers p1.
        let p1 = Bytes::from_static(b"from-c1");
        send_until_received(
            &rt,
            &c1.endpoint,
            server_pk,
            server.addr,
            p1.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == p1).then_some(()),
            "server did not receive c1's probe",
        );
        drain_matching(&server.ingress_rx, Duration::from_millis(200), |d| {
            d.message == p1
        });

        // C2 (same identity) brings up a *separate* inbound and delivers p2.
        let p2 = Bytes::from_static(b"from-c2");
        send_until_received(
            &rt,
            &c2.endpoint,
            server_pk,
            server.addr,
            p2.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == p2).then_some(()),
            "server did not receive c2's probe",
        );
        drain_matching(&server.ingress_rx, Duration::from_millis(200), |d| {
            d.message == p2
        });

        // No handover means no soft-ban on either client's outgoing side.
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !c1.banlist.is_banned(&server_pk),
            "no handover: c1 must not soft-ban the server"
        );
        assert!(
            !c2.banlist.is_banned(&server_pk),
            "no handover: c2 must not soft-ban the server"
        );

        // C1's connection survived C2 connecting (not displaced): it can still
        // deliver on the same outbound.
        let p3 = Bytes::from_static(b"from-c1-again");
        send_until_received(
            &rt,
            &c1.endpoint,
            server_pk,
            server.addr,
            p3.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == p3).then_some(()),
            "c1 must still deliver after c2's same-identity connection",
        );
    }

    #[test]
    /// Per-connection receive token bucket. A burst beyond
    /// `BURST_DATAGRAMS_PER_SECOND_PER_PEER` is *dropped* silently - the
    /// bucket itself is the throttle. The connection stays alive and the
    /// peer is NOT banned (consensus traffic legitimately bursts above the
    /// refill rate during catch-up).
    fn burst_exceeding_rate_limit_drops_excess_without_banning() {
        let rt = make_runtime();
        let server = spawn_node(&rt, Arc::new(AllowAll), Keypair::new());
        let client = spawn_node(&rt, Arc::new(AllowAll), Keypair::new());

        // Establish the connection: retry the probe until one lands (first one
        // triggers the dial, gets dropped; followers ride the Established slot).
        let probe = Bytes::from_static(b"probe");
        send_until_received(
            &rt,
            &client.endpoint,
            server.pubkey(),
            server.addr,
            probe.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == probe).then_some(()),
            "first datagram never arrived",
        );
        // Drain probe retry duplicates so they don't inflate the post-burst
        // delivery count below.
        drain_matching(&server.ingress_rx, Duration::from_millis(200), |d| {
            d.message == probe
        });

        // Blast a burst far in excess of the bucket capacity. Probe retries
        // have already consumed some tokens; the (capacity)-th additional
        // datagram trips the limiter.
        let burst = (PEER_RATE_LIMIT_BURST as usize) * 4;
        rt.block_on(async {
            for i in 0..burst {
                let payload = Bytes::from(format!("burst-{i:04}").into_bytes());
                client
                    .endpoint
                    .egress
                    .send(Datagram {
                        peer_pubkey: server.pubkey(),
                        peer_address: server.addr,
                        message: payload,
                    })
                    .await
                    .unwrap();
            }
        });

        // Let the receiver chew through whatever fits in the bucket.
        std::thread::sleep(Duration::from_millis(500));

        // The peer must NOT have been banned - drop-only semantics.
        assert!(
            !server.banlist.is_banned(&client.pubkey()),
            "client pubkey should NOT be banned by RX rate limit (drop-only semantics)"
        );

        // Drain whatever made it through ingress. The bucket caps how many
        // post-probe datagrams can be delivered within the first refill window.
        let mut delivered = 0usize;
        while server
            .ingress_rx
            .recv_timeout(Duration::from_millis(50))
            .is_ok()
        {
            delivered = delivered.saturating_add(1);
        }
        let cap = PEER_RATE_LIMIT_BURST as usize;
        assert!(
            delivered <= cap + 2,
            "delivered {delivered} datagrams post-probe, exceeds bucket capacity {cap} + slop"
        );

        // After waiting long enough for the bucket to refill, the sender should
        // be able to deliver fresh datagrams on the SAME connection (proves the
        // connection wasn't torn down). The green corridor is the top
        // `PEER_RATE_LIMIT_BURST` tokens of a `PEER_RATE_LIMIT_BURST_DOS`-capacity
        // bucket, so after a `burst`-sized blast the bucket has to climb back
        // above the watermark before it delivers again - roughly
        // `(burst - BURST) / refill_rate` seconds. Wait that long, plus margin.
        let recover_secs = ((burst as u64).saturating_sub(PEER_RATE_LIMIT_BURST) as f64
            / MAX_DATAGRAMS_PER_SECOND_PER_PEER)
            .ceil() as u64;
        std::thread::sleep(Duration::from_secs(recover_secs.saturating_add(2)));
        let resume = Bytes::from_static(b"after-refill");
        rt.block_on(async {
            client
                .endpoint
                .egress
                .send(Datagram {
                    peer_pubkey: server.pubkey(),
                    peer_address: server.addr,
                    message: resume.clone(),
                })
                .await
                .unwrap();
        });
        recv_until(
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == resume).then_some(()),
            "post-refill datagram never arrived - connection may have been torn down",
        );
    }
}
