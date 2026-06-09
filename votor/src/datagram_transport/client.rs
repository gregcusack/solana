//! Outbound (client) direction: we-dial, send-only.
use {
    crate::datagram_transport::{
        close_codes,
        endpoint::{Datagram, METRICS_INTERVAL},
        error::Error,
        stats::{self, QuicDatagramStats, add, record_error},
        transport::{IdentitySnapshot, new_client_config},
    },
    bytes::Bytes,
    log::{error, info, warn},
    quinn::{Connection, Endpoint, SendDatagramError},
    solana_net_utils::banlist::Banlist,
    solana_pubkey::Pubkey,
    solana_tls_utils::{get_remote_pubkey, socket_addr_to_quic_server_name},
    std::{
        collections::{HashMap, hash_map::Entry},
        net::SocketAddr,
        sync::{Arc, atomic::Ordering},
    },
    tokio::{
        sync::{mpsc, watch},
        time::MissedTickBehavior,
    },
    tokio_util::sync::CancellationToken,
};

/// State of a peer's entry in the outbound table.
pub(crate) enum OutgoingEntry {
    /// A placeholder installed by the egress path before spawning a dial
    /// task. Exactly one dial is ever in flight per peer (later egress sees
    /// `Dialing` and drops).
    Dialing,
    Established(Connection),
}

impl OutboundLoop {
    /// Outbound packet dispatch. Returns `true` if the
    /// caller must spawn a dial task (the trigger datagram is carried into it),
    /// `false` if the datagram was sent or dropped. The 4-case decision over the
    /// `outgoing` entry for `peer`:
    /// * vacant -> initiate new connection (-> true),
    /// * dial in progress -> drop (-> false),
    /// * established to `addr` -> send (-> false; or true if the conn was lost),
    /// * established to a different addr -> evict (`PEER_MOVED`) + redial (-> true).
    fn send_outbound(&mut self, peer: Pubkey, addr: SocketAddr, bytes: &Bytes) -> bool {
        match self.outgoing.entry(peer) {
            Entry::Vacant(slot) => {
                slot.insert(OutgoingEntry::Dialing);
                true
            }
            Entry::Occupied(mut slot) => match slot.get() {
                OutgoingEntry::Dialing => {
                    self.stats
                        .egress_dropped_dial_in_progress
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    false
                }
                OutgoingEntry::Established(conn) if conn.remote_address() == addr => {
                    match conn.send_datagram(bytes.clone()) {
                        Ok(()) => {
                            add(&self.stats.datagrams_sent);
                            false
                        }
                        Err(SendDatagramError::ConnectionLost(_)) => {
                            // Connection is dead; swap to Dialing so the
                            // caller re-dials with this datagram as trigger.
                            *slot.get_mut() = OutgoingEntry::Dialing;
                            true
                        }
                        Err(e) => {
                            record_error(&Error::from(e), &self.stats);
                            false
                        }
                    }
                }
                OutgoingEntry::Established(_) => {
                    // Peer moved - swap the slot to `Dialing`...
                    let old = std::mem::replace(slot.get_mut(), OutgoingEntry::Dialing);
                    // ... and close the displaced connection with PEER_MOVED.
                    if let OutgoingEntry::Established(old_conn) = old {
                        close_codes::PEER_MOVED.close(&old_conn);
                        self.stats
                            .connection_evicted_peer_moved
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        info!("peer {peer} moved; re-dialing at {addr}");
                    }
                    true
                }
            },
        }
    }
}

/// Event reported by a dial task or close-watcher to the outbound control loop.
pub(crate) enum OutboundEvent {
    /// Dial result: `Ok(conn)` on success, `Err(())` if the dial or identity
    /// check failed.
    Dialed {
        peer: Pubkey,
        generation: u64,
        outcome: Result<Connection, ()>,
    },
    /// An established outbound connection closed; the loop reaps its slot.
    Closed {
        peer: Pubkey,
        generation: u64,
        stable_id: usize,
    },
}

/// An outbound dial: connect, validate the server identity, and report the
/// outcome to the control loop. Built by the loop and dispatched via
/// [`Self::spawn`].
pub(crate) struct ClientConnection {
    pub(crate) endpoint: Endpoint,
    pub(crate) peer: Pubkey,
    pub(crate) addr: SocketAddr,
    pub(crate) generation: u64,
    pub(crate) trigger: Bytes,
    pub(crate) events: mpsc::Sender<OutboundEvent>,
    pub(crate) stats: Arc<QuicDatagramStats>,
}

impl ClientConnection {
    async fn run(self) {
        let outcome = match self.dial().await {
            Ok(conn) => {
                match conn.send_datagram(self.trigger) {
                    Ok(()) => add(&self.stats.datagrams_sent),
                    Err(e) => record_error(&Error::from(e), &self.stats),
                }
                Ok(conn)
            }
            Err(e) => {
                error!(
                    "Connection attempt to ({}, {}) failed: {e:?}",
                    self.peer, self.addr
                );
                record_error(&e, &self.stats);
                Err(())
            }
        };
        // Blocking send to make sure we clear the `Dialing` placeholder. If the
        // send fails there is nothing left to do.
        let _ = self
            .events
            .send(OutboundEvent::Dialed {
                peer: self.peer,
                generation: self.generation,
                outcome,
            })
            .await;
    }

    async fn dial(&self) -> Result<Connection, Error> {
        let server_name = socket_addr_to_quic_server_name(self.addr);
        let connection = self.endpoint.connect(self.addr, &server_name)?.await?;
        // Server identity must match the pubkey the caller targeted.
        let attested = get_remote_pubkey(&connection).ok_or(Error::InvalidIdentity(self.addr))?;
        if attested != self.peer {
            close_codes::INVALID_IDENTITY.close(&connection);
            return Err(Error::InvalidIdentity(self.addr));
        }
        Ok(connection)
    }
}

/// Outbound control loop: client egress (we-dial, send-only). Owns the outgoing
/// table and the dial-task event channel.
pub(crate) struct OutboundLoop {
    pub(crate) endpoint: Endpoint,
    pub(crate) local_pubkey: Pubkey,
    /// Identity-rotation counter, local to this loop.
    pub(crate) generation: u64,
    pub(crate) egress_rx: mpsc::Receiver<Datagram>,
    pub(crate) banlist: Arc<Banlist<Pubkey>>,
    pub(crate) identity_rx: watch::Receiver<Option<Arc<IdentitySnapshot>>>,
    /// Outbound table (per-peer send-only connection state).
    pub(crate) outgoing: HashMap<Pubkey, OutgoingEntry>,
    /// Cloned into every dial task so it can report its [`OutboundEvent`].
    pub(crate) events_tx: mpsc::Sender<OutboundEvent>,
    pub(crate) events_rx: mpsc::Receiver<OutboundEvent>,
    pub(crate) shutdown: CancellationToken,
    pub(crate) stats: Arc<QuicDatagramStats>,
    /// Held so an identity rotation can rebuild the client TLS config.
    pub(crate) alpn: &'static [u8],
}

impl OutboundLoop {
    pub(crate) async fn run(mut self) {
        let mut metrics = tokio::time::interval(METRICS_INTERVAL);
        metrics.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // The identity arm tolerates the `KeyUpdater` sender being dropped (some
        // local-cluster tests drop it); once closed we stop polling that arm.
        let mut id_closed = false;
        loop {
            tokio::select! {
                biased;
                // Explicit shutdown. Fires only on an explicit `cancel()`;
                // dropping the public handle's token clone never cancels it.
                _ = self.shutdown.cancelled() => break,
                changed = self.identity_rx.changed(), if !id_closed => {
                    if changed.is_err() {
                        warn!("identity rotation channel closed; outbound loop running without rotation support");
                        id_closed = true;
                        continue;
                    }
                    let snap = self.identity_rx.borrow_and_update().clone();
                    if let Some(snap) = snap {
                        self.apply_identity_change(snap);
                    }
                }
                maybe_datagram = self.egress_rx.recv() => {
                    let Some(datagram) = maybe_datagram else { break };
                    self.handle_datagram(datagram);
                }
                // Dial outcomes. `recv()` never yields `None` - the loop holds
                // an `events_tx`.
                Some(event) = self.events_rx.recv() => self.handle_event(event),
                _ = metrics.tick() => stats::report_client(&self.stats, self.outgoing.len() as u64),
            }
        }
    }

    /// Rebuild the client TLS config against the new identity, swap it into the
    /// quinn endpoint, evict the outbound table so peers are re-dialed, and
    /// adopt the new pubkey.
    fn apply_identity_change(&mut self, snap: Arc<IdentitySnapshot>) {
        let client_config = new_client_config(snap.cert.clone(), snap.key.clone_key(), self.alpn);
        self.local_pubkey = snap.pubkey;
        self.endpoint.set_default_client_config(client_config);
        // Bump first so any in-flight dial that completes after this point is
        // dropped at the event boundary (its event carries the old generation).
        self.generation = self.generation.wrapping_add(1);
        let evicted = self
            .outgoing
            .drain()
            .map(|(_, entry)| {
                if let OutgoingEntry::Established(conn) = entry {
                    close_codes::IDENTITY_ROTATED.close(&conn);
                }
            })
            .count() as u64;
        self.stats
            .connection_evicted_identity_rotated
            .fetch_add(evicted, Ordering::Relaxed);
        info!(
            "outbound identity rotated to {} ({} connection(s) evicted)",
            snap.pubkey, evicted
        );
    }

    fn handle_datagram(&mut self, datagram: Datagram) {
        let Datagram {
            peer_pubkey: peer,
            peer_address: addr,
            message: bytes,
        } = datagram;
        debug_assert_ne!(self.local_pubkey, peer, "egress to self is a caller bug");
        if self.banlist.is_banned(&peer) {
            return;
        }

        if !self.send_outbound(peer, addr, &bytes) {
            return;
        }

        tokio::spawn(
            ClientConnection {
                endpoint: self.endpoint.clone(),
                peer,
                addr,
                generation: self.generation,
                trigger: bytes,
                events: self.events_tx.clone(),
                stats: self.stats.clone(),
            }
            .run(),
        );
    }

    /// Apply a dial result or a connection-close notification.
    fn handle_event(&mut self, event: OutboundEvent) {
        let (peer, generation) = match &event {
            OutboundEvent::Dialed {
                peer, generation, ..
            }
            | OutboundEvent::Closed {
                peer, generation, ..
            } => (*peer, *generation),
        };
        if generation != self.generation {
            if let OutboundEvent::Dialed {
                outcome: Ok(conn), ..
            } = event
            {
                close_codes::IDENTITY_ROTATED.close(&conn);
                self.stats
                    .connection_evicted_identity_rotated
                    .fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        match event {
            OutboundEvent::Dialed {
                outcome: Ok(conn), ..
            } => match self.outgoing.get_mut(&peer) {
                Some(slot @ OutgoingEntry::Dialing) => {
                    *slot = OutgoingEntry::Established(conn.clone());
                    self.stats
                        .record_connection_count(self.outgoing.len() as u64);
                    self.spawn_close_watcher(peer, conn);
                }
                _ => {
                    close_codes::IDENTITY_ROTATED.close(&conn);
                    record_error(&Error::IdentityRotated(peer), &self.stats);
                }
            },
            OutboundEvent::Dialed {
                outcome: Err(()), ..
            } => {
                if let Entry::Occupied(slot) = self.outgoing.entry(peer)
                    && matches!(slot.get(), OutgoingEntry::Dialing)
                {
                    slot.remove();
                }
            }
            // Reap only if the closed connection is still the one we hold; a
            // re-dial may have already replaced it.
            OutboundEvent::Closed { stable_id, .. } => {
                if let Entry::Occupied(slot) = self.outgoing.entry(peer)
                    && matches!(slot.get(), OutgoingEntry::Established(c) if c.stable_id() == stable_id)
                {
                    slot.remove();
                }
            }
        }
    }

    /// Watch an established connection and report [`OutboundEvent::Closed`] when
    /// it ends so the loop can reap the slot.
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
