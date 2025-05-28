use {
    solana_streamer::packet::PacketRef,
    crate::protocol::Protocol,
    crate::ping_pong::Ping,
    solana_signature::Signature,
    std::{
        collections::HashMap,
        sync::{LazyLock, Mutex},
        time::Instant,
    },
};

pub static PING_RTT_TRACKER: LazyLock<Mutex<PingRttTracker>> = LazyLock::new(|| {
    Mutex::new(PingRttTracker::default())
});

#[derive(Default)]
pub struct PingRttTracker {
    pending: HashMap<Signature, Instant>, // 👈 keyed by sender pubkey
}

impl PingRttTracker {
    pub fn record_create_ping(&mut self, sig: Signature) {
        self.pending.insert(sig, Instant::now());
    }

    pub fn record_send(&mut self, ping: &Ping<32>) {
        if let Some(start) = self.pending.remove(&ping.signature) {
            let elapsed_us = start.elapsed().as_micros();
            // info!("greg: gossip_diff. pk: {:?}, rtt: {:?}", ping.signature, elapsed_us);
            datapoint_info!(
                "gossip_ping",
                ("sig", format!("{:?}", ping.signature), String),
                ("diff_us", elapsed_us, i64)
            );
        }        
    }
}

// ✅ Call this when sending a ping packet
// pub fn gossip_ping_observer(packet: &Packet) {
//     if let Some(data) = packet.data(..) {
//         if let Ok(Protocol::PingMessage(ping)) = bincode::deserialize(data) {
//             let now = Instant::now();
//             PING_RTT_TRACKER.lock().unwrap().record_send(&ping, now);
//         }
//     }
// }

pub fn gossip_ping_observer(packet: PacketRef<'_>) {
    if let Some(data) = packet.data(..) {
        if let Ok(Protocol::PingMessage(ping)) = bincode::deserialize(data) {
            PING_RTT_TRACKER.lock().unwrap().record_send(&ping);
        }
    }
}

