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

pub static PONG_RTT_TRACKER: LazyLock<Mutex<PongRttTracker>> = LazyLock::new(|| {
    Mutex::new(PongRttTracker::default())
});

#[derive(Default)]
pub struct PongRttTracker {
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

impl PongRttTracker {
    pub fn record_rx_pong(&mut self, sig: Signature) {
        self.pending.insert(sig, Instant::now());
    }

    pub fn record_add_pong(&mut self, sig: Signature) {
        if let Some(start) = self.pending.remove(&sig) {
            let elapsed_us = start.elapsed().as_micros();
            datapoint_info!(
                "gossip_pong",
                ("sig", format!("{:?}", sig), String),
                ("diff_us", elapsed_us, i64)
            );
        }
    }
}


pub fn gossip_ping_observer(packet: PacketRef<'_>) {
    if let Some(data) = packet.data(..) {
        if let Ok(Protocol::PingMessage(ping)) = bincode::deserialize(data) {
            PING_RTT_TRACKER.lock().unwrap().record_send(&ping);
        }
    }
}

