use {
    crate::repair::{quic_endpoint::RemoteRequest, serve_repair::ServeRepair},
    bytes::Bytes,
    crossbeam_channel::{bounded, unbounded, Receiver, Sender},
    solana_net_utils::SocketAddrSpace,
    solana_perf::{packet::PacketBatch, recycler::Recycler},
    solana_streamer::{
        evicting_sender::EvictingSender,
        streamer::{self, StreamerReceiveStats},
    },
    std::{
        net::{SocketAddr, UdpSocket},
        sync::{atomic::AtomicBool, Arc},
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    tokio::sync::mpsc::Sender as AsyncSender,
};

const REPAIR_REQUEST_CHANNEL_CAPACITY: usize = 1 << 14;

pub struct ServeRepairService {
    thread_hdls: Vec<JoinHandle<()>>,
}

#[derive(Default)]
struct AdaptRepairRequestStats {
    dropped_packets_total: usize,
    dropped_batches_total: usize,
    max_packets_channel_len: usize,
    max_requests_channel_len: usize,
}

impl AdaptRepairRequestStats {
    fn report_and_reset(&mut self) {
        datapoint_info!(
            "adapt-repair-request-packets",
            ("dropped_packets_total", self.dropped_packets_total as i64, i64),
            ("dropped_batches_total", self.dropped_batches_total as i64, i64),
            (
                "max_packets_channel_len",
                self.max_packets_channel_len as i64,
                i64
            ),
            (
                "max_requests_channel_len",
                self.max_requests_channel_len as i64,
                i64
            ),
        );
        *self = Self::default();
    }
}

impl ServeRepairService {
    pub(crate) fn new(
        serve_repair: ServeRepair,
        remote_request_sender: Sender<RemoteRequest>,
        remote_request_receiver: Receiver<RemoteRequest>,
        repair_response_quic_sender: AsyncSender<(SocketAddr, Bytes)>,
        serve_repair_socket: UdpSocket,
        socket_addr_space: SocketAddrSpace,
        stats_reporter_sender: Sender<Box<dyn FnOnce() + Send>>,
        exit: Arc<AtomicBool>,
    ) -> Self {
        // request_sender: written into by streamer::receiver()
        // request_receiver: read from by adapt_repair_requests_packets()
        // remote_request_sender: written into by adapt_repair_requests_packets()
        // let (request_sender, request_receiver) = bounded(REPAIR_REQUEST_CHANNEL_CAPACITY);
        let (request_sender, request_receiver) = EvictingSender::new_bounded(REPAIR_REQUEST_CHANNEL_CAPACITY);
        let serve_repair_socket = Arc::new(serve_repair_socket);
        let t_receiver = streamer::receiver(
            "solRcvrServeRep".to_string(),
            serve_repair_socket.clone(),
            exit.clone(),
            request_sender,
            Recycler::default(),
            Arc::new(StreamerReceiveStats::new("serve_repair_receiver")),
            Some(Duration::from_millis(1)), // coalesce
            false,                          // use_pinned_memory
            false,                          // is_staked_service
        );
        let t_packet_adapter = Builder::new()
            .name(String::from("solServRAdapt"))
            .spawn(|| adapt_repair_requests_packets(request_receiver, remote_request_sender))
            .unwrap();
        // push to response_sender is blocking! see send_response() in serve_repair.rs
        // read from this channel is blocking with a timeout.
        // let (response_sender, response_receiver) = unbounded(); // greg: unbounded write channel
        let (response_sender, response_receiver) = bounded(3 * REPAIR_REQUEST_CHANNEL_CAPACITY);
        let t_responder = streamer::responder(
            "Repair",
            serve_repair_socket,
            response_receiver,
            socket_addr_space,
            Some(stats_reporter_sender),
        );
        let t_listen = serve_repair.listen(
            remote_request_receiver, // greg: unbounded read channel
            response_sender,
            repair_response_quic_sender,
            exit,
        );

        let thread_hdls = vec![t_receiver, t_packet_adapter, t_responder, t_listen];
        Self { thread_hdls }
    }

    pub(crate) fn join(self) -> thread::Result<()> {
        self.thread_hdls.into_iter().try_for_each(JoinHandle::join)
    }
}

// Adapts incoming UDP repair requests into RemoteRequest struct.
pub(crate) fn adapt_repair_requests_packets(
    packets_receiver: Receiver<PacketBatch>,
    remote_request_sender: Sender<RemoteRequest>,
) {
    const STATS_REPORT_INTERVAL: Duration = Duration::from_secs(1);
    let mut stats = AdaptRepairRequestStats::default();
    let mut last_report = Instant::now();
    'recv_batch: for packets in packets_receiver.iter() {
        stats.max_packets_channel_len = stats.max_packets_channel_len.max(packets_receiver.len());
        stats.max_requests_channel_len =
            stats.max_requests_channel_len.max(remote_request_sender.len());
        let total_packets = packets.len();
        for (i, packet) in packets.iter().enumerate() {
            let Some(bytes) = packet.data(..).map(Vec::from) else {
                continue;
            };
            let request = RemoteRequest {
                remote_pubkey: None,
                remote_address: packet.meta().socket_addr(),
                bytes: Bytes::from(bytes),
            };
           
            match remote_request_sender.try_send(request) {
                Ok(_) => {}
                Err(crossbeam_channel::TrySendError::Full(_)) => {
                    stats.dropped_batches_total += 1;
                    stats.dropped_packets_total += total_packets - i;
                    continue 'recv_batch;
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => return,
            }
        }
        if last_report.elapsed() >= STATS_REPORT_INTERVAL {
            stats.report_and_reset();
            last_report = Instant::now();
        }
    }
    stats.report_and_reset();
}
