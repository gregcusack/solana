// re-export since this is needed at validator startup
pub use agave_xdp::set_cpu_affinity;
#[cfg(target_os = "linux")]
use {
    agave_xdp::{
        device::{NetworkDevice, QueueId},
        load_xdp_program,
        tx_loop::tx_loop,
    },
    crossbeam_channel::TryRecvError,
    std::{sync::Arc, thread::Builder, time::Duration},
};
use {
    crossbeam_channel::{Sender, TrySendError},
    solana_ledger::shred,
    std::{error::Error, net::SocketAddr, thread},
};

#[derive(Clone, Debug)]
pub struct XdpConfig {
    pub interface: Option<String>,
    pub cpus: Vec<usize>,
    pub zero_copy: bool,
    // The capacity of the channel that sits between retransmit stage and each XDP thread that
    // enqueues packets to the NIC.
    pub rtx_channel_cap: usize,
}

impl XdpConfig {
    // A nice round number
    const DEFAULT_RTX_CHANNEL_CAP: usize = 1_000_000;
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            interface: None,
            cpus: vec![],
            zero_copy: false,
            rtx_channel_cap: Self::DEFAULT_RTX_CHANNEL_CAP,
        }
    }
}

impl XdpConfig {
    pub fn new(interface: Option<impl Into<String>>, cpus: Vec<usize>, zero_copy: bool) -> Self {
        Self {
            interface: interface.map(|s| s.into()),
            cpus,
            zero_copy,
            rtx_channel_cap: XdpConfig::DEFAULT_RTX_CHANNEL_CAP,
        }
    }
}

#[derive(Clone)]
pub struct XdpSender {
    senders: Vec<Sender<(XdpAddrs, shred::Payload)>>,
}

pub enum XdpAddrs {
    Single(SocketAddr),
    Multi(Vec<SocketAddr>),
}

impl From<SocketAddr> for XdpAddrs {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        XdpAddrs::Single(addr)
    }
}

impl From<Vec<SocketAddr>> for XdpAddrs {
    #[inline]
    fn from(addrs: Vec<SocketAddr>) -> Self {
        XdpAddrs::Multi(addrs)
    }
}

impl AsRef<[SocketAddr]> for XdpAddrs {
    #[inline]
    fn as_ref(&self) -> &[SocketAddr] {
        match self {
            XdpAddrs::Single(addr) => std::slice::from_ref(addr),
            XdpAddrs::Multi(addrs) => addrs,
        }
    }
}

impl XdpSender {
    #[inline]
    pub(crate) fn try_send(
        &self,
        sender_index: usize,
        addr: impl Into<XdpAddrs>,
        payload: shred::Payload,
    ) -> Result<(), TrySendError<(XdpAddrs, shred::Payload)>> {
        self.senders[sender_index % self.senders.len()].try_send((addr.into(), payload))
    }
}

pub struct XdpRetransmitter {
    threads: Vec<thread::JoinHandle<()>>,
}

impl XdpRetransmitter {
    #[cfg(not(target_os = "linux"))]
    pub fn new(_config: XdpConfig, _src_port: u16) -> Result<(Self, XdpSender), Box<dyn Error>> {
        Err("XDP is only supported on Linux".into())
    }

    #[cfg(target_os = "linux")]
    pub fn new(config: XdpConfig, src_port: u16) -> Result<(Self, XdpSender), Box<dyn Error>> {
        use caps::{
            CapSet,
            Capability::{CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW},
        };
        const DROP_CHANNEL_CAP: usize = 1_000_000;

        // switch to higher caps while we setup XDP. We assume that an error in
        // this function is irrecoverable so we don't try to drop on errors.
        //greg: CAP_NET_ADMIN -> configure network interfaces
        //greg: CAP_NET_RAW -> send raw network packets
        //greg: CAP_BPF -> load ebpf programs for zero copy
        // need these so that we can attafch programs to the network interface and send packets directly
        for cap in [CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF] {
            caps::raise(None, CapSet::Effective, cap)
                .map_err(|e| format!("failed to raise {cap:?} capability: {e}"))?;
        }

        // greg: create network devicex handle that XDP will use to send packets
        // so we attach to the interface?
        let dev = Arc::new(if let Some(interface) = config.interface {
            NetworkDevice::new(interface).unwrap()
        } else {
            NetworkDevice::new_from_default_route().unwrap()
        });

        // greg: attach custom kernel code to network interface
        // so if zero copy is enabled, we attach the ebpf program to the network interface
        // so that we can send packets directly to the network interface
        // without going through the kernel
        // if zero copy is disabled, we don't attach the ebpf program
        // and we send packets through the kernel
        // but we still get the benefits of parallel transmission across multiple cpu cores
        // dedicated transmission threads with cpu affinity
        // channel-based packet queueing
        // greg: question: so we're not attaching any xdp program to the network interface???
        let ebpf = if config.zero_copy {
            Some(
                load_xdp_program(dev.if_index())
                    .map_err(|e| format!("failed to attach xdp program: {e}"))?,
            )
        } else {
            None
        };

        // greg: drop the caps after we've used them for setup
        for cap in [CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF] {
            caps::drop(None, CapSet::Effective, cap).unwrap();
        }

        //greg: create a channel for each cpu core
        // sender is what the main thread uses to send packets
        // receive is what the xdp transmission thread uses to receive packets
        // each cpu has its own channel
        // call try_send() with a packet
        // packet goes to a specific CPU channel 
        // that cpu's xdp thread picks up packet from its receiver
        // xdp thread sends packet out to the network interface
        let (senders, receivers) = (0..config.cpus.len())
            .map(|_| crossbeam_channel::bounded(config.rtx_channel_cap))
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let mut threads = vec![];

        // creates a channel for sending items that need to be dropped/clean up
        // xdp threads should never block or do expensive ops
        let (drop_sender, drop_receiver) = crossbeam_channel::bounded(DROP_CHANNEL_CAP);
        threads.push(
            Builder::new()
                .name("solRetransmDrop".to_owned())
                .spawn(move || {
                    loop {
                        // drop shreds in a dedicated thread so that we never lock/madvise() from
                        // the xdp thread
                        match drop_receiver.try_recv() {
                            Ok(i) => {
                                drop(i);
                            }
                            Err(TryRecvError::Empty) => {
                                thread::sleep(Duration::from_millis(1));
                            }
                            Err(TryRecvError::Disconnected) => break,
                        }
                    }
                    // move the ebpf program here so it stays attached until we exit
                    drop(ebpf);
                })
                .unwrap(),
        );

        // greg: spawn the xdp transmission threads - one for each cpu core
        // iterate over each cpu core
        // each core gets a transmit thread and a reference to the drop sender
        for (i, (receiver, cpu_id)) in receivers
            .into_iter()
            .zip(config.cpus.into_iter())
            .enumerate()
        {
            // each threads gets its own reference to the network device and drop_sender
            let dev = Arc::clone(&dev);
            let drop_sender = drop_sender.clone();
            threads.push(
                Builder::new()
                    .name(format!("solRetransmIO{i:02}"))
                    .spawn(move || {
                        tx_loop(
                            cpu_id, // cpu_id
                            &dev, // network device
                            QueueId(i as u64), // just the index of the cpu core
                            config.zero_copy,
                            None,
                            None,
                            src_port, // src port of the retransmit socket
                            None,
                            receiver, // the channel that the main thread uses to send packets. we read shreds to send from here
                            drop_sender,
                        )
                    })
                    .unwrap(),
            );
        }

        Ok((Self { threads }, XdpSender { senders }))
    }

    pub fn join(self) -> thread::Result<()> {
        for handle in self.threads {
            handle.join()?;
        }
        Ok(())
    }
}
