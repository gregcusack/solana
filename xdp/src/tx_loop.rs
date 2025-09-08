#![allow(clippy::arithmetic_side_effects)]

use {
    crate::{
        device::{NetworkDevice, QueueId, RingSizes},
        netlink::MacAddress,
        packet::{
            write_eth_header, write_ip_header, write_udp_header, ETH_HEADER_SIZE, IP_HEADER_SIZE,
            UDP_HEADER_SIZE,
        },
        route::Router,
        set_cpu_affinity,
        socket::{Socket, Tx, TxRing},
        umem::{Frame as _, PageAlignedMemory, SliceUmem, SliceUmemFrame, Umem as _},
    },
    caps::{
        CapSet,
        Capability::{CAP_NET_ADMIN, CAP_NET_RAW},
    },
    crossbeam_channel::{Receiver, Sender, TryRecvError},
    libc::{sysconf, _SC_PAGESIZE},
    std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        thread,
        time::Duration,
    },
};

// packet tx logic happens here
#[allow(clippy::too_many_arguments)]
pub fn tx_loop<T: AsRef<[u8]>, A: AsRef<[SocketAddr]>>(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    src_mac: Option<MacAddress>,
    src_ip: Option<Ipv4Addr>,
    src_port: u16,
    dest_mac: Option<MacAddress>,
    receiver: Receiver<(A, T)>,
    drop_sender: Sender<(A, T)>,
) {
    log::info!(
        "starting xdp loop on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );

    // each queue/thread is bound to its own CPU core
    // cache efficiency and performance
    set_cpu_affinity([cpu_id]).unwrap();

    let src_mac = src_mac.unwrap_or_else(|| {
        // if no source MAC is provided, use the device's MAC address
        dev.mac_addr()
            .expect("no src_mac provided, device must have a MAC address")
    });
    let src_ip = src_ip.unwrap_or_else(|| {
        // if no source IP is provided, use the device's IPv4 address
        dev.ipv4_addr()
            .expect("no src_ip provided, device must have an IPv4 address")
    });

    // some drivers require frame_size=page_size
    // greg: get page size in bytes
    // page size is typically 4KB
    // some network drivers expect packet buffers to align with memory pages
    // better when buffers match page boundaries
    // dma ops more efficient with page aligned buffers
    // nics often expect page aligned buffers
    let frame_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

    // opens a network queue on the network interface
    // gets ring sizes from hardware (ethtool)
    // create devicequeue with queueinfo
    // returns DeviceQueue that represents opened queue
    // opening one queue per cpu core
    let queue = dev
        .open_queue(queue_id)
        .expect("failed to open queue for AF_XDP socket");
    let RingSizes {
        rx: rx_size,
        tx: tx_size,
    } = queue.ring_sizes().unwrap_or_else(|| {
        log::info!(
            "using default ring sizes for {} queue {queue_id:?}",
            dev.name()
        );
        RingSizes::default()
    });

    // total number of packet buffers to allocate in memory
    // hw buffers have fixed size (ringsizes)
    // memory buffers need to be larger than rings
    // 2x to avoid bottlenecks
    let frame_count = (rx_size + tx_size) * 2;

    // try to allocate huge pages first, then fall back to regular pages
    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| {
                log::warn!("huge page alloc failed, falling back to regular page size");
                PageAlignedMemory::alloc(frame_size, frame_count)
            })
            .unwrap();
    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    // we need NET_ADMIN and NET_RAW for the socket
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    //// creating af_xdp socket
    let Ok((mut socket, tx)) = Socket::tx(queue, umem, zero_copy, tx_size * 2, tx_size) else {
        panic!("failed to create AF_XDP socket on queue {queue_id:?}");
    };

    let umem = socket.umem();
    let umem_tx_capacity = umem.available();
    let Tx {
        // this is where we'll queue frames
        ring,
        // this is where we'll get completion events once frames have been picked up by the NIC
        mut completion,
    } = tx;
    let mut ring = ring.unwrap();

    // get the routing table from netlink
    let router = Router::new().expect("failed to create router");

    // we don't need higher caps anymore
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    // How long we sleep waiting to receive shreds from the channel.
    const RECV_TIMEOUT: Duration = Duration::from_nanos(1000);

    const MAX_TIMEOUTS: usize = 500;

    // We try to collect _at least_ BATCH_SIZE packets before queueing into the NIC. This is to
    // avoid introducing too much per-packet overhead and giving the NIC time to complete work
    // before we queue the next chunk of packets.
    const BATCH_SIZE: usize = 64;

    // Local buffer where we store packets before sending themi.
    let mut batched_items = Vec::with_capacity(BATCH_SIZE);

    // How many packets we've batched. This is _not_ batched_items.len(), but item * peers. For
    // example if we have 3 packets to transmit to 2 destination addresses each, we have 6 batched
    // packets.
    let mut batched_packets = 0;

    let mut timeouts = 0;
    loop {
        match receiver.try_recv() {
            Ok((addrs, payload)) => {
                batched_packets += addrs.as_ref().len(); // number of dest
                batched_items.push((addrs, payload)); // batches
                timeouts = 0;
                if batched_packets < BATCH_SIZE { // once we reach batch size, go onto the next
                    continue;
                }
            }
            Err(TryRecvError::Empty) => {
                if timeouts < MAX_TIMEOUTS {
                    timeouts += 1;
                    thread::sleep(RECV_TIMEOUT);
                } else {
                    timeouts = 0;
                    // we haven't received anything in a while, kick the driver
                    ring.commit();
                    kick(&ring);
                }
            }
            Err(TryRecvError::Disconnected) => {
                // keep looping until we've flushed all the packets
                // this is where we flush the ring
                if batched_packets == 0 {
                    break;
                }
            }
        };
        // now we have received a full batch of packets
        // greg: 
        // does ring get commited if we hit max batch size?
        // does ring (aka the driver) get kicked if we hit max batch size?
        // greg: yes but down below

        // this is the number of packets after which we commit the ring and kick the driver if
        // necessary
        let mut chunk_remaining = BATCH_SIZE.min(batched_packets);

        // ring holds slots for XdpDesc structs
        // xdpDesc struct describes the memory address in UMEM, total packet length, and flags/options
        // UMUM contains complete packets (headers/payloads)
        // TX RING (metadata):
        // Slot 0: XdpDesc { addr: 0x1000, len: 1500, options: 0 }
        // Slot 1: XdpDesc { addr: 0x2000, len: 1200, options: 0 }
        // Slot 2: XdpDesc { addr: 0x3000, len: 800,  options: 0 }
        // UMEM (actual packet data)
        // Frame 0 (0x1000): [ETH][IP][UDP][Payload1...]
        // Frame 1 (0x2000): [ETH][IP][UDP][Payload2...]
        // Frame 2 (0x3000): [ETH][IP][UDP][Payload3...]
        for (addrs, payload) in batched_items.drain(..) {
            for addr in addrs.as_ref() {
                // ring no available -> tx ring is full -> no slots to queue packets
                // umem no available -> umem is full -> no free memory frames to store packet data
                if ring.available() == 0 || umem.available() == 0 { // no space for the next packet
                    // loop until we have space for the next packet
                    loop {
                        // see what packets have been transmitted from the kernel
                        // tells kernel wat we've processed
                        // sees what kernel has written
                        completion.sync(true); // check for completion notifications from kernel
                        // we haven't written any frames so we only need to sync the consumer position
                        // sync tx ring with kernel without committing
                        // we are not commiting new frames to the ring, we are just syncing the consumer position
                        // and checking status of the ring
                        ring.sync(false);

                        // check if any frames were completed
                        // read complettion notification from kernel
                        // release memory frames back to pool
                        // each completion means one packet was transmitted successfully
                        // now we should have space for the next packet
                        while let Some(frame_offset) = completion.read() {
                            umem.release(frame_offset);
                        }

                        if ring.available() > 0 && umem.available() > 0 {
                            // we have space for the next packet, break out of the loop
                            break;
                        }

                        // queues are full, if NEEDS_WAKEUP is set kick the driver so hopefully it'll
                        // complete some work
                        kick(&ring);
                    }
                }

                // at this point we're guaranteed to have a frame to write the next packet into and
                // a slot in the ring to submit it
                let mut frame = umem.reserve().unwrap(); // get a free memory frame
                let IpAddr::V4(dst_ip) = addr.ip() else {
                    panic!("IPv6 not supported");
                };

                // route resolution
                let dest_mac = if let Some(mac) = dest_mac {
                    mac
                } else {
                    // greg: query routing table to get route for packet
                    let next_hop = router.route(addr.ip()).unwrap();

                    let mut skip = false;

                    // sanity check that the address is routable through our NIC
                    if next_hop.if_index != dev.if_index() {
                        log::warn!(
                            "dropping packet: turbine peer {addr} must be routed through \
                             if_index: {} our if_index: {}",
                            next_hop.if_index,
                            dev.if_index()
                        );
                        skip = true;
                    }

                    // we need the MAC address to send the packet
                    if next_hop.mac_addr.is_none() {
                        log::warn!(
                            "dropping packet: turbine peer {addr} must be routed through {} which \
                             has no known MAC address",
                            next_hop.ip_addr
                        );
                        skip = true;
                    };

                    if skip {
                        batched_packets -= 1;
                        umem.release(frame.offset());
                        continue;
                    }

                    next_hop.mac_addr.unwrap()
                };

                // greg: ok now we build the complete packet headers
                // we write the complete packet headers and payload into umem
                const PACKET_HEADER_SIZE: usize =
                    ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
                let len = payload.as_ref().len();
                frame.set_len(PACKET_HEADER_SIZE + len); // total packet length
                let packet = umem.map_frame_mut(&frame);

                // write the payload first as it's needed for checksum calculation (if enabled)
                packet[PACKET_HEADER_SIZE..][..len].copy_from_slice(payload.as_ref());


                write_eth_header(packet, &src_mac.0, &dest_mac.0);

                write_ip_header(
                    &mut packet[ETH_HEADER_SIZE..],
                    &src_ip,
                    &dst_ip,
                    (UDP_HEADER_SIZE + len) as u16,
                );

                write_udp_header(
                    &mut packet[ETH_HEADER_SIZE + IP_HEADER_SIZE..],
                    &src_ip,
                    src_port,
                    &dst_ip,
                    addr.port(),
                    len as u16,
                    // don't do checksums
                    false,
                );

                // write the packet descriptior/metadata (XdpDesc) into the ring 
                ring.write(frame, 0)
                    .map_err(|_| "ring full")
                    // this should never happen as we check for available slots above
                    .expect("failed to write to ring");

                batched_packets -= 1;
                chunk_remaining -= 1;

                // check if it's time to commit the ring and kick the driver
                if chunk_remaining == 0 {
                    chunk_remaining = BATCH_SIZE.min(batched_packets);

                    // commit new frames
                    ring.commit();
                    kick(&ring);
                }
            }
            let _ = drop_sender.try_send((addrs, payload));
        }
        debug_assert_eq!(batched_packets, 0);
    }
    assert_eq!(batched_packets, 0);

    // drain the ring
    // greg: is this when we are exiting?? 
    while umem.available() < umem_tx_capacity || ring.available() < ring.capacity() {
        log::debug!(
            "draining xdp ring umem {}/{} ring {}/{}",
            umem.available(),
            umem_tx_capacity,
            ring.available(),
            ring.capacity()
        );

        completion.sync(true);
        while let Some(frame_offset) = completion.read() {
            umem.release(frame_offset);
        }

        ring.sync(false);
        kick(&ring);
    }
}

// With some drivers, or always when we work in SKB mode, we need to explicitly kick the driver once
// we want the NIC to do something.
#[inline(always)]
fn kick(ring: &TxRing<SliceUmemFrame<'_>>) {
    if !ring.needs_wakeup() { 
        return;
    }

    if let Err(e) = ring.wake() { // wakeup network driver when new packets are available so it can process them
        kick_error(e);
    }
}

#[inline(never)]
fn kick_error(e: std::io::Error) {
    match e.raw_os_error() {
        // these are non-fatal errors
        Some(libc::EBUSY | libc::ENOBUFS | libc::EAGAIN) => {}
        // this can temporarily happen with some drivers when changing
        // settings (eg with ethtool)
        Some(libc::ENETDOWN) => {
            log::warn!("network interface is down")
        }
        // we should never get here, hopefully the driver recovers?
        _ => {
            log::error!("network interface driver error: {e:?}");
        }
    }
}
