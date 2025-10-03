use {
    crate::{
        netlink::{
            is_supported_ipv4_neigh_header, is_supported_ipv4_route_header, parse_rtm_newneigh,
            parse_rtm_newroute, NetlinkMessage, NetlinkSocket,
        },
        route::{AtomicRouter, WorkingRouter},
    },
    libc::{
        poll, pollfd, POLLIN, RTMGRP_IPV4_ROUTE, RTMGRP_NEIGH, RTM_DELNEIGH, RTM_DELROUTE,
        RTM_NEWNEIGH, RTM_NEWROUTE,
    },
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
    },
};

pub struct RouteMonitor;

impl RouteMonitor {
    /// Subscribes to RTMGRP_IPV4_ROUTE | RTMGRP_NEIGH; drains for `drain_window`
    /// If any relevant updates arrived, fully refresh the corresponding tables.
    pub fn start(
        atomic_router: Arc<AtomicRouter>,
        exit: Arc<AtomicBool>,
        drain_window: Duration,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let groups = (RTMGRP_IPV4_ROUTE | RTMGRP_NEIGH) as u32;
            let sock = match NetlinkSocket::open_multicast_listener(groups) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("netlink bind failed: {e}");
                    return;
                }
            };
            // Set netlink socket to non-blocking once on creation
            unsafe {
                let fd = sock.as_raw_fd();
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                if flags >= 0 {
                    let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                } else {
                    log::warn!("fcntl(F_GETFL) failed: {}", std::io::Error::last_os_error());
                }
            }
            let snapshot = atomic_router.load();
            let mut working = WorkingRouter::from_router(&snapshot);
            let mut routes_changed = false;
            let mut neigh_changed = false;
            let mut resync_needed = false;

            'outer: loop {
                if exit.load(Ordering::Relaxed) {
                    break;
                }

                // Block until at least one message arrives; then start the window
                loop {
                    let mut pfd = pollfd {
                        fd: sock.as_raw_fd(),
                        events: POLLIN,
                        revents: 0,
                    };
                    let rc = unsafe { poll(&mut pfd as *mut pollfd, 1, -1) };
                    if rc < 0 {
                        let err = std::io::Error::last_os_error();
                        if let Some(code) = err.raw_os_error() {
                            if code == libc::EINTR {
                                continue;
                            }
                        }
                        log::warn!("poll error waiting first msg: {err}");
                        resync_needed = true;
                        break;
                    }
                    if (pfd.revents & POLLIN) != 0 {
                        break;
                    }
                }

                // Don't start window until we have one update
                let first = match sock.recv() {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("recv error on first drain: {e}");
                        continue;
                    }
                };
                if first.is_empty() {
                    continue;
                }
                Self::apply_msgs(
                    &mut working,
                    &first,
                    &mut routes_changed,
                    &mut neigh_changed,
                );

                log::info!(
                    "greg: first update routes_changed: {routes_changed}, neigh_changed: \
                     {neigh_changed}"
                );
                // read from socket for drain_window time
                let t0 = Instant::now();

                // Once we have an update, drain the netlink socket for the rest of the window
                loop {
                    if exit.load(Ordering::Relaxed) {
                        break 'outer;
                    }
                    let now = Instant::now();
                    if now.saturating_duration_since(t0) >= drain_window {
                        break;
                    }

                    let mut pfd = pollfd {
                        fd: sock.as_raw_fd(),
                        events: POLLIN,
                        revents: 0,
                    };
                    let remain_ms = drain_window
                        .saturating_sub(now.saturating_duration_since(t0))
                        .as_millis() as i32;
                    let rc = unsafe { poll(&mut pfd as *mut pollfd, 1, remain_ms) };
                    if rc < 0 {
                        let err = std::io::Error::last_os_error();
                        if let Some(code) = err.raw_os_error() {
                            if code == libc::EINTR {
                                continue;
                            }
                        }
                        log::warn!("poll error (non-fatal): {err}");
                        resync_needed = true;
                        break;
                    }
                    if rc == 0 || (pfd.revents & POLLIN) == 0 {
                        break;
                    }

                    // Drain as much as available immediately (non-blocking)
                    loop {
                        if Instant::now().saturating_duration_since(t0) >= drain_window {
                            break;
                        }
                        match sock.recv() {
                            Ok(msgs) => {
                                if msgs.is_empty() {
                                    break;
                                }
                                Self::apply_msgs(
                                    &mut working,
                                    &msgs,
                                    &mut routes_changed,
                                    &mut neigh_changed,
                                );
                            }
                            Err(e) => {
                                if let Some(code) = e.raw_os_error() {
                                    if code == libc::EAGAIN || code == libc::EWOULDBLOCK {
                                        break;
                                    }
                                }
                                log::warn!("recv during drain failed: {e}");
                                resync_needed = true;
                                break;
                            }
                        }
                    }
                }

                if resync_needed {
                    let _ = atomic_router.update_routes_and_neighbors();
                    let snapshot = atomic_router.load();
                    working = WorkingRouter::from_router(&snapshot);
                } else if routes_changed || neigh_changed {
                    log::info!("greg: publishing updated router. routes_changed: {routes_changed}, neigh_changed: {neigh_changed}");
                    atomic_router.publish(working.to_router());
                }

                routes_changed = false;
                neigh_changed = false;
                resync_needed = false;
            }
        })
    }

    #[inline]
    fn apply_msgs(
        working: &mut WorkingRouter,
        msgs: &[NetlinkMessage],
        routes_changed: &mut bool,
        neigh_changed: &mut bool,
    ) {
        for msg in msgs.iter() {
            match msg.nlmsg_type() {
                RTM_NEWROUTE | RTM_DELROUTE => {
                    if !is_supported_ipv4_route_header(msg) {
                        continue;
                    }
                    if let Some(route) = parse_rtm_newroute(msg) {
                        if msg.nlmsg_type() == RTM_DELROUTE {
                            *routes_changed |= working.apply_route_delete(&route);
                        } else {
                            *routes_changed |= working.apply_route_upsert(route);
                        }
                    }
                }
                RTM_NEWNEIGH | RTM_DELNEIGH => {
                    if !is_supported_ipv4_neigh_header(msg) {
                        continue;
                    }
                    if let Some(neigh) = parse_rtm_newneigh(msg, None) {
                        if msg.nlmsg_type() == RTM_DELNEIGH {
                            *neigh_changed |= working.apply_neighbor_delete(&neigh);
                        } else {
                            *neigh_changed |= working.apply_neighbor_update(neigh);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
