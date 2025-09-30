use {
    crate::{
        netlink::{NetlinkMessage, NetlinkSocket},
        route::AtomicRouter,
    },
    libc::{poll, pollfd, POLLIN, RTMGRP_IPV4_ROUTE, RTMGRP_NEIGH},
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

            let mut refresh_routes: bool = false;
            let mut refresh_neighbors: bool = false;

            let mut outer_count: usize = 0;
            'outer: loop {
                outer_count += 1;
                log::info!("greg: outer loop count: {}", outer_count);
                if exit.load(Ordering::Relaxed) {
                    break;
                }

                // Just block until we get the first updata from netlink. don't start window until we have one update
                let first = match sock.recv() {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("netlink recv error: {e}; resyncing");
                        let _ = atomic_router.update_routes_and_neighbors();
                        continue;
                    }
                };
                if first.is_empty() {
                    continue;
                }
                log::info!("greg: got first update");
                Self::process_msgs(first, &mut refresh_routes, &mut refresh_neighbors);
                log::info!(
                    "greg: first update route_refresh_pending: {}, neigh_refresh_pending: {}",
                    refresh_routes,
                    refresh_neighbors
                );

                // read from socket for drain_window time
                let t0 = Instant::now();
                let deadline = t0 + drain_window;

                // Once we have an update, drain the netlink socket for the rest of the window
                loop {
                    if exit.load(Ordering::Relaxed) {
                        break 'outer;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }

                    let mut pfd = pollfd {
                        fd: sock.as_raw_fd(),
                        events: POLLIN,
                        revents: 0,
                    };
                    let remain_ms = (deadline - now).as_millis() as i32;
                    let rc = unsafe { poll(&mut pfd as *mut pollfd, 1, remain_ms) };
                    if rc < 0 {
                        log::warn!("poll error: {}", std::io::Error::last_os_error());
                        // treat as loss -> refresh both
                        refresh_routes = true;
                        refresh_neighbors = true;
                        break;
                    }
                    if rc == 0 || (pfd.revents & POLLIN) == 0 {
                        break;
                    }

                    if !Self::drain_netlink_socket(
                        &sock,
                        &mut refresh_routes,
                        &mut refresh_neighbors,
                    ) {
                        // on error, refresh both
                        refresh_routes = true;
                        refresh_neighbors = true;
                        break;
                    }
                }

                // based on incoming updates, refresh the appropriate tables
                if refresh_routes && refresh_neighbors {
                    let _ = atomic_router.update_routes_and_neighbors();
                } else if refresh_routes {
                    let _ = atomic_router.refresh_routes();
                } else if refresh_neighbors {
                    let _ = atomic_router.refresh_neighbors();
                } else {
                    continue;
                }

                refresh_routes = false;
                refresh_neighbors = false;
            }
        })
    }

    #[inline]
    fn drain_netlink_socket(
        sock: &NetlinkSocket,
        route_refresh_pending: &mut bool,
        neigh_refresh_pending: &mut bool,
    ) -> bool {
        let mut pfd = pollfd {
            fd: sock.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        loop {
            pfd.revents = 0;
            let rc0 = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
            if rc0 <= 0 || (pfd.revents & libc::POLLIN) == 0 {
                break;
            }

            match sock.recv() {
                Ok(msgs) => {
                    if msgs.is_empty() {
                        break;
                    }
                    Self::process_msgs(msgs, route_refresh_pending, neigh_refresh_pending);
                }
                Err(e) => {
                    log::warn!("recv during drain failed: {e}");
                    return false;
                }
            }
        }
        true
    }

    #[inline]
    fn process_msgs(
        msgs: Vec<NetlinkMessage>,
        route_refresh_pending: &mut bool,
        neigh_refresh_pending: &mut bool,
    ) {
        for m in msgs.into_iter() {
            m.check_if_relevant_message(route_refresh_pending, neigh_refresh_pending);
        }
    }
}
