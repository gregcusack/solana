use {
    crate::netlink::{
        netlink_get_interfaces, netlink_get_neighbors, netlink_get_routes, InterfaceInfo,
        MacAddress, NeighborEntry, RouteEntry,
    },
    arc_swap::ArcSwap,
    libc::{ifreq, syscall, SYS_ioctl, AF_INET, AF_INET6, IF_NAMESIZE, SIOCGIFADDR},
    std::{
        collections::HashMap,
        ffi::{c_char, CString},
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        sync::Arc,
    },
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("no route found to destination {0}")]
    NoRouteFound(IpAddr),

    #[error("missing output interface in route")]
    MissingOutputInterface,

    #[error("could not resolve MAC address")]
    MacResolutionError,
}

#[derive(Debug)]
pub struct NextHop {
    pub mac_addr: Option<MacAddress>,
    pub ip_addr: IpAddr,
    pub if_index: u32,
    pub preferred_src_ip: Option<Ipv4Addr>,
}

fn lookup_route(routes: &[RouteEntry], dest: IpAddr) -> Option<&RouteEntry> {
    let mut best_match = None;

    let family = match dest {
        IpAddr::V4(_) => AF_INET as u8,
        IpAddr::V6(_) => AF_INET6 as u8,
    };

    for route in routes.iter().filter(|r| r.family == family) {
        match (dest, route.destination) {
            // this is the default route
            (_, None) => {
                if best_match.is_none() {
                    best_match = Some((route, 0));
                }
            }

            (IpAddr::V4(dest_addr), Some(IpAddr::V4(route_addr))) => {
                let prefix_len = route.dst_len;
                if !is_ipv4_match(dest_addr, route_addr, prefix_len) {
                    continue;
                }

                if best_match.is_none() || prefix_len > best_match.unwrap().1 {
                    best_match = Some((route, prefix_len));
                }
            }

            (IpAddr::V6(dest_addr), Some(IpAddr::V6(route_addr))) => {
                let prefix_len = route.dst_len;
                if !is_ipv6_match(dest_addr, route_addr, prefix_len) {
                    continue;
                }

                if best_match.is_none() || prefix_len > best_match.unwrap().1 {
                    best_match = Some((route, prefix_len));
                }
            }

            // mixed address families - can't match
            _ => continue,
        }
    }

    best_match.map(|(route, _)| route)
}

fn is_ipv4_match(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }

    let mask = 0xFFFFFFFF << 32u32.saturating_sub(prefix_len as u32);
    let addr_bits = u32::from(addr) & mask;
    let network_bits = u32::from(network) & mask;

    addr_bits == network_bits
}

fn is_ipv6_match(addr: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }

    let addr_segments = addr.segments();
    let network_segments = network.segments();

    let full_segments = (prefix_len / 16) as usize;
    if addr_segments[..full_segments] != network_segments[..full_segments] {
        return false;
    }

    if let Some(remaining_bits) = prefix_len.checked_rem(16).filter(|&b| b != 0) {
        let mask = 0xFFFF_u16 << 16u16.saturating_sub(remaining_bits as u16);
        if (addr_segments[full_segments] & mask) != (network_segments[full_segments] & mask) {
            return false;
        }
    }

    true
}

#[derive(Clone)]
pub struct Router {
    arp_table: Arc<ArpTable>,
    routes: Arc<Vec<RouteEntry>>,
    interfaces: Arc<HashMap<u32, InterfaceInfo>>, // if_index (on host) -> InterfaceInfo map
}

impl Router {
    pub fn new() -> Result<Self, io::Error> {
        let arp_table = ArpTable::new()?;
        let routes = netlink_get_routes(AF_INET as u8)?;
        let interfaces = netlink_get_interfaces()?;
        let interface_map: HashMap<u32, InterfaceInfo> = interfaces
            .into_iter()
            .map(|if_info| (if_info.if_index, if_info))
            .collect();

        Ok(Self {
            arp_table: Arc::new(arp_table),
            routes: Arc::new(routes),
            interfaces: Arc::new(interface_map),
        })
    }

    pub fn default(&self) -> Result<NextHop, RouteError> {
        let default_route = self
            .routes
            .iter()
            .find(|r| r.destination.is_none())
            .ok_or(RouteError::NoRouteFound(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))?;

        let if_index = default_route
            .out_if_index
            .ok_or(RouteError::MissingOutputInterface)? as u32;

        let next_hop_ip = match default_route.gateway {
            Some(gateway) => gateway,
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        let mac_addr = self.arp_table.lookup(next_hop_ip).cloned();
        let preferred_src_ip = match default_route.pref_src {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        };

        Ok(NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index,
            preferred_src_ip,
        })
    }

    // greg: todo: not sure if we should return is_gre here?
    // we may want to return the entire InterfaceInfo
    // InterfaceInfo will have to be expanded to include the src_ip/dst_ip for gre
    pub fn route(&self, dest_ip: IpAddr) -> Result<(NextHop, InterfaceInfo), RouteError> {
        let route = lookup_route(&self.routes, dest_ip).ok_or(RouteError::NoRouteFound(dest_ip))?;

        let if_index = route
            .out_if_index
            .ok_or(RouteError::MissingOutputInterface)? as u32;

        let next_hop_ip = match route.gateway {
            Some(gateway) => gateway,
            None => dest_ip,
        };

        let mac_addr = self.arp_table.lookup(next_hop_ip).cloned();
        let preferred_src_ip = match route.pref_src {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        };

        let next_hop = NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index,
            preferred_src_ip,
        };

        // Get the interface info for this route
        let interface_info = self
            .interfaces
            .get(&(if_index))
            .ok_or(RouteError::MissingOutputInterface)?
            .clone();

        Ok((next_hop, interface_info))
    }
}

struct ArpTable {
    neighbors: Vec<NeighborEntry>,
}

impl ArpTable {
    pub fn new() -> Result<Self, io::Error> {
        let neighbors = netlink_get_neighbors(None, AF_INET as u8)?;
        Ok(Self { neighbors })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&MacAddress> {
        self.neighbors
            .iter()
            .find(|n| n.destination == Some(ip))
            .and_then(|n| n.lladdr.as_ref())
    }
}

pub struct AtomicRouter {
    router: ArcSwap<Router>,
}

impl AtomicRouter {
    pub fn new() -> Result<Self, io::Error> {
        Ok(Self {
            router: ArcSwap::from_pointee(Router::new()?),
        })
    }

    // Lock-free read - just load the current router
    pub fn load(&self) -> Arc<Router> {
        self.router.load().clone()
    }

    // update both routes and ARP table
    pub fn update_routes_and_neighbors(&self) -> Result<(), io::Error> {
        let mut current_router = (**self.router.load()).clone();
        current_router.routes = Self::fetch_routes()?;
        log::info!("greg: num routes: {}", current_router.routes.len());
        current_router.arp_table = Self::fetch_arp_table()?;
        log::info!("greg: num arp_table: {}", current_router.arp_table.neighbors.len());
        self.router.store(Arc::new(current_router));
        Ok(())
    }

    fn fetch_routes() -> Result<Arc<Vec<RouteEntry>>, io::Error> {
        Ok(Arc::new(netlink_get_routes(AF_INET as u8)?))
    }

    fn fetch_arp_table() -> Result<Arc<ArpTable>, io::Error> {
        let neighbors = netlink_get_neighbors(None, AF_INET as u8)?;
        Ok(Arc::new(ArpTable { neighbors }))
    }
}

/// Decide the fixed inner source IPv4 once (at startup or on router refresh).
/// Order:
///   1) any route RTA_PREFSRC (v4) from the current route dump (greg: todo: this will likely have to change with multihoming)
///   2) default route egress interface IPv4 (prefer interfaces[ifindex].primary_ipv4; else ioctl)
pub fn get_inner_src_ipv4(router: &Router) -> Result<Ipv4Addr, io::Error> {
    // 1) Any route with prefsrc (common when BGP installs /32 with 'src X')
    if let Some(v4) = router.routes.iter().find_map(|re| match re.pref_src {
        Some(IpAddr::V4(v)) => Some(v),
        _ => None,
    }) {
        return Ok(v4);
    }

    // 2) Default route egress interface address
    //    Find default route in main table: AF_INET, no RTA_DST, dst_len==0
    let def = router
        .routes
        .iter()
        .find(|re| re.family == libc::AF_INET as u8 && re.dst_len == 0 && re.destination.is_none())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no IPv4 default route found"))?;

    let oif = def
        .out_if_index
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "default route missing oif"))?
        as u32;

    // Prefer what you already cached on InterfaceInfo from RTM_GETADDR (scope=global)
    if let Some(iface) = router.interfaces.get(&oif) {
        if let Some(ip) = iface.primary_ipv4 {
            return Ok(ip);
        }
        // Fallback: query via ioctl once (safe here; this is init-time)
        return ioctl_ipv4_addr_by_name(&iface.if_name);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "default route oif not in interfaces map",
    ))
}

// greg: todo this is basically a copy of the function ipv4_addr() in device.rs
pub fn ioctl_ipv4_addr_by_name(if_name: &str) -> Result<Ipv4Addr, io::Error> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut req: ifreq = unsafe { std::mem::zeroed() };
    let if_name = CString::new(if_name.as_bytes()).unwrap();

    let if_name_bytes = if_name.as_bytes_with_nul();
    let len = std::cmp::min(if_name_bytes.len(), IF_NAMESIZE);
    unsafe {
        std::ptr::copy_nonoverlapping(
            if_name_bytes.as_ptr() as *const c_char,
            req.ifr_name.as_mut_ptr(),
            len,
        );
    }

    let result = unsafe { syscall(SYS_ioctl, fd.as_raw_fd(), SIOCGIFADDR, &mut req) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    let addr = unsafe {
        let addr_ptr = &req.ifr_ifru.ifru_addr as *const libc::sockaddr;
        let sin_addr = (*(addr_ptr as *const libc::sockaddr_in)).sin_addr;
        Ipv4Addr::from(sin_addr.s_addr.to_ne_bytes())
    };
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_match() {
        assert!(is_ipv4_match(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));

        assert!(!is_ipv4_match(
            Ipv4Addr::new(192, 168, 2, 10),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));

        // Match with default route
        assert!(is_ipv4_match(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(0, 0, 0, 0),
            0
        ));
    }

    #[test]
    fn test_ipv6_match() {
        assert!(is_ipv6_match(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0xabcd, 0xef01, 0x2345, 0x6789),
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 0),
            64
        ));

        assert!(!is_ipv6_match(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1235, 0x5678, 0xabcd, 0xef01, 0x2345, 0x6789),
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 0),
            64
        ));

        // Match with partial segment
        assert!(is_ipv6_match(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x6700, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x6600, 0, 0, 0, 0),
            52
        ));

        assert!(!is_ipv6_match(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x6700, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5600, 0, 0, 0, 0),
            52
        ));
    }

    #[test]
    fn test_route() {
        let router = Router::new().unwrap();
        let next_hop = router.route("1.1.1.1".parse().unwrap()).unwrap();
        eprintln!("{next_hop:?}");
    }
}
