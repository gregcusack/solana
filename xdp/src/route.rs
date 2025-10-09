use {
    crate::netlink::{
        netlink_get_interfaces, netlink_get_neighbors, netlink_get_routes, InterfaceInfo,
        MacAddress, NeighborEntry, RouteEntry,
    },
    arc_swap::ArcSwap,
    log::info,
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

    #[error("unknown interface index {0}")]
    UnknownInterfaceIndex(u32),
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

    pub fn clone_neighbors(&self) -> Vec<NeighborEntry> {
        self.arp_table.neighbors.clone()
    }

    pub fn clone_routes(&self) -> Vec<RouteEntry> {
        self.routes.as_ref().clone()
    }

    pub fn clone_interfaces(&self) -> HashMap<u32, InterfaceInfo> {
        self.interfaces.as_ref().clone()
    }

    pub fn default(&self) -> Result<NextHop, RouteError> {
        let default_route = self
            .routes
            .iter()
            .find(|r| r.destination.is_none())
            .ok_or(RouteError::NoRouteFound(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))?;

        let if_index = default_route
            .out_if_index
            .ok_or(RouteError::MissingOutputInterface)?;
        if !self.interfaces.contains_key(&(if_index as u32)) {
            return Err(RouteError::UnknownInterfaceIndex(if_index as u32));
        }

        let next_hop_ip = match default_route.gateway {
            Some(gateway) => gateway,
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        let mac_addr = self.arp_table.lookup(next_hop_ip, if_index).cloned();
        let preferred_src_ip = match default_route.pref_src {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        };

        Ok(NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index: if_index as u32,
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
            .ok_or(RouteError::MissingOutputInterface)?;
        if !self.interfaces.contains_key(&(if_index as u32)) {
            return Err(RouteError::UnknownInterfaceIndex(if_index as u32));
        }

        let next_hop_ip = match route.gateway {
            Some(gateway) => gateway,
            None => dest_ip,
        };

        let mac_addr = self.arp_table.lookup(next_hop_ip, if_index).cloned();
        let preferred_src_ip = match route.pref_src {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        };

        let next_hop = NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index: if_index as u32,
            preferred_src_ip,
        };

        // Get the interface info for this route
        let interface_info = self
            .interfaces
            .get(&(if_index as u32))
            .ok_or(RouteError::MissingOutputInterface)?
            .clone();

        Ok((next_hop, interface_info))
    }
}

#[derive(Clone, Default)]
pub struct WorkingRouter {
    pub routes: Vec<RouteEntry>,
    pub neighbors: Vec<NeighborEntry>,
    pub interfaces: HashMap<u32, InterfaceInfo>,
}

impl WorkingRouter {
    pub fn from_router(router: &Router) -> Self {
        Self {
            routes: router.routes.as_ref().clone(),
            neighbors: router.arp_table.neighbors.clone(),
            interfaces: router.interfaces.as_ref().clone(),
        }
    }

    pub fn to_router(&self) -> Router {
        Router {
            arp_table: Arc::new(ArpTable {
                neighbors: self.neighbors.clone(),
            }),
            routes: Arc::new(self.routes.clone()),
            interfaces: Arc::new(self.interfaces.clone()),
        }
    }

    #[inline]
    fn route_key(r: &RouteEntry) -> (u8, Option<IpAddr>, u8, Option<u32>, Option<i32>) {
        (r.family, r.destination, r.dst_len, r.table, r.out_if_index)
    }

    #[inline]
    fn neigh_key(n: &NeighborEntry) -> (Option<IpAddr>, i32) {
        (n.destination, n.ifindex)
    }

    pub fn apply_route_upsert(&mut self, route: RouteEntry) -> bool {
        let key = Self::route_key(&route);
        if let Some(idx) = self.routes.iter().position(|r| Self::route_key(r) == key) {
            if self.routes[idx] != route {
                self.routes[idx] = route; // route has same key but different value, update in place
                return true;
            }
            return false; // upserting route we already have, nothing to do
        }
        self.routes.push(route); // upserting route we don't have, add to end
        true
    }

    pub fn apply_route_delete(&mut self, route: &RouteEntry) -> bool {
        let key = Self::route_key(route);
        if let Some(idx) = self.routes.iter().position(|r| Self::route_key(r) == key) {
            self.routes.swap_remove(idx);
            return true;
        }
        false // trying to delete route we don't have, nothing to do
    }

    pub fn apply_neighbor_update(&mut self, neigh: NeighborEntry) -> bool {
        let key = Self::neigh_key(&neigh);
        if let Some(idx) = self
            .neighbors
            .iter()
            .position(|n| Self::neigh_key(n) == key)
        {
            if self.neighbors[idx] != neigh {
                self.neighbors[idx] = neigh; // neighbor has same key but different value, update in place
                return true;
            }
            return false; // upserting neighbor we already have, nothing to do
        }
        self.neighbors.push(neigh); // upserting neighbor we don't have, add to end
        true
    }

    pub fn apply_neighbor_delete(&mut self, neigh: &NeighborEntry) -> bool {
        let key = Self::neigh_key(neigh);
        if let Some(idx) = self
            .neighbors
            .iter()
            .position(|n| Self::neigh_key(n) == key)
        {
            self.neighbors.swap_remove(idx);
            return true;
        }
        false // trying to delete neighbor we don't have, nothing to do
    }
}

#[derive(Clone)]
pub(crate) struct ArpTable {
    pub(crate) neighbors: Vec<NeighborEntry>,
}

impl ArpTable {
    pub fn new() -> Result<Self, io::Error> {
        let neighbors = netlink_get_neighbors(None, AF_INET as u8)?;
        Ok(Self { neighbors })
    }

    pub fn lookup(&self, ip: IpAddr, if_index: i32) -> Option<&MacAddress> {
        self.neighbors
            .iter()
            .find(|n| n.ifindex == if_index && n.destination == Some(ip))
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

    pub fn load(&self) -> Arc<Router> {
        self.router.load().clone()
    }

    /// Publish a new snapshot of the router into the fast path
    pub fn publish(&self, new_router: Router) {
        self.router.store(Arc::new(new_router));
    }

    /// update both routes and ARP table
    pub fn resync(&self) -> Result<(), io::Error> {
        info!("greg: resyncing");
        let mut current_router = (**self.router.load()).clone();
        current_router.routes = Arc::new(netlink_get_routes(AF_INET as u8)?);
        current_router.arp_table = Arc::new(ArpTable {
            neighbors: netlink_get_neighbors(None, AF_INET as u8)?,
        });
        let interfaces = netlink_get_interfaces()?;
        let interface_map: HashMap<u32, InterfaceInfo> = interfaces
            .into_iter()
            .map(|if_info| (if_info.if_index, if_info))
            .collect();
        current_router.interfaces = Arc::new(interface_map);
        self.router.store(Arc::new(current_router));
        Ok(())
    }

    pub fn publish_snapshot(&self, working: &Working) {
        info!("greg: publishing new snapshot");
        let router = Router {
            arp_table: Arc::new(ArpTable {
                neighbors: working.neigh.clone(),
            }),
            routes: Arc::new(working.routes.clone()),
            interfaces: Arc::new(working.interfaces.clone()),
        };
        self.router.store(Arc::new(router));
    }
}

// Working Router used for lock-free updates
pub struct Working {
    routes: Vec<RouteEntry>,
    neigh: Vec<NeighborEntry>,
    interfaces: HashMap<u32, InterfaceInfo>,
    dirty_routes: bool,
    dirty_neigh: bool,
    dirty_interfaces: bool,
}

impl Working {
    // create a working router from the atomic router
    // only called on startup and when the atomic router is resynced due to a netlink error
    pub fn from_atomic_router(router: &AtomicRouter) -> Self {
        let router = router.load();
        let mut routes = router.clone_routes();
        let mut neigh = router.clone_neighbors();
        let mut interfaces = router.clone_interfaces();
        routes.reserve(routes.len().saturating_mul(2).max(512));
        neigh.reserve(neigh.len().saturating_mul(2).max(128));
        interfaces.reserve(interfaces.len().saturating_mul(2).max(128));
        Self {
            routes,
            neigh,
            interfaces,
            dirty_routes: false,
            dirty_neigh: false,
            dirty_interfaces: false,
        }
    }

    pub fn dirty_routes(&self) -> bool {
        self.dirty_routes
    }

    pub fn dirty_neigh(&self) -> bool {
        self.dirty_neigh
    }

    pub fn dirty_interfaces(&self) -> bool {
        self.dirty_interfaces
    }

    pub fn clear_dirty(&mut self) {
        self.dirty_routes = false;
        self.dirty_neigh = false;
        self.dirty_interfaces = false;
    }

    #[inline]
    fn same_key(a: &RouteEntry, b: &RouteEntry) -> bool {
        a.family == b.family
            && a.dst_len == b.dst_len
            && a.destination == b.destination
            && a.table == b.table
            && a.type_ == b.type_
    }

    #[inline]
    fn neighbor_key(n: &NeighborEntry) -> Option<(i32, Ipv4Addr)> {
        match n.destination {
            Some(IpAddr::V4(ip)) => Some((n.ifindex, ip)),
            _ => None,
        }
    }

    pub fn upsert_route(&mut self, new_route: RouteEntry) {
        if let Some(i) = self
            .routes
            .iter()
            .position(|old| Self::same_key(old, &new_route))
        {
            if self.routes[i] != new_route {
                self.routes[i] = new_route;
                self.dirty_routes = true;
            }
        } else {
            self.routes.push(new_route);
            self.dirty_routes = true;
        }
    }

    pub fn delete_route(&mut self, new_route: RouteEntry) {
        if let Some(i) = self
            .routes
            .iter()
            .position(|old| Self::same_key(old, &new_route))
        {
            self.routes.swap_remove(i);
            self.dirty_routes = true;
        }
    }

    pub fn upsert_neighbor(&mut self, new_neighbor: NeighborEntry) {
        if !new_neighbor.is_valid() {
            return;
        }
        let Some((ifidx, ip)) = Self::neighbor_key(&new_neighbor) else {
            return;
        };

        if let Some(i) = self
            .neigh
            .iter()
            .position(|old| old.ifindex == ifidx && old.destination == Some(IpAddr::V4(ip)))
        {
            if self.neigh[i] != new_neighbor {
                self.neigh[i] = new_neighbor;
                self.dirty_neigh = true;
            }
        } else {
            self.neigh.push(new_neighbor);
            self.dirty_neigh = true;
        }
    }

    pub fn delete_neighbor(&mut self, ip: Ipv4Addr, if_index: i32) {
        if let Some(i) = self
            .neigh
            .iter()
            .position(|old| old.ifindex == if_index && old.destination == Some(IpAddr::V4(ip)))
        {
            self.neigh.swap_remove(i);
            self.dirty_neigh = true;
        }
    }

    pub fn upsert_interface(&mut self, new_interface: InterfaceInfo) {
        self.interfaces
            .insert(new_interface.if_index, new_interface);
        self.dirty_interfaces = true;
    }

    pub fn delete_interface(&mut self, if_index: u32) {
        self.interfaces.remove(&if_index);
        self.dirty_interfaces = true;
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
    use {
        super::*,
        crate::netlink::{MacAddress, NeighborEntry, RouteEntry},
        libc::{AF_INET, NUD_REACHABLE},
        std::net::{IpAddr, Ipv4Addr},
    };

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

    #[test]
    fn test_working_upsert_and_delete_route() {
        let atomic_router = AtomicRouter::new().unwrap();
        let router_before = atomic_router.load();
        let before_routes = router_before.clone_routes();

        let mut working = Working::from_atomic_router(&atomic_router);

        // Create a unique, private IPv4 /32 route to avoid collisions
        let test_dst = Ipv4Addr::new(10, 255, 255, 123);
        let route = RouteEntry {
            destination: Some(IpAddr::V4(test_dst)),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1))),
            pref_src: None,
            out_if_index: Some(1),
            in_if_index: None,
            priority: None,
            table: None,
            protocol: 0,
            scope: 0,
            type_: 0,
            family: AF_INET as u8,
            dst_len: 32,
            flags: 0,
        };

        // Upsert new route and check that it was inserted and routes are dirty
        working.upsert_route(route.clone());
        assert!(working.dirty_routes());
        atomic_router.publish_snapshot(&working);
        working.clear_dirty();
        assert!(!working.dirty_routes());

        let router_after_insert = atomic_router.load();
        let after_insert_routes = router_after_insert.clone_routes();
        assert!(after_insert_routes.iter().any(|r| r == &route));
        assert!(after_insert_routes.len() >= before_routes.len());

        // Delete using same key should remove the route
        working.delete_route(route.clone());
        assert!(working.dirty_routes());
        atomic_router.publish_snapshot(&working);
        working.clear_dirty();

        let router_after_delete = atomic_router.load();
        let after_delete_routes = router_after_delete.clone_routes();
        assert!(after_delete_routes.iter().all(|r| r != &route));
        assert!(after_delete_routes.len() == before_routes.len());
    }

    #[test]
    fn test_working_upsert_and_delete_neighbor() {
        let atomic_router = AtomicRouter::new().unwrap();
        let router_before = atomic_router.load();
        let before_neigh = router_before.clone_neighbors();

        let mut working = Working::from_atomic_router(&atomic_router);

        // Create a unique, private neighbor entry on a dummy ifindex
        let neigh_ip = Ipv4Addr::new(10, 255, 255, 77);
        let entry = NeighborEntry {
            destination: Some(IpAddr::V4(neigh_ip)),
            lladdr: Some(MacAddress([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01])),
            ifindex: 1,
            state: NUD_REACHABLE,
        };

        // Upsert new neighbor and check that it was inserted and neighbors are dirty
        working.upsert_neighbor(entry.clone());
        assert!(working.dirty_neigh());
        atomic_router.publish_snapshot(&working);
        working.clear_dirty();
        assert!(!working.dirty_neigh());

        let router_after_insert = atomic_router.load();
        let after_insert_neigh = router_after_insert.clone_neighbors();
        assert!(after_insert_neigh.iter().any(|n| n == &entry));
        assert!(after_insert_neigh.len() >= before_neigh.len());

        // Delete neighbor and check that it was deleted
        working.delete_neighbor(neigh_ip, 1);
        assert!(working.dirty_neigh());
        atomic_router.publish_snapshot(&working);
        working.clear_dirty();

        let router_after_delete = atomic_router.load();
        let after_delete_neigh = router_after_delete.clone_neighbors();
        assert!(after_delete_neigh.iter().all(|n| n != &entry));
        assert!(after_delete_neigh.len() == before_neigh.len());
    }
}
