use {
    crate::netlink::{
        netlink_get_neighbors, netlink_get_routes, MacAddress, NeighborEntry, RouteEntry,
    },
    arc_swap::ArcSwap,
    libc::{AF_INET, AF_INET6},
    std::{
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
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
    pub(crate) arp_table: Arc<ArpTable>,
    pub(crate) routes: Arc<Vec<RouteEntry>>,
}

impl Router {
    pub fn new() -> Result<Self, io::Error> {
        let arp_table = ArpTable::new()?;
        let routes = netlink_get_routes(AF_INET as u8)?;

        Ok(Self {
            arp_table: Arc::new(arp_table),
            routes: Arc::new(routes),
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

        Ok(NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index,
        })
    }

    pub fn route(&self, dest_ip: IpAddr) -> Result<NextHop, RouteError> {
        let route = lookup_route(&self.routes, dest_ip).ok_or(RouteError::NoRouteFound(dest_ip))?;

        let if_index = route
            .out_if_index
            .ok_or(RouteError::MissingOutputInterface)? as u32;

        let next_hop_ip = match route.gateway {
            Some(gateway) => gateway,
            None => dest_ip,
        };

        let mac_addr = self.arp_table.lookup(next_hop_ip).cloned();

        Ok(NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index,
        })
    }
}

#[derive(Clone, Default)]
pub struct WorkingRouter {
    pub routes: Vec<RouteEntry>,
    pub neighbors: Vec<NeighborEntry>,
}

impl WorkingRouter {
    pub fn from_router(router: &Router) -> Self {
        Self {
            routes: router.routes.as_ref().clone(),
            neighbors: router.arp_table.neighbors.clone(),
        }
    }

    pub fn to_router(&self) -> Router {
        Router {
            arp_table: Arc::new(ArpTable {
                neighbors: self.neighbors.clone(),
            }),
            routes: Arc::new(self.routes.clone()),
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

    /// Publish a new snapshot of the router into the fast path
    pub fn publish(&self, new_router: Router) {
        self.router.store(Arc::new(new_router));
    }

    /// update both routes and ARP table
    pub fn update_routes_and_neighbors(&self) -> Result<(), io::Error> {
        let mut current_router = (**self.router.load()).clone();
        current_router.routes = Self::fetch_routes()?;
        current_router.arp_table = Self::fetch_arp_table()?;
        self.router.store(Arc::new(current_router));
        Ok(())
    }

    /// Refresh only the routes, leave ARP table unchanged.
    pub fn refresh_routes(&self) -> Result<(), io::Error> {
        let mut current_router = (**self.router.load()).clone();
        current_router.routes = Self::fetch_routes()?;
        self.router.store(Arc::new(current_router));
        Ok(())
    }

    /// Refresh only the ARP neighbor table, leave routes unchanged.
    pub fn refresh_neighbors(&self) -> Result<(), io::Error> {
        let mut current_router = (**self.router.load()).clone();
        current_router.arp_table = Self::fetch_arp_table()?;
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
    fn test_router() {
        let router = Router::new().unwrap();
        let next_hop = router.route("1.1.1.1".parse().unwrap()).unwrap();
        eprintln!("{next_hop:?}");
    }
}
