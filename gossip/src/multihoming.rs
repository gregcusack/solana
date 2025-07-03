use {crate::cluster_info::Node, solana_streamer::atomic_udp_socket::AtomicUdpSocket};

/// Subset of `Sockets`' used to share with the AdminRpc service for multihoming support
///
/// More sockets (tvu, retransmit, etc.) will be added in the future.
#[derive(Debug, Clone)]
pub struct SocketsMultihomed {
    pub gossip: AtomicUdpSocket,
}

/// Subset of `Node` used to share sockets with the AdminRpc service.
///
/// In the future, we will add more, non-socket members to this struct as we add more multihoming support.
#[derive(Debug, Clone)]
pub struct NodeMultihomed {
    pub sockets: SocketsMultihomed,
}

impl From<&Node> for NodeMultihomed {
    fn from(node: &Node) -> Self {
        NodeMultihomed {
            sockets: SocketsMultihomed {
                gossip: node.sockets.gossip.clone(),
            },
        }
    }
}
