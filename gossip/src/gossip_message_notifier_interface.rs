use {
    crate::crds::VersionedCrdsValue,
    std::sync::Arc,
};

pub trait GossipMessageNotifierInterface: std::fmt::Debug {
    /// Notified when an account is updated at runtime, due to transaction activities
    fn notify_receive_message(
        &self,
        value: &VersionedCrdsValue,
    );
}

pub type GossipMessageNotifier = Arc<dyn GossipMessageNotifierInterface + Sync + Send>;
