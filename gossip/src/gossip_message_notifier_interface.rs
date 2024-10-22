use {
    crate::crds_value::CrdsValue,
    std::sync::Arc,
};

pub trait GossipMessageNotifierInterface: std::fmt::Debug {
    /// Notified when an account is updated at runtime, due to transaction activities
    fn notify_receive_message(
        &self,
        crds_value: &CrdsValue,
    );
}

pub type GossipMessageNotifier = Arc<dyn GossipMessageNotifierInterface + Sync + Send>;
