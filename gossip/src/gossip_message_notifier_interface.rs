use {crate::contact_info::ContactInfo, std::sync::Arc};

pub trait GossipMessageNotifierInterface: std::fmt::Debug {
    /// Notified when a CrdsValue is upserted
    fn notify_receive_message(&self, contact_info: &ContactInfo);
}

pub type GossipMessageNotifier = Arc<dyn GossipMessageNotifierInterface + Sync + Send>;
