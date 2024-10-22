/// Module responsible for notifying plugins of gossip messages
use {
    crate::geyser_plugin_manager::GeyserPluginManager,
    log::*,
    solana_gossip::{
        gossip_message_notifier_interface:: GossipMessageNotifierInterface,
        crds::VersionedCrdsValue,
    },
    std::sync::{Arc, RwLock},
};

#[derive(Debug)]
pub(crate) struct GossipMessageNotifierImpl {
    plugin_manager: Arc<RwLock<GeyserPluginManager>>,
}

impl GossipMessageNotifierInterface for GossipMessageNotifierImpl {
    fn notify_receive_message(
        &self,
        value: &VersionedCrdsValue,
    ) {
        // println!("greg: notify_receive_message. pk origin: {}", value.value.pubkey());
        self.notify_plugins_of_gossip_message(value);
    }
}

impl GossipMessageNotifierImpl {
    pub fn new(plugin_manager: Arc<RwLock<GeyserPluginManager>>) -> Self {
        Self { plugin_manager }
    }

    fn notify_plugins_of_gossip_message(
        &self,
        value: &VersionedCrdsValue,
    ) {
        let plugin_manager = self.plugin_manager.read().unwrap();
        if plugin_manager.plugins.is_empty() {
            return;
        }

        for plugin in plugin_manager.plugins.iter() {
            // TODO: figure out how to not clone the crds_value
            match plugin.insert_crds_value(value.clone()) {
                Err(err) => {
                    error!(
                        "Failed to insert crds value w/ origin: {}, error: {} to plugin {}",
                        value.value.pubkey(),
                        err,
                        plugin.name()
                    )
                }
                Ok(_) => {
                    info!(
                        "Inserted crds value w/ origin: {} to plugin {}",
                        value.value.pubkey(),
                        plugin.name()
                    )
                }
            }
        }
    }
}