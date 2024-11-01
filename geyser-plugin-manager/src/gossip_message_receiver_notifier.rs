/// Module responsible for notifying plugins of gossip messages
use {
    crate::geyser_plugin_manager::GeyserPluginManager,
    agave_geyser_plugin_interface::geyser_plugin_interface::{FfiNode, FfiPubkey, FfiVersion},
    log::*,
    solana_gossip::{
        contact_info::ContactInfo,
        gossip_message_notifier_interface::GossipMessageNotifierInterface,
    },
    solana_measure::measure::Measure,
    solana_metrics::*,
    solana_sdk::pubkey::Pubkey,
    std::sync::{Arc, RwLock},
};

#[derive(Debug)]
pub(crate) struct GossipMessageNotifierImpl {
    plugin_manager: Arc<RwLock<GeyserPluginManager>>,
}

impl GossipMessageNotifierInterface for GossipMessageNotifierImpl {
    fn notify_receive_node_update(&self, contact_info: &ContactInfo) {
        let ffi_node = self
            .ffi_node_from_contact_info(contact_info)
            .expect("Failed to convert ContactInfo to FfiNode");
        self.notify_plugins_of_node_update(&ffi_node);
    }

    fn notify_remove_node(&self, pubkey: &Pubkey) {
        let ffi_pubkey = self.ffi_pubkey_from_pubkey(pubkey);
        self.notify_plugins_of_node_removal(&ffi_pubkey);
    }
}

impl GossipMessageNotifierImpl {
    pub fn new(plugin_manager: Arc<RwLock<GeyserPluginManager>>) -> Self {
        Self { plugin_manager }
    }

    fn ffi_pubkey_from_pubkey(&self, pubkey: &Pubkey) -> FfiPubkey {
        FfiPubkey {
            pubkey: pubkey.to_bytes(),
        }
    }

    fn ffi_node_from_contact_info(
        &self,
        contact_info: &ContactInfo,
    ) -> Result<FfiNode, std::io::Error> {
        let pubkey = contact_info.pubkey().to_bytes();
        let version = contact_info.version();
        let version = FfiVersion {
            major: version.major,
            minor: version.minor,
            patch: version.patch,
            commit: version.commit,
            feature_set: version.feature_set,
            client: u16::try_from(version.client())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        };

        Ok(FfiNode {
            pubkey: FfiPubkey { pubkey },
            wallclock: contact_info.wallclock(),
            shred_version: contact_info.shred_version(),
            version,
        })
    }

    fn notify_plugins_of_node_update(&self, ffi_node: &FfiNode) {
        let mut measure_all = Measure::start("geyser-plugin-notify_plugins_of_node_update");
        let plugin_manager = self.plugin_manager.read().unwrap();
        if plugin_manager.plugins.is_empty() {
            return;
        }

        for plugin in plugin_manager.plugins.iter() {
            let mut measure_plugin = Measure::start("geyser-plugin-notify_node_update");
            match plugin.notify_node_update(ffi_node) {
                Err(err) => {
                    error!(
                        "Failed to insert crds value w/ origin: {}, error: {} to plugin {}",
                        Pubkey::from(ffi_node.pubkey.pubkey),
                        err,
                        plugin.name()
                    )
                }
                Ok(_) => {
                    trace!(
                        "Inserted crds value w/ origin: {} to plugin {}",
                        Pubkey::from(ffi_node.pubkey.pubkey),
                        plugin.name()
                    )
                }
            }
            measure_plugin.stop();
            inc_new_counter_debug!(
                "geyser-plugin-notify_node_update-us",
                measure_plugin.as_us() as usize,
                100000,
                100000
            );
        }
        measure_all.stop();
        inc_new_counter_debug!(
            "geyser-plugin-notify_plugins_of_node_update-us",
            measure_all.as_us() as usize,
            100000,
            100000
        );
    }

    fn notify_plugins_of_node_removal(&self, ffi_pubkey: &FfiPubkey) {
        let mut measure_all = Measure::start("geyser-plugin-notify_plugins_of_node_removal");
        let plugin_manager = self.plugin_manager.read().unwrap();
        if plugin_manager.plugins.is_empty() {
            return;
        }

        for plugin in plugin_manager.plugins.iter() {
            let mut measure_plugin = Measure::start("geyser-plugin-notify_node_removal");
            match plugin.notify_node_removal(ffi_pubkey) {
                Err(err) => {
                    error!(
                        "Failed to remove pubkey: {}, error: {} to plugin {}",
                        Pubkey::from(ffi_pubkey.pubkey),
                        err,
                        plugin.name()
                    )
                }
                Ok(_) => {
                    trace!(
                        "removed pubkey: {} to plugin {}",
                        Pubkey::from(ffi_pubkey.pubkey),
                        plugin.name()
                    )
                }
            }
            measure_plugin.stop();
            inc_new_counter_debug!(
                "geyser-plugin-notify_node_removal-us",
                measure_plugin.as_us() as usize,
                100000,
                100000
            );
        }
        measure_all.stop();
        inc_new_counter_debug!(
            "geyser-plugin-notify_plugins_of_node_removal-us",
            measure_all.as_us() as usize,
            100000,
            100000
        );
    }
}
