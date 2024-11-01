/// Module responsible for notifying plugins of gossip messages
use {
    crate::geyser_plugin_manager::GeyserPluginManager,
    agave_geyser_plugin_interface::geyser_plugin_interface::{
        ContactInfoVersions, FfiContactInfo, FfiVersion,
    },
    log::*,
    solana_gossip::{
        crds::VersionedCrdsValue, crds_value::CrdsData,
        gossip_message_notifier_interface::GossipMessageNotifierInterface,
    },
    solana_sdk::pubkey::Pubkey,
    std::sync::{Arc, RwLock},
};

#[derive(Debug)]
pub(crate) struct GossipMessageNotifierImpl {
    plugin_manager: Arc<RwLock<GeyserPluginManager>>,
}

impl GossipMessageNotifierInterface for GossipMessageNotifierImpl {
    fn notify_receive_message(&self, value: &VersionedCrdsValue) {
        let ffi_ci = self
            .ffi_contact_info_from_value(value)
            .expect("Failed to convert VersionedCrdsValue to FfiContactInfo");
        self.notify_plugins_of_gossip_message(ffi_ci);
    }
}

impl GossipMessageNotifierImpl {
    pub fn new(plugin_manager: Arc<RwLock<GeyserPluginManager>>) -> Self {
        Self { plugin_manager }
    }

    fn ffi_contact_info_from_value(
        &self,
        value: &VersionedCrdsValue,
    ) -> Result<FfiContactInfo, std::io::Error> {
        if let CrdsData::ContactInfo(ci) = &value.value.data {
            let pubkey = ci.pubkey().to_bytes();
            let version = ci.version();
            let version = FfiVersion {
                major: version.major,
                minor: version.minor,
                patch: version.patch,
                commit: version.commit,
                feature_set: version.feature_set,
                client: u16::try_from(version.client())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            };

            return Ok(FfiContactInfo {
                pubkey,
                wallclock: ci.wallclock(),
                shred_version: ci.shred_version(),
                version,
            });
        }

        // Return an error if `CrdsData` is not `ContactInfo`
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected CrdsData::ContactInfo but found a different data type",
        ))
    }

    fn notify_plugins_of_gossip_message(&self, ffi_ci: FfiContactInfo) {
        let plugin_manager = self.plugin_manager.read().unwrap();
        if plugin_manager.plugins.is_empty() {
            return;
        }

        for plugin in plugin_manager.plugins.iter() {
            // TODO: figure out how to not clone the crds_value
            match plugin.insert_crds_value(ContactInfoVersions::V0_0_1(ffi_ci.clone())) {
                Err(err) => {
                    error!(
                        "Failed to insert crds value w/ origin: {}, error: {} to plugin {}",
                        Pubkey::from(ffi_ci.pubkey),
                        err,
                        plugin.name()
                    )
                }
                Ok(_) => {
                    trace!(
                        "Inserted crds value w/ origin: {} to plugin {}",
                        Pubkey::from(ffi_ci.pubkey),
                        plugin.name()
                    )
                }
            }
        }
    }
}
