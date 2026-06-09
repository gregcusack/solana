//! Votor wrapper for [`crate::datagram_transport::QuicDatagramEndpoint`].

use {
    crate::datagram_transport::allowlist::StakedNodesAllowlist,
    solana_pubkey::Pubkey,
    solana_runtime::bank_forks::SharableBanks,
    std::{collections::HashMap, sync::Arc},
};

/// ALPN identifier negotiated on every alpenglow QUIC handshake. Pass this as
/// the `alpn_protocol_id` when constructing the votor
/// [`crate::datagram_transport::endpoint::QuicDatagramEndpoint`].
pub const ALPENGLOW_ALPN: &[u8] = b"alpenglow-v1";

/// Build the allowlist map (pubkey → epoch stake) for validators with
/// positive stake in the working bank's current epoch. This is the
/// canonical allowlist; callers seed `StakedNodesAllowlist` from
/// this at construction and then drive subsequent epoch-boundary
/// refreshes from [`crate::staked_validators_cache::StakedValidatorsCache`].
///
/// Takes a [`SharableBanks`] so the working bank is read lock-free (no
/// `BankForks` `RwLock` acquisition).
pub fn current_admit_set(banks: &SharableBanks) -> HashMap<Pubkey, u64> {
    let bank = banks.working();
    let epoch = bank.epoch();
    bank.epoch_staked_nodes(epoch)
        .map(|m| {
            m.iter()
                .filter(|(_, stake)| **stake > 0)
                .map(|(pk, stake)| (*pk, *stake))
                .collect()
        })
        .unwrap_or_default()
}

/// Build a fresh [`StakedNodesAllowlist`] seeded with the current
/// epoch's staked-set.
pub fn build_allowlist(banks: &SharableBanks) -> Arc<StakedNodesAllowlist> {
    Arc::new(StakedNodesAllowlist::new(current_admit_set(banks)))
}
