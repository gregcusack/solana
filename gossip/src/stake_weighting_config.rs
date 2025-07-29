use {serde::Deserialize, solana_account::ReadableAccount, solana_runtime::bank::Bank};

#[derive(Deserialize, Debug)]
#[repr(u8)]
pub enum WeightingKind {
    Static,
    Dynamic,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum TimeConstant {
    /// IIR time-constant (ms)
    Value(u64),
    /// Use the default time constant.
    Default,
}

#[derive(Deserialize, Debug)]
#[repr(C)]
pub struct WeightingConfig {
    pub weighting_kind: WeightingKind,
    pub tc: TimeConstant,
}

mod weighting_config_control_pubkey {
    solana_pubkey::declare_id!("maCwV5aXW6srR4kppBWTeNdizYhyEwVcVh6mSWnFZxo");
}

pub(crate) fn get_gossip_config_from_account(bank: &Bank) -> Option<WeightingConfig> {
    let data = bank
        .accounts()
        .accounts_db
        .load_account_with(
            &bank.ancestors,
            &weighting_config_control_pubkey::id(),
            |_| true,
        )?
        .0;
    bincode::deserialize::<WeightingConfig>(data.data()).ok()
}
