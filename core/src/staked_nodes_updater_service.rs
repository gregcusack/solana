use {
    arc_swap::ArcSwap,
    solana_pubkey::Pubkey,
    solana_runtime::bank_forks::BankForks,
    solana_streamer::streamer::StakedNodes,
    std::{
        collections::{HashMap, HashSet},
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

const STAKE_REFRESH_CYCLE: Duration = Duration::from_secs(5);

pub type StakedNodePubkeySet = Arc<ArcSwap<HashSet<Pubkey>>>;

pub struct StakedNodesUpdaterService {
    thread_hdl: JoinHandle<()>,
}

fn staked_pubkeys(
    stakes: &HashMap<Pubkey, u64>,
    overrides: &HashMap<Pubkey, u64>,
) -> HashSet<Pubkey> {
    let mut pubkeys: HashSet<_> = stakes
        .iter()
        .filter_map(|(pubkey, stake)| {
            (*stake > 0 && !overrides.contains_key(pubkey)).then_some(*pubkey)
        })
        .collect();
    pubkeys.extend(
        overrides
            .iter()
            .filter_map(|(pubkey, stake)| (*stake > 0).then_some(*pubkey)),
    );
    pubkeys
}

impl StakedNodesUpdaterService {
    pub fn new(
        exit: Arc<AtomicBool>,
        bank_forks: Arc<RwLock<BankForks>>,
        staked_nodes: Arc<RwLock<StakedNodes>>,
        staked_nodes_overrides: Arc<RwLock<HashMap<Pubkey, u64>>>,
        staked_node_pubkeys: Option<StakedNodePubkeySet>,
    ) -> Self {
        let thread_hdl = Builder::new()
            .name("solStakedNodeUd".to_string())
            .spawn(move || {
                while !exit.load(Ordering::Relaxed) {
                    let stakes = {
                        let root_bank = bank_forks.read().unwrap().root_bank();
                        root_bank.current_epoch_staked_nodes()
                    };
                    let overrides = staked_nodes_overrides.read().unwrap().clone();
                    if let Some(staked_node_pubkeys) = &staked_node_pubkeys {
                        staked_node_pubkeys.store(Arc::new(staked_pubkeys(&stakes, &overrides)));
                    }
                    *staked_nodes.write().unwrap() = StakedNodes::new(stakes, overrides);
                    std::thread::sleep(STAKE_REFRESH_CYCLE);
                }
            })
            .unwrap();

        Self { thread_hdl }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
