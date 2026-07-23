use {
    itertools::Itertools,
    lazy_lru::LruCache,
    solana_pubkey::Pubkey,
    std::{
        cmp::Reverse,
        collections::HashMap,
        fs,
        mem::size_of,
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::Instant,
    },
};

const RECEIVED_CACHE_REPORT_INTERVAL_MS: u64 = 5_000;
static RECEIVED_CACHE_MONITOR_START: OnceLock<Instant> = OnceLock::new();
static RECEIVED_CACHE_NEXT_REPORT_MS: AtomicU64 = AtomicU64::new(0);
static RECEIVED_CACHE_RSS_BASELINE_BYTES: OnceLock<u64> = OnceLock::new();

// For each origin, tracks which nodes have sent messages from that origin and
// their respective score in terms of timeliness of delivered messages.
pub(crate) struct ReceivedCache(LruCache</*origin/owner:*/ Pubkey, ReceivedCacheEntry>);

#[derive(Clone, Default)]
struct ReceivedCacheEntry {
    nodes: HashMap<Pubkey, /*score:*/ usize>,
    num_upserts: usize,
}

pub(crate) struct ReceivedCacheStats {
    origins: usize,
    nodes: usize,
    node_capacity: usize,
    largest_origin: Option<Pubkey>,
    largest_nodes: usize,
    largest_node_capacity: usize,
    largest_num_upserts: usize,
}

impl ReceivedCache {
    // Minimum number of upserts before a cache entry can be pruned.
    const MIN_NUM_UPSERTS: usize = 20;

    pub(crate) fn new(capacity: usize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub(crate) fn record(&mut self, origin: Pubkey, node: Pubkey, num_dups: usize) {
        match self.0.get_mut(&origin) {
            Some(entry) => entry.record(node, num_dups),
            None => {
                let mut entry = ReceivedCacheEntry::default();
                entry.record(node, num_dups);
                self.0.put(origin, entry);
            }
        }
    }

    pub(crate) fn stats_if_due(&self) -> Option<ReceivedCacheStats> {
        let now = RECEIVED_CACHE_MONITOR_START
            .get_or_init(Instant::now)
            .elapsed()
            .as_millis() as u64;
        let next = RECEIVED_CACHE_NEXT_REPORT_MS.load(Ordering::Relaxed);
        if now < next
            || RECEIVED_CACHE_NEXT_REPORT_MS
                .compare_exchange(
                    next,
                    now.saturating_add(RECEIVED_CACHE_REPORT_INTERVAL_MS),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return None;
        }

        let mut stats = ReceivedCacheStats {
            origins: self.0.len(),
            nodes: 0,
            node_capacity: 0,
            largest_origin: None,
            largest_nodes: 0,
            largest_node_capacity: 0,
            largest_num_upserts: 0,
        };
        for (origin, entry) in self.0.iter() {
            stats.nodes = stats.nodes.saturating_add(entry.nodes.len());
            stats.node_capacity = stats.node_capacity.saturating_add(entry.nodes.capacity());
            if entry.nodes.len() > stats.largest_nodes {
                stats.largest_origin = Some(*origin);
                stats.largest_nodes = entry.nodes.len();
                stats.largest_node_capacity = entry.nodes.capacity();
                stats.largest_num_upserts = entry.num_upserts;
            }
        }
        Some(stats)
    }

    pub(crate) fn prune(
        &mut self,
        pubkey: &Pubkey, // This node.
        origin: Pubkey,  // CRDS value owner.
        stake_threshold: f64,
        min_ingress_nodes: usize,
        stakes: &HashMap<Pubkey, u64>,
    ) -> impl Iterator<Item = Pubkey> + use<> {
        match self.0.get_mut(&origin) {
            None => None,
            Some(entry) if entry.num_upserts < Self::MIN_NUM_UPSERTS => None,
            Some(entry) => Some(
                std::mem::take(entry)
                    .prune(pubkey, &origin, stake_threshold, min_ingress_nodes, stakes)
                    .filter(move |node| node != &origin),
            ),
        }
        .into_iter()
        .flatten()
    }

    #[cfg(test)]
    fn mock_clone(&mut self) -> Self {
        Self(self.0.clone())
    }

    #[cfg(test)]
    pub(crate) fn entry_stats(
        &self,
        origin: &Pubkey,
    ) -> Option<(/*nodes:*/ usize, /*upserts:*/ usize)> {
        self.0
            .peek(origin)
            .map(|entry| (entry.nodes.len(), entry.num_upserts))
    }
}

impl ReceivedCacheStats {
    pub(crate) fn report(self) {
        let node_value_capacity_bytes_lower_bound = self
            .node_capacity
            .saturating_mul(size_of::<(Pubkey, usize)>());
        match process_rss_bytes() {
            Some(rss_bytes) => {
                let baseline = *RECEIVED_CACHE_RSS_BASELINE_BYTES.get_or_init(|| rss_bytes);
                let rss_delta_bytes = i128::from(rss_bytes) - i128::from(baseline);
                eprintln!(
                    "[received-cache-monitor] rss_bytes={rss_bytes} \
                     rss_delta_bytes={rss_delta_bytes} origins={} nodes={} node_capacity={} \
                     node_value_capacity_bytes_lower_bound={} largest_origin={:?} largest_nodes={} \
                     largest_node_capacity={} largest_num_upserts={}",
                    self.origins,
                    self.nodes,
                    self.node_capacity,
                    node_value_capacity_bytes_lower_bound,
                    self.largest_origin,
                    self.largest_nodes,
                    self.largest_node_capacity,
                    self.largest_num_upserts,
                );
            }
            None => eprintln!(
                "[received-cache-monitor] rss_bytes=unavailable origins={} nodes={} \
                 node_capacity={} node_value_capacity_bytes_lower_bound={} largest_origin={:?} \
                 largest_nodes={} largest_node_capacity={} largest_num_upserts={}",
                self.origins,
                self.nodes,
                self.node_capacity,
                node_value_capacity_bytes_lower_bound,
                self.largest_origin,
                self.largest_nodes,
                self.largest_node_capacity,
                self.largest_num_upserts,
            ),
        }
    }
}

fn process_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let kibibytes = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_ascii_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    kibibytes.checked_mul(1024)
}

impl ReceivedCacheEntry {
    // Limit how big the cache can get if it is spammed
    // with old messages with random pubkeys.
    const CAPACITY: usize = 50;
    // Threshold for the number of duplicates before which a message
    // is counted as timely towards node's score.
    const NUM_DUPS_THRESHOLD: usize = 2;

    fn record(&mut self, node: Pubkey, num_dups: usize) {
        if num_dups == 0 {
            self.num_upserts = self.num_upserts.saturating_add(1);
        }
        // If the message has been timely enough increment node's score.
        if num_dups < Self::NUM_DUPS_THRESHOLD {
            let score = self.nodes.entry(node).or_default();
            *score = score.saturating_add(1);
        } else if self.nodes.len() < Self::CAPACITY {
            // Ensure that node is inserted into the cache for later pruning.
            // This intentionally does not negatively impact node's score, in
            // order to prevent replayed messages with spoofed addresses force
            // pruning a good node.
            let _ = self.nodes.entry(node).or_default();
        }
    }

    fn prune(
        self,
        pubkey: &Pubkey, // This node.
        origin: &Pubkey, // CRDS value owner.
        stake_threshold: f64,
        min_ingress_nodes: usize,
        stakes: &HashMap<Pubkey, u64>,
    ) -> impl Iterator<Item = Pubkey> + use<> {
        debug_assert!((0.0..=1.0).contains(&stake_threshold));
        debug_assert!(self.num_upserts >= ReceivedCache::MIN_NUM_UPSERTS);
        // Enforce a minimum aggregate ingress stake; see:
        // https://github.com/solana-labs/solana/issues/3214
        let min_ingress_stake = {
            let stake = stakes.get(pubkey).min(stakes.get(origin));
            (stake.copied().unwrap_or_default() as f64 * stake_threshold) as u64
        };
        self.nodes
            .into_iter()
            .map(|(node, score)| {
                let stake = stakes.get(&node).copied().unwrap_or_default();
                (node, score, stake)
            })
            .sorted_unstable_by_key(|&(_, score, stake)| Reverse((score, stake)))
            .scan(0u64, |acc, (node, _score, stake)| {
                let old = *acc;
                *acc = acc.saturating_add(stake);
                Some((node, old))
            })
            .skip(min_ingress_nodes)
            .skip_while(move |&(_, stake)| stake < min_ingress_stake)
            .map(|(node, _stake)| node)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{collections::HashSet, iter::repeat_with},
    };

    #[test]
    fn test_received_cache() {
        let mut cache = ReceivedCache::new(/*capacity:*/ 100);
        let pubkey = Pubkey::new_unique();
        let origin = Pubkey::new_unique();
        let records = vec![
            vec![3, 1, 7, 5],
            vec![7, 6, 5, 2],
            vec![2, 0, 0, 2],
            vec![3, 5, 0, 6],
            vec![6, 2, 6, 2],
        ];
        let nodes: Vec<_> = repeat_with(Pubkey::new_unique)
            .take(records.len())
            .collect();
        for (node, records) in nodes.iter().zip(records) {
            for (num_dups, k) in records.into_iter().enumerate() {
                for _ in 0..k {
                    cache.record(origin, *node, num_dups);
                }
            }
        }
        assert_eq!(cache.0.get(&origin).unwrap().num_upserts, 21);
        let scores: HashMap<Pubkey, usize> = [
            (nodes[0], 4),
            (nodes[1], 13),
            (nodes[2], 2),
            (nodes[3], 8),
            (nodes[4], 8),
        ]
        .into_iter()
        .collect();
        assert_eq!(cache.0.get(&origin).unwrap().nodes, scores);
        let stakes = [
            (nodes[0], 6),
            (nodes[1], 1),
            (nodes[2], 5),
            (nodes[3], 3),
            (nodes[4], 7),
            (pubkey, 9),
            (origin, 9),
        ]
        .into_iter()
        .collect();
        let prunes: HashSet<Pubkey> = [nodes[0], nodes[2], nodes[3]].into_iter().collect();
        assert_eq!(
            cache
                .mock_clone()
                .prune(&pubkey, origin, 0.5, 2, &stakes)
                .collect::<HashSet<_>>(),
            prunes
        );
        let prunes: HashSet<Pubkey> = [nodes[0], nodes[2]].into_iter().collect();
        assert_eq!(
            cache
                .prune(&pubkey, origin, 1.0, 0, &stakes)
                .collect::<HashSet<_>>(),
            prunes
        );
    }
}
