use {
    itertools::Itertools,
    lru::LruCache,
    solana_sdk::pubkey::Pubkey,
    std::{cmp::Reverse, collections::{HashSet, HashMap}},
};

// For each origin, tracks which nodes have sent messages from that origin and
// their respective score in terms of timeliness of delivered messages.
pub(crate) struct ReceivedCache(LruCache</*origin/owner:*/ Pubkey, ReceivedCacheEntry>);

#[derive(Clone, Default)]
struct ReceivedCacheEntry {
    nodes: HashMap<Pubkey, /*score:*/ usize>,
    num_upserts: usize,
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

    pub(crate) fn prune(
        &mut self,
        pubkey: &Pubkey, // This node.
        origin: Pubkey,  // CRDS value owner.
        stake_threshold: f64,
        min_ingress_nodes: usize,
        stakes: &HashMap<Pubkey, u64>,
    ) -> impl Iterator<Item = Pubkey> {
        match self.0.peek_mut(&origin) {
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
    fn mock_clone(&self) -> Self {
        let mut cache = LruCache::new(self.0.cap());
        for (&origin, entry) in self.0.iter().rev() {
            cache.put(origin, entry.clone());
        }
        Self(cache)
    }
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
    ) -> impl Iterator<Item = Pubkey> {
        debug_assert!((0.0..=1.0).contains(&stake_threshold));
        debug_assert!(self.num_upserts >= ReceivedCache::MIN_NUM_UPSERTS);
        // Enforce a minimum aggregate ingress stake; see:
        // https://github.com/solana-labs/solana/issues/3214
        let min_ingress_stake = {
            let stake = stakes.get(pubkey).min(stakes.get(origin));
            (stake.copied().unwrap_or_default() as f64 * stake_threshold) as u64
        };

        // Build a vector of (node, accumulated_stake) after sorting and scanning
        let results: Vec<(Pubkey, u64)> = self.nodes
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
            .collect();

        // Find the index where pruning starts:
        // skip min_ingress_nodes and then skip while stake < min_ingress_stake
        let prune_start_idx = results
            .iter()
            .enumerate()
            .skip(min_ingress_nodes)
            .find(|&(_, &(_, stake))| stake >= min_ingress_stake)
            .map(|(i, _)| i)
            .unwrap_or(results.len());

        // Split into not_pruned and pruned slices
        let (not_pruned, pruned) = results.split_at(prune_start_idx);
        let pruned_nodes: Vec<Pubkey> = pruned.iter().map(|(node, _)| *node).collect();
        let not_pruned = not_pruned.iter().map(|(node, _)| node).collect::<Vec<_>>();
        info!("greg: not pruned: {:?}", not_pruned);
        info!("greg: pruned: {:?}", pruned_nodes);

        let spoof_pubkeys: HashSet<_> = [
            Pubkey::try_from("141vSYKGRPNGieSrGJy8EeDVBcbjSr6aWkimNgrNZ6xN").unwrap(),
            Pubkey::try_from("J7v9ndmcoBuo9to2MnHegLnBkC9x3SAVbQBJo5MMJrN1").unwrap(),
            Pubkey::try_from("Can7hzmTxAuBBtaaMDCMPWwyYxMJLuXd5YVmPEDBTs1J").unwrap(),
            Pubkey::try_from("FT9QgTVo375TgDAQusTgpsfXqTosCJLfrBpoVdcbnhtS").unwrap(),
            Pubkey::try_from("J5BJHkRuGpWwfkm1Bxau6QFge4dTausFzdgvj3vzipuv").unwrap(),
            Pubkey::try_from("9QxCLckBiJc783jnMvXZubK4wH86Eqqvashtrwvcsgkv").unwrap(),
            Pubkey::try_from("5D1fNXzvv5NjV1ysLjirC4WY92RNsVH18vjmcszZd8on").unwrap(),
            Pubkey::try_from("C7cp6FA3hctfvH2kPUYttoJTNowrghE7xJZwS8yxCp1o").unwrap(),
            Pubkey::try_from("HZX4MWsSDzRerGuV6kgtj5sGM3dcX9doaiN7qr5y9MAw").unwrap(),
            Pubkey::try_from("mtvxq35ST4CnAiWuQeF6vLucJnNeut3wSFZs63so9jG").unwrap(),
        ].into_iter().collect();

        for pubkey in not_pruned {
            if spoof_pubkeys.contains(pubkey) {
                info!("greg: not pruning spoofed node : {:?}", pubkey);
            }
        }

        pruned_nodes.into_iter()


        // Return an iterator over pruned nodes
        // pruned.iter().map(|(node, _)| *node)
 
        // self.nodes
        //     .into_iter()
        //     .map(|(node, score)| {
        //         let stake = stakes.get(&node).copied().unwrap_or_default();
        //         (node, score, stake)
        //     })
        //     .sorted_unstable_by_key(|&(_, score, stake)| Reverse((score, stake)))
        //     .scan(0u64, |acc, (node, _score, stake)| {
        //         let old = *acc;
        //         *acc = acc.saturating_add(stake);
        //         Some((node, old))
        //     })
        //     .skip(min_ingress_nodes)
        //     .skip_while(move |&(_, stake)| stake < min_ingress_stake)
        //     .map(|(node, _stake)| node)
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
