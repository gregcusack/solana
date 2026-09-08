use {
    rayon::prelude::*,
    solana_hash::Hash,
    std::collections::{HashSet, VecDeque},
};

/// A bounded set of hashes ordered by insertion time.
///
/// Duplicate inserts do not refresh an entry. Once full, a new hash evicts
/// the oldest one. Removing entries retains the backing allocations so that
/// steady-state churn does not repeatedly allocate and deallocate memory.
pub(crate) struct RecentHashes {
    entries: VecDeque<(Hash, /*timestamp:*/ u64)>,
    members: HashSet<Hash>,
    capacity: usize,
}

impl RecentHashes {
    pub(crate) fn new(capacity: usize) -> Self {
        assert_ne!(capacity, 0);
        Self {
            entries: VecDeque::new(),
            members: HashSet::new(),
            capacity,
        }
    }

    /// Inserts a hash if it is not already present.
    pub(crate) fn insert(&mut self, hash: Hash, timestamp: u64) {
        if self.members.contains(&hash) {
            return;
        }
        if self.entries.len() == self.capacity {
            let (hash, _) = self.entries.pop_front().unwrap();
            assert!(self.members.remove(&hash));
        }
        self.entries.push_back((hash, timestamp));
        assert!(self.members.insert(hash));
    }

    /// Removes hashes inserted before `cutoff`.
    pub(crate) fn purge(&mut self, cutoff: u64) {
        while self
            .entries
            .front()
            .is_some_and(|(_, timestamp)| *timestamp < cutoff)
        {
            let (hash, _) = self.entries.pop_front().unwrap();
            assert!(self.members.remove(&hash));
        }
    }

    pub(crate) fn len(&self) -> usize {
        debug_assert_eq!(self.entries.len(), self.members.len());
        self.entries.len()
    }

    pub(crate) fn par_iter(&self) -> impl IndexedParallelIterator<Item = Hash> + '_ {
        self.entries.par_iter().map(|(hash, _)| *hash)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn back(&self) -> Option<&(Hash, u64)> {
        self.entries.back()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &(Hash, u64)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recent_hashes_capacity_and_deduplication() {
        let hashes: Vec<_> = (0..4)
            .map(|index| Hash::new_from_array([index; 32]))
            .collect();
        let mut recent = RecentHashes::new(3);

        recent.insert(hashes[0], 0);
        recent.insert(hashes[1], 1);
        recent.insert(hashes[0], 2);
        assert_eq!(recent.len(), 2);

        recent.insert(hashes[2], 3);
        recent.insert(hashes[3], 4);
        assert_eq!(recent.len(), 3);
        assert!(!recent.members.contains(&hashes[0]));
        assert!(
            recent
                .members
                .is_superset(&HashSet::from([hashes[1], hashes[2], hashes[3],]))
        );
    }

    #[test]
    fn test_recent_hashes_purge() {
        let hashes: Vec<_> = (0..3)
            .map(|index| Hash::new_from_array([index; 32]))
            .collect();
        let mut recent = RecentHashes::new(3);
        for (timestamp, hash) in hashes.iter().copied().enumerate() {
            recent.insert(hash, timestamp as u64);
        }

        // A duplicate does not refresh the original insertion timestamp.
        recent.insert(hashes[0], 10);
        recent.purge(2);
        assert_eq!(recent.len(), 1);
        assert!(recent.members.contains(&hashes[2]));
    }
}
