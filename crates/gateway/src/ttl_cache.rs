//! Bounded TTL storage shared by the Gateway's reconstructible routing caches.
use parking_lot::RwLock;
use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_CAPACITY: usize = 4096;

struct Entry<V> {
    expires_at: Instant,
    value: V,
}

struct Entries<V> {
    values: HashMap<String, Entry<V>>,
    expiry: BTreeSet<(Instant, String)>,
}

pub(crate) struct TtlCache<V> {
    ttl: Duration,
    capacity: usize,
    entries: RwLock<Entries<V>>,
}

impl<V: Clone> TtlCache<V> {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            entries: RwLock::new(Entries {
                values: HashMap::new(),
                expiry: BTreeSet::new(),
            }),
        }
    }

    pub fn get(&self, key: &str) -> Option<V> {
        let entries = self.entries.read();
        let entry = entries.values.get(key)?;
        (entry.expires_at > Instant::now()).then(|| entry.value.clone())
    }

    pub fn put(&self, key: String, value: V) {
        self.put_at(key, value, Instant::now());
    }

    fn put_at(&self, key: String, value: V, now: Instant) {
        let mut entries = self.entries.write();
        entries.prune(now);
        entries.remove(&key);
        if self.capacity == 0 {
            return;
        }
        while entries.values.len() >= self.capacity {
            entries.remove_oldest();
        }
        let expires_at = now + self.ttl;
        entries.expiry.insert((expires_at, key.clone()));
        entries.values.insert(key, Entry { expires_at, value });
    }

    pub fn remove(&self, key: &str) {
        self.entries.write().remove(key);
    }

    pub fn retain(&self, predicate: impl Fn(&V) -> bool) {
        let mut entries = self.entries.write();
        let removed: Vec<_> = entries
            .values
            .iter()
            .filter(|(_, entry)| !predicate(&entry.value))
            .map(|(key, _)| key.clone())
            .collect();
        for key in removed {
            entries.remove(&key);
        }
    }

    pub fn prune_expired(&self) -> usize {
        self.entries.write().prune(Instant::now())
    }
}

impl<V> Entries<V> {
    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.values.remove(key) {
            self.expiry.remove(&(entry.expires_at, key.to_owned()));
        }
    }

    fn remove_oldest(&mut self) {
        if let Some((_, key)) = self.expiry.pop_first() {
            self.values.remove(&key);
        }
    }

    fn prune(&mut self, now: Instant) -> usize {
        let before = self.values.len();
        while self
            .expiry
            .first()
            .is_some_and(|(expires, _)| *expires <= now)
        {
            self.remove_oldest();
        }
        before - self.values.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_evicts_oldest_without_invalidating_a_refreshed_entry() {
        let cache = TtlCache::new(Duration::from_secs(60), 2);
        let now = Instant::now();
        cache.put_at("a".into(), 1, now);
        cache.put_at("b".into(), 2, now + Duration::from_secs(1));
        cache.put_at("a".into(), 3, now + Duration::from_secs(2));
        cache.put_at("c".into(), 4, now + Duration::from_secs(3));
        assert_eq!(cache.get("a"), Some(3));
        assert_eq!(cache.get("b"), None);
        assert_eq!(cache.get("c"), Some(4));
        assert_eq!(cache.entries.read().values.len(), 2);
        assert_eq!(cache.entries.read().expiry.len(), 2);
    }

    #[test]
    fn maintenance_reclaims_abandoned_entries_and_preserves_refreshed_entries() {
        let cache = TtlCache::new(Duration::from_secs(60), 3);
        let now = Instant::now();
        cache.put_at("abandoned".into(), 1, now);
        cache.put_at("refreshed".into(), 2, now);
        cache.put_at("refreshed".into(), 3, now + Duration::from_secs(30));
        assert_eq!(
            cache.entries.write().prune(now + Duration::from_secs(61)),
            1
        );
        assert_eq!(cache.get("abandoned"), None);
        assert_eq!(cache.get("refreshed"), Some(3));
        assert_eq!(cache.entries.read().expiry.len(), 1);
    }

    #[test]
    fn invalidation_removes_values_and_expiry_records() {
        let cache = TtlCache::new(Duration::from_secs(60), 4);
        cache.put("a".into(), 1);
        cache.put("b".into(), 2);
        cache.put("c".into(), 3);
        cache.retain(|value| *value != 2);
        cache.remove("a");
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.get("b"), None);
        assert_eq!(cache.get("c"), Some(3));
        assert_eq!(cache.entries.read().expiry.len(), 1);
    }

    #[test]
    fn expired_entries_are_never_returned_before_maintenance() {
        let cache = TtlCache::new(Duration::ZERO, 4);
        cache.put("expired".into(), 1);
        assert_eq!(cache.get("expired"), None);
        assert_eq!(cache.prune_expired(), 1);
    }
}
