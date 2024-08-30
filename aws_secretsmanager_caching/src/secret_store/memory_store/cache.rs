use linked_hash_map::LinkedHashMap;
use std::{borrow::Borrow, hash::Hash, num::NonZeroUsize};

#[derive(Debug, Clone)]
/// Keeps track of the most recently used items and evicts old entries when max_size is reached
pub struct Cache<K: Hash + Eq, V> {
    entries: LinkedHashMap<K, V>,
    max_size: NonZeroUsize,
}

/// Create a cache with a default size of 1000
impl<K: Hash + Eq, V> Default for Cache<K, V> {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(1000).unwrap())
    }
}

impl<K: Hash + Eq, V> Cache<K, V> {
    /// Returns a new least recently updated cache with default configuration.
    pub fn new(max_size: NonZeroUsize) -> Self {
        Cache {
            entries: LinkedHashMap::new(),
            max_size,
        }
    }

    /// Returns the number of items currently in the cache.
    pub fn len(&mut self) -> usize {
        self.entries.len()
    }

    /// Inserts a key into the cache.
    ///  If the key already exists, it overwrites it
    ///  If the insert results in too many keys in the cache, the oldest updated entry is removed.
    pub fn insert(&mut self, key: K, val: V) {
        self.entries.insert(key, val);
        if self.len() > self.max_size.get() {
            self.entries.pop_front();
        }
    }

    /// Retrieves the key from the cache.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        // This Q is used to allow for syntactic sugar with types like String, allowing &str as a key for example
        Q: ?Sized + Hash + Eq,
        K: Borrow<Q>,
    {
        self.entries.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestCache = Cache<String, TestCacheItem>;
    type TestIntCache = Cache<String, usize>;

    #[derive(PartialEq, Eq, Hash)]
    pub struct TestCacheItem {
        pub key: String,
    }

    #[test]
    fn len_counts() {
        let mut cache = TestCache::default();
        let item = TestCacheItem {
            key: "test".to_string(),
        };
        assert_eq!(cache.len(), 0);
        cache.insert("Test".to_string(), item);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn insert_inserts() {
        let mut cache = TestCache::default();
        let item = TestCacheItem {
            key: "test".to_string(),
        };
        assert_eq!(cache.len(), 0);
        cache.insert("Test".to_string(), item);
        let item2 = cache.get("Test");
        assert_eq!("test", item2.unwrap().key);
    }

    #[test]
    fn max_limit_followed() {
        let mut cache = TestIntCache::new(NonZeroUsize::new(4).unwrap());

        cache.insert("test1".to_string(), 1);
        cache.insert("test2".to_string(), 2);
        cache.insert("test3".to_string(), 3);
        cache.insert("test4".to_string(), 4);
        assert_eq!(cache.len(), 4);
        let items: Vec<usize> = cache.entries.iter().map(|t| (*t.1)).collect();
        assert_eq!(items, [1, 2, 3, 4]);

        cache.insert("test5".to_string(), 5);
        assert_eq!(cache.len(), 4);
        let items: Vec<usize> = cache.entries.iter().map(|t| (*t.1)).collect();
        assert_eq!(items, [2, 3, 4, 5]);
    }

    #[test]
    fn same_key_takes_latest_value() {
        let mut cache = TestIntCache::new(NonZeroUsize::new(4).unwrap());

        cache.insert("test1".to_string(), 1);
        cache.insert("test1".to_string(), 2);
        assert_eq!(cache.len(), 1);
        let items: Vec<usize> = cache.entries.iter().map(|t| (*t.1)).collect();
        assert_eq!(items, [2]);
    }
}
