//! Minimal bounded LRU cache for classification results.

use std::collections::HashMap;
use std::hash::Hash;

/// Bounded LRU cache. Used so repeated calls (e.g. multiple rivets classifying
/// the same sanitized text) do not re-run inference.
pub struct BoundedCache<K, V> {
    max_entries: usize,
    order: Vec<K>,
    store: HashMap<K, V>,
}

impl<K: Clone + Eq + Hash, V: Clone> BoundedCache<K, V> {
    pub fn new(max_entries: usize) -> Result<Self, String> {
        if max_entries == 0 {
            return Err("maxEntries must be a positive integer".to_string());
        }
        Ok(Self {
            max_entries,
            order: Vec::new(),
            store: HashMap::new(),
        })
    }

    pub fn get(&mut self, key: &K) -> Option<V> {
        if !self.store.contains_key(key) {
            return None;
        }
        self.order.retain(|k| k != key);
        self.order.push(key.clone());
        self.store.get(key).cloned()
    }

    pub fn set(&mut self, key: K, value: V) {
        if self.store.contains_key(&key) {
            self.order.retain(|k| k != &key);
        } else if self.store.len() >= self.max_entries {
            if let Some(oldest) = self.order.first().cloned() {
                self.order.remove(0);
                self.store.remove(&oldest);
            }
        }
        self.order.push(key.clone());
        self.store.insert(key, value);
    }

    pub fn has(&self, key: &K) -> bool {
        self.store.contains_key(key)
    }

    pub fn size(&self) -> usize {
        self.store.len()
    }

    pub fn clear(&mut self) {
        self.order.clear();
        self.store.clear();
    }
}
