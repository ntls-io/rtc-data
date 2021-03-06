//! Support for inspecting [`KvStore`] instances (for testing and debugging)

use std::borrow::ToOwned;
use std::collections::HashMap;
#[cfg(not(test))]
use std::prelude::v1::*;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::in_memory::{InMemoryJsonStore, InMemoryStore};
use super::KvStore;

pub trait InspectStore<V> {
    fn to_map(&self) -> HashMap<String, V>;
}

impl<V> InspectStore<V> for InMemoryStore<V>
where
    V: Clone,
{
    fn to_map(&self) -> HashMap<String, V> {
        self.map.clone()
    }
}

impl<V> InspectStore<V> for InMemoryJsonStore
where
    V: Serialize + DeserializeOwned,
{
    fn to_map(&self) -> HashMap<String, V> {
        self.map
            .keys()
            .map(|k| {
                let loaded: Option<V> = self
                    .load(k)
                    .unwrap_or_else(|_| panic!("load {:?} failed!", k));
                let v: V = loaded.unwrap_or_else(|| panic!("key missing! {:?}", k));
                (k.to_owned(), v)
            })
            .collect()
    }
}
