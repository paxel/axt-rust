//! The public API as an app outside the crate uses it: its own store, with its own error.

use std::collections::BTreeMap;

use axt_protocol::{
    AxtNode, EncryptionSeed, Error, RecordPolicy, SigningSeed, Store, Value, new_record_id,
};

/// The error of the app's store.
#[derive(Debug)]
struct DiskFull;

impl std::fmt::Display for DiskFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("disk full")
    }
}

impl std::error::Error for DiskFull {}

/// A store in memory that fails to list once `broken`.
#[derive(Default)]
struct AppStore {
    data: BTreeMap<String, Vec<u8>>,
    broken: bool,
}

impl Store for AppStore {
    type Error = DiskFull;

    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, DiskFull> {
        Ok(self.data.get(key).cloned())
    }

    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), DiskFull> {
        self.data.insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &str) -> Result<(), DiskFull> {
        self.data.remove(key);
        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, DiskFull> {
        if self.broken {
            return Err(DiskFull);
        }
        Ok(self
            .data
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn transaction<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let before = self.data.clone();
        let result = body(self);
        if result.is_err() {
            self.data = before;
        }
        result
    }
}

#[test]
fn an_app_opens_the_library_on_its_own_store() {
    let mut node = AxtNode::open(
        AppStore::default(),
        SigningSeed::new([1; 32]),
        EncryptionSeed::new([2; 32]),
        [],
        RecordPolicy::default(),
    );
    let id = new_record_id().unwrap();
    let target = Value::Record(vec![
        ("id".into(), Value::String(id.clone())),
        ("sender".into(), Value::Null),
        ("type".into(), Value::String(String::new())),
        ("text".into(), Value::String(String::new())),
    ]);
    assert_eq!(node.resolve("someone", &target).unwrap(), None);
    assert!(node.linked_from("someone", &id).unwrap().is_empty());
    node.store_mut().broken = true;
    let failed = node.linked_from("someone", &id).unwrap_err();
    assert!(matches!(failed, Error::Store(_)));
    assert_eq!(failed.to_string(), "the store failed: disk full");
}
