//! The public API as an app outside the crate uses it: its own store, with its own error.

use std::collections::BTreeMap;

use axt_protocol::{
    AxtNode, EncryptionSeed, Error, NodeConfig, Outcome, OutgoingRecord, RecordPolicy,
    RecordResult, SigningSeed, Store, TypeDescription, Value, new_record_id,
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
        NodeConfig::new(manifest("App")),
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

fn text(t: &str) -> Value {
    Value::String(t.into())
}

/// A manifest content of `name` that takes `org.example.Memo`.
fn manifest(name: &str) -> Value {
    let take = Value::Record(vec![
        ("type".into(), text("org.example.Memo")),
        ("min_version".into(), Value::Int(1)),
        ("max_version".into(), Value::Null),
        ("purpose".into(), text("A memo becomes a note.")),
        ("purpose_translations".into(), Value::Map(BTreeMap::new())),
    ]);
    Value::Record(vec![
        ("app_name".into(), text(name)),
        ("app_url".into(), Value::Null),
        ("formats".into(), Value::Array(vec![Value::Int(1)])),
        ("takes".into(), Value::Array(vec![take])),
        ("any_type".into(), Value::Null),
        ("sends".into(), Value::Null),
        ("encryption_key".into(), Value::Null),
        ("relay".into(), Value::Null),
    ])
}

#[test]
fn an_app_writes_a_file_that_another_app_applies_in_its_own_transaction() {
    let memo = TypeDescription::from_json(&serde_json::json!({
        "name": "memo", "doc": "A memo.", "texts": {},
        "kind": {"axt.ObjectField": {"name": "org.example.Memo", "version": 1, "fields": [
            {"name": "text", "doc": "The text.", "texts": {}, "required": true,
             "kind": {"axt.StringField": {}}},
        ]}},
    }))
    .unwrap();
    let mut sender = AxtNode::open(
        AppStore::default(),
        SigningSeed::new([1; 32]),
        EncryptionSeed::new([2; 32]),
        NodeConfig::new(manifest("Sender")),
    );
    let mut config = NodeConfig::new(manifest("Reader"));
    config.readers = vec![memo.clone()];
    config.policy = RecordPolicy::default();
    let mut reader = AxtNode::open(
        AppStore::default(),
        SigningSeed::new([3; 32]),
        EncryptionSeed::new([4; 32]),
        config,
    );
    let id = new_record_id().unwrap();
    let value = Value::Record(vec![("text".into(), text("vet at 10"))]);
    let file = sender
        .write_file(
            &[OutgoingRecord::new(&id, &memo, value.clone())],
            Some(&reader.public_key()),
            false,
        )
        .unwrap();
    let preview = reader.inspect(&file).unwrap();
    assert!(preview.first_contact);
    assert_eq!(preview.app_name.as_deref(), Some("Sender"));
    let result = reader
        .apply(
            &preview,
            true,
            |store, change| {
                assert_eq!(change.outcome, Outcome::Applied);
                assert_eq!(change.value.as_ref(), Some(&value));
                store
                    .write(&format!("memo/{}", change.id), b"vet at 10")
                    .map_err(Error::store)
            },
            |_, _, _| Ok(None),
        )
        .unwrap();
    assert!(result.accepted);
    assert_eq!(
        result.records[0].result,
        RecordResult::Outcome(Outcome::Applied)
    );
    assert!(reader.store().data.contains_key(&format!("memo/{id}")));
}
