//! The Rust library of AXT (Avro eXchange Transfer).
//!
//! AXT is the open standard of <https://github.com/paxel/axt> for small apps to
//! exchange typed records.

mod avro;
mod bricks;
mod container;
mod device_sets;
mod ed25519;
#[cfg(feature = "conformance")]
mod element_parts;
pub mod envelope;
pub mod error;
mod file_reader;
mod iregexp;
pub mod keys;
mod limits;
mod links;
#[cfg(feature = "conformance")]
mod live_session;
mod manifest;
mod node;
#[cfg(feature = "conformance")]
mod proposals;
mod record_decoder;
mod records;
mod relation_index;
pub mod schema;
pub mod schemas;
mod sealing;
#[cfg(feature = "conformance")]
mod shares;
mod signing;
mod time_values;
pub mod type_description;
pub mod value;
#[cfg(feature = "conformance")]
mod zone_rules;

#[cfg(feature = "conformance")]
#[doc(hidden)]
pub mod conformance;

pub use envelope::{
    Envelope, Kind, MAX_MESSAGE_BYTES, RecordRef, decode_body, decode_message, encode_message,
};
pub use error::{Error, ErrorCode};
pub use file_reader::{FileRecordResult, RecordResult};
pub use keys::{EncryptionSeed, SigningSeed};
pub use node::{
    AxtNode, Clock, FilePreview, FileResult, Link, NodeConfig, OutgoingRecord, RecordAddress,
    RecordChange, Store, new_record_id,
};
pub use records::{DeleteWithLocalChanges, LocalChanges, Outcome, RecordPolicy};
pub use schema::{Fingerprint, Schema};
pub use type_description::TypeDescription;
pub use value::Value;

/// The version of the AXT specification this library conforms to.
pub const AXT_VERSION: &str = "0.2.0";
