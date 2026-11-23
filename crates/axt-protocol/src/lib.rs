//! The Rust library of AXT (Avro eXchange Transfer).
//!
//! AXT is the open standard of <https://github.com/paxel/axt> for small apps to
//! exchange typed records.

mod avro;
mod bricks;
mod device_sets;
mod ed25519;
pub mod envelope;
pub mod error;
mod iregexp;
pub mod keys;
mod limits;
mod links;
mod manifest;
mod record_decoder;
mod records;
pub mod schema;
pub mod schemas;
mod sealing;
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
pub use keys::{EncryptionSeed, SigningSeed};
pub use schema::{Fingerprint, Schema};
pub use type_description::TypeDescription;
pub use value::Value;

/// The version of the AXT specification this library conforms to.
pub const AXT_VERSION: &str = "0.2.0";
