//! The Rust library of AXT (Avro eXchange Transfer).
//!
//! AXT is the open standard of <https://github.com/paxel/axt> for small apps to
//! exchange typed records.

#[cfg(feature = "conformance")]
#[doc(hidden)]
pub mod conformance;

/// The version of the AXT specification this library conforms to.
pub const AXT_VERSION: &str = "0.2.0";
