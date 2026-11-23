//! The conformance adapter's answer to one request of arbitrary bytes: it must answer, never
//! panic.
#![no_main]

use axt_protocol::conformance::Adapter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = Adapter::default().answer(&request);
    }
});
