//! The answers of the conformance adapter (AXT `spec/conformance.md`, section 6).
//!
//! Behind the feature `conformance`, which only the crate `axt-conformance-adapter` turns on.
//! It is a test tool, not part of the public API.

use serde_json::{Map, Value as Json, json};

/// The categories of `spec/conformance.md`, section 2.1, that the adapter answers. A category
/// is listed only once all of its vectors pass.
pub const IMPLEMENTED_CATEGORIES: &[&str] = &[];

/// The version of the vector file format the adapter reads.
pub const VECTOR_FORMAT: i64 = 1;

/// One operation of a vector: its input, its result or a rejection.
type Operation = fn(&Map<String, Json>) -> Result<Json, Failure>;

/// Why an operation has no result.
#[derive(Debug)]
pub enum Failure {
    /// The request cannot be read: a fault of the input, not of the library.
    BadRequest(String),
}

/// The adapter: the categories it answers.
#[derive(Debug, Default)]
pub struct Adapter {
    /// Categories under construction that a local run asks for too (`--also <category>`);
    /// never set in CI.
    pub extra_categories: Vec<String>,
}

impl Adapter {
    /// Answers one request of the runner.
    #[must_use]
    pub fn answer(&self, request: &Json) -> Json {
        let Some(request) = request.as_object() else {
            return json!({"id": null, "failure": "the request is not a JSON object"});
        };
        let id = request.get("id").cloned().unwrap_or(Json::Null);
        let op = request.get("op").and_then(Json::as_str).unwrap_or_default();
        let input = request.get("input");
        if op == "hello" {
            let format = input.and_then(|i| i.get("format")).and_then(Json::as_i64);
            if format != Some(VECTOR_FORMAT) {
                return json!({
                    "id": id,
                    "failure": format!("vector format {format:?} is not {VECTOR_FORMAT}"),
                });
            }
            let mut categories: Vec<Json> =
                IMPLEMENTED_CATEGORIES.iter().map(|c| json!(c)).collect();
            categories.extend(self.extra_categories.iter().map(|c| json!(c)));
            return json!({
                "id": id,
                "output": {
                    "name": format!("axt-protocol (AXT {})", crate::AXT_VERSION),
                    "categories": categories,
                },
            });
        }
        let Some(operation) = operation(op) else {
            return json!({"id": id, "unsupported": true});
        };
        let Some(input) = input.and_then(Json::as_object) else {
            return json!({"id": id, "failure": "the input is not a JSON object"});
        };
        match operation(input) {
            Ok(output) => json!({"id": id, "output": output}),
            Err(Failure::BadRequest(message)) => json!({"id": id, "failure": message}),
        }
    }
}

/// The operation of a name, if the adapter performs it.
fn operation(_op: &str) -> Option<Operation> {
    None
}
