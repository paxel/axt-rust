//! The conformance adapter of `axt-protocol` (AXT `spec/conformance.md`, section 6).
//!
//! The runner of the AXT conformance suite starts it and sends one JSON request per line on
//! standard input; the adapter writes one JSON answer per line on standard output and nothing
//! else. It is a test tool, not part of the library.

use std::io::{self, BufRead, Write};

use axt_protocol::conformance::Adapter;
use serde_json::{Value as Json, json};

fn main() -> io::Result<()> {
    let mut adapter = Adapter::default();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--also"
            && let Some(category) = arguments.next()
        {
            adapter.extra_categories.push(category);
        }
    }
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let reply = match serde_json::from_str::<Json>(&line) {
            Ok(request) => adapter.answer(&request),
            Err(e) => json!({"id": null, "failure": format!("not JSON: {e}")}),
        };
        writeln!(stdout, "{reply}")?;
        stdout.flush()?;
    }
    Ok(())
}
