//! `axt-protocol-generate`: Rust structs for the types of AXT descriptions.
//!
//! `axt-protocol-generate <description.json...> -o <file.rs>` writes one Rust file with a
//! struct for the type of each description, in the JSON form of `spec/fields.md`, section
//! 10.3, and a type for each named type inside it. The types convert to and from
//! `axt_protocol::Value`; the generated code depends on `axt-protocol` alone.

mod generate;

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use generate::{GenerateError, generate_from_descriptions};

const USAGE: &str = "\
Usage: axt-protocol-generate <description.json...> -o <file.rs>

Writes one Rust file with a struct for the type of each description, in the
JSON form of spec/fields.md, section 10.3, and a type for each named type
inside it. The types convert to and from axt_protocol::Value.

  -o, --output <file>  the Rust file to write
  -h, --help           print this help";

/// The prefix of every message of the command.
const NAME: &str = "axt-protocol-generate";

/// Runs the command with `args`, the arguments after the program's name, writing messages
/// to `out` and `err`; returns the exit code: 0 on success, 2 for a usage error, 1 for any
/// other failure. Nothing is written on a failure before the file. `format` formats the
/// written file and says whether it could; by default [`rustfmt`].
pub fn run(
    args: &[OsString],
    out: &mut dyn Write,
    err: &mut dyn Write,
    format: Option<&dyn Fn(&Path) -> bool>,
) -> u8 {
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut output: Option<PathBuf> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            let _ = writeln!(out, "{USAGE}");
            return 0;
        }
        if arg == "-o" || arg == "--output" {
            match args.next() {
                Some(file) => output = Some(PathBuf::from(file)),
                None => {
                    return usage_error(err, &format!("{} needs a file", arg.display()));
                }
            }
        } else {
            inputs.push(PathBuf::from(arg));
        }
    }
    let Some(output) = output else {
        return usage_error(err, "no output file");
    };
    if inputs.is_empty() {
        return usage_error(err, "no description");
    }
    let mut descriptions = Vec::new();
    for path in &inputs {
        match std::fs::read_to_string(path) {
            Ok(text) => descriptions.push((path.display().to_string(), text)),
            Err(e) => {
                let _ = writeln!(err, "{NAME}: {}: {e}", path.display());
                return 1;
            }
        }
    }
    let source = match generate_from_descriptions(&descriptions) {
        Ok(source) => source,
        Err(e) => {
            let _ = writeln!(err, "{NAME}: {e}");
            return 1;
        }
    };
    if let Err(e) = std::fs::write(&output, source) {
        let _ = writeln!(err, "{NAME}: {}: {e}", output.display());
        return 1;
    }
    let formatted = match format {
        Some(format) => format(&output),
        None => rustfmt(&output, None),
    };
    if !formatted {
        let _ = writeln!(err, "{NAME}: {}: rustfmt failed", output.display());
        return 1;
    }
    let _ = writeln!(out, "wrote {}", output.display());
    0
}

fn usage_error(err: &mut dyn Write, message: &str) -> u8 {
    let _ = writeln!(err, "{NAME}: {message}\n\n{USAGE}");
    2
}

/// Formats `path` in place with `rustfmt` of the edition 2024: `executable`, else the one
/// the environment variable `RUSTFMT` names, else `rustfmt` on the path. False where it
/// fails or cannot run.
#[must_use]
pub fn rustfmt(path: &Path, executable: Option<&Path>) -> bool {
    let program: OsString = match executable {
        Some(executable) => executable.into(),
        None => std::env::var_os("RUSTFMT").unwrap_or_else(|| "rustfmt".into()),
    };
    Command::new(program)
        .args([
            OsStr::new("--edition"),
            OsStr::new("2024"),
            path.as_os_str(),
        ])
        .status()
        .is_ok_and(|status| status.success())
}
