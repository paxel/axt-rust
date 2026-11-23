//! `axt-protocol-generate <description.json...> -o <file.rs>`: writes the Rust structs of
//! the types of descriptions.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ExitCode::from(axt_protocol_generate::run(
        &args,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
        None,
    ))
}
