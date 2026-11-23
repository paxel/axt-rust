# 1. Parity with axt_protocol for Dart: the same model, in Rust

Date: 2026-11-23

## Status

Accepted.

## Context

`axt-protocol` is the Rust library of AXT. The Dart library, [paxel/axt-dart](https://github.com/paxel/axt-dart) (`axt_protocol` 0.2.0), conforms to AXT 0.2.0 and passes the categories `encoding`, `bricks`, `types`, `time`, `keys`, `manifest`, `records`, `file`, `protocol` and `shares`; its public API is decided in its ADR 1 and ADR 2. The Rust library is to offer all of its features. AXT 0.3.0 is started in paxel/axt but not released. Grilled on 2026-11-23 (Q1 to Q24).

## Decision

- **AXT 0.2.0 only** (Q1): the CI pins `axt-0.2.0.tar.gz` by its SHA-256 and its attestation.
- **The API of axt_protocol** (Q2): ADR 1 and ADR 2 of axt-dart are taken over as they are, in Rust idiom (traits, `Result`, enums). The library keeps the AXT state in a key-value store of bytes that the app implements, with a transaction around each received message and file; records are generic values with their type's description; the app keeps the seeds; results are values, errors only for a whole that fails; a file is read with `inspect` and `apply`; `on_record` is called inside the transaction; the library resolves relations; links go along per record with `with_links`; types are given as descriptions.
- **Blocking** (Q3): no async runtime; the `Store` is a plain trait. Dart is asynchronous only because its cryptography is.
- **`apache-avro`** (Q4) from crates.io does Avro 1.12, inside the library only.
- **Typed structs from a CLI** (Q5): `axt-protocol-generate <description.json...> -o <file.rs>`; the eight example types of AXT 0.2.0 ship generated in an `examples` module, and CI generates them again and diffs.
- **The name `axt-protocol`** (Q6), imported as `axt_protocol`, the name of the Dart package.
- **A workspace of three crates** (Q7): `axt-protocol` (the library), `axt-protocol-generate` (published), `axt-conformance-adapter` (`publish = false`).
- **A `Value` of its own** (Q8): the public API carries the library's own `Value` enum; `apache-avro` stays replaceable.
- **Generated structs bind to `Value`** (Q9): `impl From<T> for Value`, `impl TryFrom<Value> for T`, the description as a const; the generator writes its own code, without `rsgen-avro`.
- **Bundled zone rules** (Q10) through `jiff`, the same on every platform.
- **One release with full parity** (Q11): built in stages, published only once every category passes.
- **Version `0.1.0`** (Q12), versioned on its own; the AXT version is stated separately.
- **Native only** (Q13): Linux, macOS, Windows, Android, iOS.
- **The gates of paxel/gates** (Q14), as axt-dart has them, with `rust.yml`.
- **Ticket IDs `axtrs-<n>`** (Q15), from `axtrs-1`.
- **`Apache-2.0 OR MIT`** (Q16).
- **MSRV is the pinned stable toolchain** (Q17).
- **`AxtNode<S: Store>`** (Q18), generic over the store, with a generic `transaction<T>`.
- **I-Regexp through `regex`** (Q19): the crate's own parser validates RFC 9485 and translates the pattern; `regex` matches in time linear in the value.
- **Seeds with `zeroize`** (Q20): `[u8; 32]`, zeroed on drop, without `Debug`.
- **No store in the crate** (Q21): only the trait; a memory store lives in the tests and the adapter.
- **Errors as in Dart** (Q22): an `ErrorCode` of the specification's codes, with a message and, for `VALUE_INVALID`, the field path.
- **Store errors pass through** (Q23): `Store` has an associated `Error` type; `Error` is `Axt { code, message, field }` or `Store(..)`, and `code()` returns `Option<ErrorCode>`.
- **The docs of axt-dart** (Q24): `AGENTS.md`, `CLAUDE.md`, `CONTEXT.md`, this ADR, `docs/agents/`.

## Considered options

- AXT 0.3.0, which has no vectors yet; or 0.2.0 with a planned move.
- An API designed anew for Rust; an `async` API, or both behind a feature.
- A Rust port of dart-avro of its own, or only the Avro subset AXT needs.
- A proc macro or a `build.rs` function for typed structs, or no generation; serde structs on `apache-avro`.
- The names `axt` or `axt-rs`; one crate with the generator behind a feature.
- `apache_avro::types::Value` or `serde_json::Value` in the public API.
- The system's zone rules, or rules the app hands in.
- Staged releases that do not conform yet; version `0.2.0` to match the Dart package.
- `wasm32` support; workflows of its own; a lagging MSRV.
- `Box<dyn Store>`; a port of Dart's I-Regexp matcher; seeds without zeroing; a `MemoryStore` or a SQLite store in the crate; one error variant per cause; store methods that return the library's error.

## Consequences

- An app gets the same model in Dart and in Rust.
- A Tokio app calls the library inside `spawn_blocking`.
- The library converts between its `Value` and `apache-avro`'s.
- The live connection stays internal to the library, as in Dart, and is tested through the adapter; `sync`, `qr`, `local` and `relay` are not part of 0.1.0.
