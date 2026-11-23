# axt-protocol

[![CI](https://github.com/paxel/axt-rust/actions/workflows/ci.yml/badge.svg?branch=summer)](https://github.com/paxel/axt-rust/actions/workflows/ci.yml)
[![Security](https://github.com/paxel/axt-rust/actions/workflows/security.yml/badge.svg?branch=summer)](https://github.com/paxel/axt-rust/actions/workflows/security.yml)
[![CodeQL](https://github.com/paxel/axt-rust/actions/workflows/codeql.yml/badge.svg?branch=summer)](https://github.com/paxel/axt-rust/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/paxel/axt-rust/badge)](https://scorecard.dev/viewer/?uri=github.com/paxel/axt-rust)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=paxel_axt-rust&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=paxel_axt-rust)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fpaxel%2Faxt-rust%2Fsummer%2F.github%2Fbadges%2Fcoverage-rust.json)](coverage-floors.toml)
[![Fuzz](https://github.com/paxel/axt-rust/actions/workflows/fuzz.yml/badge.svg?branch=summer)](https://github.com/paxel/axt-rust/actions/workflows/fuzz.yml)
[![Release](https://img.shields.io/github/v/release/paxel/axt-rust)](https://github.com/paxel/axt-rust/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](README.md#licence)
[![panic-free](https://img.shields.io/badge/panic--free-linted-success)](Cargo.toml)
[![unsafe](https://img.shields.io/badge/unsafe-forbidden-success)](Cargo.toml)

The Rust library of [AXT](https://github.com/paxel/axt) (Avro eXchange Transfer), the open
standard that lets small, independent apps exchange typed records with each other.

Status: in development; nothing is published yet.

## Conformance

`axt-protocol` is being built to conform to **AXT 0.2.0**: the categories every library must
implement (`encoding`, `types`, `time`, `records`, `manifest`, `keys`, `protocol`, `shares`,
`bricks`) and the transport `file`.

## Crates

| Crate                     | Content                                                     |
|---------------------------|-------------------------------------------------------------|
| `axt-protocol`            | The library                                                 |
| `axt-protocol-generate`   | Generates Rust structs for the types of AXT descriptions    |
| `axt-conformance-adapter` | The adapter of the AXT conformance suite (not published)    |

## Typed structs

`axt-protocol-generate <description.json...> -o <file.rs>` writes a Rust struct for the type of
each description, in the JSON form of `spec/fields.md`, section 10.3; it converts to and from
the library's `Value` (`From`/`TryFrom`) and carries its description as `DESCRIPTION`. The
generated code depends on `axt-protocol` alone. The eight example types of AXT 0.2.0 ship
generated in `axt_protocol::examples`.

## Platforms

Native only: Linux, macOS, Windows, Android and iOS.

## Licence

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
