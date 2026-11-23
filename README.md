# axt-protocol

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

## Platforms

Native only: Linux, macOS, Windows, Android and iOS.

## Licence

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
