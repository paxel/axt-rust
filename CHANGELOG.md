# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0]

### Added

- Passes every vector of the AXT 0.2.0 conformance categories `encoding` ([axtrs-4](https://github.com/paxel/axt-rust/issues/4)) and `bricks` ([axtrs-5](https://github.com/paxel/axt-rust/issues/5)).
- Live messages are read and written with their envelope, and schemas named by their CRC-64-AVRO fingerprint; records are generic values of the library's own `Value` type ([axtrs-4](https://github.com/paxel/axt-rust/issues/4)).
- Types are given as descriptions of typed fields, `TypeDescription`: the library validates them, derives their Avro schema and fingerprint, and checks record values against them; patterns run in time linear in the value ([axtrs-5](https://github.com/paxel/axt-rust/issues/5)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
