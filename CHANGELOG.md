# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0]

### Added

- Passes every vector of the AXT 0.2.0 conformance categories `encoding` ([axtrs-4](https://github.com/paxel/axt-rust/issues/4)), `types` ([axtrs-6](https://github.com/paxel/axt-rust/issues/6)), `time` ([axtrs-7](https://github.com/paxel/axt-rust/issues/7)), `records` ([axtrs-10](https://github.com/paxel/axt-rust/issues/10)), `keys` ([axtrs-8](https://github.com/paxel/axt-rust/issues/8)), `manifest` ([axtrs-9](https://github.com/paxel/axt-rust/issues/9)), `file` ([axtrs-11](https://github.com/paxel/axt-rust/issues/11)), `protocol` ([axtrs-12](https://github.com/paxel/axt-rust/issues/12)) and `bricks` ([axtrs-5](https://github.com/paxel/axt-rust/issues/5)).
- Live messages are read and written with their envelope, and schemas named by their CRC-64-AVRO fingerprint; records are generic values of the library's own `Value` type ([axtrs-4](https://github.com/paxel/axt-rust/issues/4)).
- Types are given as descriptions of typed fields, `TypeDescription`: the library validates them, derives their Avro schema and fingerprint, and checks record values against them; patterns run in time linear in the value ([axtrs-5](https://github.com/paxel/axt-rust/issues/5)).
- Records written with another version of a type are read by Avro 1.12 schema resolution: fields matched by name, a field the reader adds takes its default ([axtrs-6](https://github.com/paxel/axt-rust/issues/6)).
- The app hands the library the seeds of its Ed25519 signing key and its X25519 encryption key, `SigningSeed` and `EncryptionSeed`, which are zeroed when dropped; messages are signed and verified strictly, and sealed and opened for a receiver ([axtrs-8](https://github.com/paxel/axt-rust/issues/8)).
- `AxtNode` keeps the AXT state in a key-value `Store` that the app implements on its own storage; the app gives records their ids (`new_record_id`, UUID version 7) ([axtrs-10](https://github.com/paxel/axt-rust/issues/10)).
- Reading AXT files in two steps, `inspect` for a preview of the sender and what fits, then `apply`, which hands each record to the app inside the store's transaction ([axtrs-11](https://github.com/paxel/axt-rust/issues/11)).
- Writing AXT files of the records shared with one receiver, with the withdrawals it is owed, or whole for an app of the own user; versions are state stamps that keep rising after a restore from a backup ([axtrs-11](https://github.com/paxel/axt-rust/issues/11)).
- The user's own changes of received records are kept per field or for the whole record, as the app's `RecordPolicy` chooses; relations and extensions merge per element, and extensions of types the app does not know are carried unchanged ([axtrs-10](https://github.com/paxel/axt-rust/issues/10)).
- Relations resolve across senders: `AxtNode::resolve` finds the record a relation points at, following the senders' device sets and joins, and `AxtNode::linked_from` lists the relations that point at a record ([axtrs-10](https://github.com/paxel/axt-rust/issues/10)).

---

Historical changes have been moved to [OLDER_CHANGES.md](OLDER_CHANGES.md).
