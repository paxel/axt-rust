# axt-protocol

The Rust library of AXT: what an app holds, sends and receives when it speaks AXT. The terms of the specification itself are those of [paxel/axt](https://github.com/paxel/axt) (`spec/`); this file names the library's own. They are those of the Dart library, [paxel/axt-dart](https://github.com/paxel/axt-dart), in Rust form.

## Language

**Store**:
The key-value storage of bytes that the app implements for the library (the `Store` trait), with a transaction around each received message and file.
_Avoid_: database, repository

**Seed**:
The 32 bytes of a private key, the Ed25519 signing key or the X25519 encryption key, that the app keeps and hands the library.
_Avoid_: secret, private key file

**Description**:
A type as AXT 0.2.0 gives it: an `axt.Field` of bricks in the JSON form of `spec/fields.md`, section 10.3, from which the library derives the Avro schema.
_Avoid_: schema text (for a type)

**Record value**:
A record as a generic value of the library's own `Value` type, with its type's description.

**Links**:
A record's relations to records not shared with a receiver, to things outside AXT, and its extensions; they go along only with `with_links`.

**Relation index**:
What the library keeps to resolve relations across senders and to answer which records link to one.

**Preview**:
What `inspect` returns for a file before anything is applied: sender, short fingerprint, app name, the types that fit, first contact or not.

**Change**:
What the app gets in `on_record` for one received record: new, updated, deleted or withdrawn, with the merged value.

**Taken value**:
The value of a record as the library last took it from its sender, kept to find the user's own changes.
_Avoid_: original, base

**Shared ids**:
The ids of the app's records that are shared with one receiver now, which the app hands the library for each send and file.

## Relationships

- The app gives a record its **id**; the library gives each change its version, a state stamp.
- A **Change** is delivered inside the **Store**'s transaction, so the app's data and the library's bookkeeping are written together.
- The library compares the app's current value with the **Taken value**; a field that differs is the user's own change.

## Flagged ambiguities

- "Share" is the app's rule; the library only sees **Shared ids**.
