//! Device sets: adding and removing devices, and a receiver that follows the devices of
//! its known senders (AXT `spec/keys.md`, section 5).

use std::collections::{BTreeMap, BTreeSet};

use crate::ed25519::{is_point_of_order_l, verify_strict};
use crate::envelope::{Kind, decode_body, decode_message};
use crate::error::{Error, ErrorCode};
use crate::signing::{device_add_proof_bytes, verify_live_message};
use crate::value::Value;

/// An Ed25519 public key.
pub(crate) type Key = [u8; 32];

/// The bytes of the fixed `name` of a decoded body.
fn fixed_field<const N: usize>(body: &Value, name: &str) -> Result<[u8; N], Error> {
    match body.field(name) {
        Some(Value::Fixed(bytes)) => bytes.as_slice().try_into().map_err(|_| {
            Error::axt(
                ErrorCode::InvalidMessage,
                format!("{name} has {} bytes, not {N}", bytes.len()),
            )
        }),
        _ => Err(Error::axt(
            ErrorCode::InvalidMessage,
            format!("the body has no fixed {name}"),
        )),
    }
}

/// A `DEVICE_ADD` or `DEVICE_REMOVE`, decoded.
pub(crate) struct DeviceChange {
    /// The message as received.
    message: Vec<u8>,
    /// `DEVICE_ADD` or `DEVICE_REMOVE`.
    kind: Kind,
    /// The message's `sender`.
    pub(crate) signer: Key,
    /// The body's `device`.
    pub(crate) device: Key,
    /// The proof of an addition; `None` for a removal.
    proof: Option<[u8; 64]>,
}

impl DeviceChange {
    /// Decodes `message`, a live message of the kind `DEVICE_ADD` or `DEVICE_REMOVE`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidMessage`] for a message of another kind or with a broken body,
    /// and the errors of [`decode_message`].
    pub(crate) fn decode(message: &[u8]) -> Result<Self, Error> {
        let envelope = decode_message(message)?;
        if envelope.kind != Kind::DeviceAdd && envelope.kind != Kind::DeviceRemove {
            return Err(Error::axt(
                ErrorCode::InvalidMessage,
                format!("{} is no addition or removal", envelope.kind.symbol()),
            ));
        }
        let body = decode_body(envelope.kind, &envelope.body)?;
        let proof = if envelope.kind == Kind::DeviceAdd {
            Some(fixed_field(&body, "proof")?)
        } else {
            None
        };
        Ok(Self {
            message: message.to_vec(),
            kind: envelope.kind,
            signer: envelope.sender,
            device: fixed_field(&body, "device")?,
            proof,
        })
    }

    /// Whether it is a `DEVICE_ADD`.
    pub(crate) fn is_add(&self) -> bool {
        self.kind == Kind::DeviceAdd
    }

    /// Step 1: whether the message's signature verifies with the signer's key.
    pub(crate) fn signature_verifies(&self) -> bool {
        verify_live_message(&self.message, &self.signer)
    }

    /// Step 2: whether the device's key and the proof of an addition verify, and a removal
    /// does not remove its own signer.
    pub(crate) fn device_verifies(&self) -> bool {
        match &self.proof {
            None => self.device != self.signer,
            Some(proof) => {
                is_point_of_order_l(&self.device) && self.proof_verifies(&self.signer, proof)
            }
        }
    }

    /// Whether `proof` is the device's signature over its addition by `member`.
    fn proof_verifies(&self, member: &Key, proof: &[u8; 64]) -> bool {
        verify_strict(
            &self.device,
            &device_add_proof_bytes(member, &self.device),
            proof,
        )
    }
}

/// The result of a `DEVICE_ADD` or `DEVICE_REMOVE` at a receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangeResult {
    /// Applied.
    Applied,
    /// Ignored: a repeat, or a removal of a key the signer's sender does not have.
    Ignored,
    /// Rejected by step 2 or by the table.
    DeviceRejected,
    /// Its signature does not verify.
    SignatureInvalid,
    /// Signed with a refused key.
    Refused,
    /// By a key the receiver does not know, about a key that vouches for no one.
    NotPlaced,
}

impl ChangeResult {
    /// The result as the conformance vectors write it.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Applied => "APPLIED",
            Self::Ignored => "IGNORED",
            Self::DeviceRejected => "DEVICE_REJECTED",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::Refused => "REFUSED",
            Self::NotPlaced => "NOT_PLACED",
        }
    }
}

/// The state of a record a receiver keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordState {
    /// The record is there.
    There,
    /// The record is deleted; its tombstone is kept.
    Tombstone,
}

/// What a receiver keeps of one record: its version and its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeptRecord {
    /// The record's version.
    pub(crate) version: i64,
    /// Whether it is there or a tombstone.
    pub(crate) state: RecordState,
}

/// A sender a receiver knows: its keys and its records.
#[derive(Debug, Clone, Default)]
pub(crate) struct KnownSender {
    /// The name by which the receiver shows the sender.
    pub(crate) name: String,
    /// The current keys.
    pub(crate) current: BTreeSet<Key>,
    /// The removed keys.
    pub(crate) removed: BTreeSet<Key>,
    /// The records, by id.
    pub(crate) records: BTreeMap<String, KeptRecord>,
}

impl KnownSender {
    /// Whether the sender has only one key, current and not removed.
    fn has_one_key(&self) -> bool {
        self.current.len() == 1 && self.removed.is_empty()
    }

    /// Whether `key` is a current or a removed key of the sender.
    fn has(&self, key: &Key) -> bool {
        self.current.contains(key) || self.removed.contains(key)
    }
}

/// What a key is to the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyState {
    /// A current key of a known sender.
    Current,
    /// A removed key of a known sender.
    Removed,
    /// A refused key.
    Refused,
    /// A key of no known sender.
    Unknown,
}

impl KeyState {
    /// The state as the conformance vectors write it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Removed => "removed",
            Self::Refused => "refused",
            Self::Unknown => "unknown",
        }
    }
}

/// The outcome of a message tried by the table: one of the results, or kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Try {
    Applied,
    Ignored,
    Rejected,
    Refused,
    NotPlaced,
    KeptRemoval,
}

impl Try {
    /// The result a vector names for the outcome.
    const fn result(self) -> ChangeResult {
        match self {
            Self::Applied => ChangeResult::Applied,
            Self::Ignored | Self::KeptRemoval => ChangeResult::Ignored,
            Self::Rejected => ChangeResult::DeviceRejected,
            Self::Refused => ChangeResult::Refused,
            Self::NotPlaced => ChangeResult::NotPlaced,
        }
    }
}

/// A receiver that follows the devices of its known senders (section 5.5).
#[derive(Debug, Clone, Default)]
pub(crate) struct DeviceSetReceiver {
    /// The senders the receiver knows.
    pub(crate) senders: Vec<KnownSender>,
    /// The receiver's refused keys (section 3.4).
    pub(crate) refused: BTreeSet<Key>,
}

impl DeviceSetReceiver {
    /// The position of the known sender of which `key` is a key, current or removed.
    fn sender_of(&self, key: &Key) -> Option<usize> {
        self.senders.iter().position(|sender| sender.has(key))
    }

    /// What `key` is to the receiver.
    pub(crate) fn state_of(&self, key: &Key) -> KeyState {
        if self.refused.contains(key) {
            return KeyState::Refused;
        }
        match self.sender_of(key).and_then(|i| self.senders.get(i)) {
            None => KeyState::Unknown,
            Some(sender) if sender.current.contains(key) => KeyState::Current,
            Some(_) => KeyState::Removed,
        }
    }

    /// The sender of which `key` is a current key.
    pub(crate) fn current_sender_of(&self, key: &Key) -> Option<&KnownSender> {
        self.sender_of(key)
            .and_then(|i| self.senders.get(i))
            .filter(|sender| sender.current.contains(key))
    }

    /// Takes the messages of one chain in their order (section 5.5); one result for each
    /// message, the last try of a kept one.
    pub(crate) fn receive_chain(&mut self, chain: &[Vec<u8>]) -> Vec<ChangeResult> {
        let mut results = vec![ChangeResult::Ignored; chain.len()];
        let mut changes: Vec<Option<DeviceChange>> = Vec::with_capacity(chain.len());
        let mut kept: Vec<usize> = Vec::new();
        for (index, message) in chain.iter().enumerate() {
            let result = results.get_mut(index);
            let Ok(change) = DeviceChange::decode(message) else {
                changes.push(None);
                if let Some(result) = result {
                    *result = ChangeResult::DeviceRejected;
                }
                continue;
            };
            let verdict = if !change.signature_verifies() {
                Some(ChangeResult::SignatureInvalid)
            } else if !change.device_verifies() {
                Some(ChangeResult::DeviceRejected)
            } else {
                None
            };
            if let Some(verdict) = verdict {
                changes.push(None);
                if let Some(result) = result {
                    *result = verdict;
                }
                continue;
            }
            let outcome = self.table(&change);
            if let Some(result) = result {
                *result = outcome.result();
            }
            let is_add = change.is_add();
            changes.push(Some(change));
            if outcome == Try::NotPlaced || outcome == Try::KeptRemoval {
                kept.push(index);
            } else if outcome == Try::Applied && is_add {
                self.retry_kept(&changes, &mut kept, &mut results);
            }
        }
        self.retry_kept(&changes, &mut kept, &mut results);
        results
    }

    /// Tries the kept messages again, in their order, until none of them applies.
    fn retry_kept(
        &mut self,
        changes: &[Option<DeviceChange>],
        kept: &mut Vec<usize>,
        results: &mut [ChangeResult],
    ) {
        loop {
            let mut applied = None;
            for (position, index) in kept.iter().enumerate() {
                let Some(Some(change)) = changes.get(*index) else {
                    continue;
                };
                let outcome = self.table(change);
                if let Some(result) = results.get_mut(*index) {
                    *result = outcome.result();
                }
                if outcome == Try::Applied {
                    applied = Some(position);
                    break;
                }
            }
            match applied {
                Some(position) => {
                    kept.remove(position);
                }
                None => return,
            }
        }
    }

    /// Steps 3 and 4 for a message whose signature and device verified.
    fn table(&mut self, change: &DeviceChange) -> Try {
        let signer = change.signer;
        let device = change.device;
        if self.refused.contains(&signer) {
            return Try::Refused;
        }
        let Some(own) = self.sender_of(&signer) else {
            // Step 3: an unknown signer is placed by the known device it adds.
            let vouching = if change.is_add() {
                self.sender_of(&device).filter(|i| {
                    self.senders
                        .get(*i)
                        .is_some_and(|s| s.current.contains(&device))
                })
            } else {
                None
            };
            return match vouching.and_then(|i| self.senders.get_mut(i)) {
                Some(sender) => {
                    sender.current.insert(signer);
                    Try::Applied
                }
                None => Try::NotPlaced,
            };
        };
        let Some(own_sender) = self.senders.get_mut(own) else {
            return Try::NotPlaced;
        };
        let signer_current = own_sender.current.contains(&signer);
        if own_sender.current.contains(&device) {
            if change.is_add() {
                return Try::Ignored;
            }
            if !signer_current {
                return Try::Rejected;
            }
            own_sender.current.remove(&device);
            own_sender.removed.insert(device);
            return Try::Applied;
        }
        if own_sender.removed.contains(&device) {
            return Try::Ignored;
        }
        if !change.is_add() {
            return if signer_current {
                Try::KeptRemoval
            } else {
                Try::Rejected
            };
        }
        if !signer_current {
            return Try::Rejected;
        }
        let own_has_one_key = own_sender.has_one_key();
        let other = self.sender_of(&device);
        if self.refused.contains(&device) {
            return Try::Rejected;
        }
        let Some(other) = other else {
            if let Some(own_sender) = self.senders.get_mut(own) {
                own_sender.current.insert(device);
            }
            return Try::Applied;
        };
        let Some(other_sender) = self.senders.get(other) else {
            return Try::Rejected;
        };
        if !other_sender.current.contains(&device) {
            return Try::Rejected;
        }
        if other_sender.has_one_key() {
            self.join(own, other);
            return Try::Applied;
        }
        if own_has_one_key {
            self.join(other, own);
            return Try::Applied;
        }
        Try::Rejected
    }

    /// Joins the sender at `joins` into the one at `stays` (section 5.5, joining two
    /// senders), and forgets the one that joined.
    fn join(&mut self, stays: usize, joins: usize) {
        if stays == joins || joins >= self.senders.len() {
            return;
        }
        let joining = self.senders.remove(joins);
        let stays = if joins < stays {
            stays.saturating_sub(1)
        } else {
            stays
        };
        let Some(staying) = self.senders.get_mut(stays) else {
            return;
        };
        staying.current.extend(joining.current);
        staying.removed.extend(joining.removed);
        for (id, record) in joining.records {
            let newer = staying
                .records
                .get(&id)
                .is_none_or(|kept| record.version > kept.version);
            if newer {
                staying.records.insert(id, record);
            }
        }
    }
}

/// What a member does with a `DEVICE_JOIN` (section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinAction {
    /// Ask its user whether to add the device.
    Ask,
    /// Answer with its chain, asking no one.
    SendChain,
    /// Ignore it without a report.
    Ignore,
}

/// The set of a member, as a `DEVICE_JOIN` is answered by it.
pub(crate) struct Member<'a> {
    /// The member's own key.
    pub(crate) key: &'a Key,
    /// The other current keys of its set.
    pub(crate) current: &'a BTreeSet<Key>,
    /// The removed keys of its set.
    pub(crate) removed: &'a BTreeSet<Key>,
}

/// The member's answer to the `DEVICE_JOIN` `message`, when `first` is the sender of the
/// first `DEVICE_JOIN` for this join code, if there was one.
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] for a message of another kind,
/// [`ErrorCode::SignatureInvalid`] for a message whose signature does not verify, and
/// [`ErrorCode::DeviceRejected`] for a proof that does not verify or a removed key of the
/// set.
pub(crate) fn answer_device_join(
    message: &[u8],
    member: &Member<'_>,
    first: Option<&Key>,
) -> Result<JoinAction, Error> {
    let envelope = decode_message(message)?;
    if envelope.kind != Kind::DeviceJoin {
        return Err(Error::axt(
            ErrorCode::InvalidMessage,
            format!("{} is no DEVICE_JOIN", envelope.kind.symbol()),
        ));
    }
    if !verify_live_message(message, &envelope.sender) {
        return Err(Error::axt(
            ErrorCode::SignatureInvalid,
            "the DEVICE_JOIN does not verify",
        ));
    }
    let body = decode_body(Kind::DeviceJoin, &envelope.body)?;
    let to: Key = fixed_field(&body, "to")?;
    let proof: [u8; 64] = fixed_field(&body, "proof")?;
    if &to != member.key {
        return Ok(JoinAction::Ignore);
    }
    if first.is_some_and(|first| first != &envelope.sender) {
        return Ok(JoinAction::Ignore);
    }
    let key = envelope.sender;
    let proof_verifies = verify_strict(&key, &device_add_proof_bytes(member.key, &key), &proof);
    if !proof_verifies || member.removed.contains(&key) {
        return Err(Error::axt(
            ErrorCode::DeviceRejected,
            "the proof does not verify or the key was removed",
        ));
    }
    if &key == member.key || member.current.contains(&key) {
        return Ok(JoinAction::SendChain);
    }
    Ok(JoinAction::Ask)
}

/// Whether a new device with the key `device` takes `chain`, the answer to its
/// `DEVICE_JOIN` to `member` (section 5.2, step 5).
pub(crate) fn takes_join_chain(chain: &[Vec<u8>], member: &Key, device: &Key) -> bool {
    let mut added = false;
    for message in chain {
        let Ok(change) = DeviceChange::decode(message) else {
            return false;
        };
        if !change.signature_verifies() {
            return false;
        }
        if &change.device != device {
            continue;
        }
        let Some(proof) = &change.proof else {
            return false;
        };
        if &change.signer == member && change.proof_verifies(member, proof) {
            added = true;
        }
    }
    added
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Test keys and signed messages, as `key_fixtures.dart` of the Dart library has them.

    use sha2::{Digest, Sha256};

    use super::Key;
    use crate::ed25519::{public_key_of, sign};
    use crate::envelope::{Envelope, Kind, encode_message};
    use crate::keys::SigningSeed;
    use crate::schemas::axt_schema;
    use crate::signing::{device_add_proof_bytes, signed_bytes_of_live_message};
    use crate::value::Value;

    /// A test key: its seed and its public key.
    pub(crate) struct TestKey {
        pub(crate) seed: SigningSeed,
        pub(crate) public: Key,
    }

    impl TestKey {
        /// The test key of `label`.
        pub(crate) fn named(label: &str) -> Self {
            let seed: [u8; 32] = Sha256::digest(format!("axt_protocol test key {label}")).into();
            let seed = SigningSeed::new(seed);
            let public = public_key_of(&seed);
            Self { seed, public }
        }
    }

    /// A live message of `kind` by `signer` with `body`, signed.
    pub(crate) fn signed_message(signer: &TestKey, kind: Kind, body: Vec<u8>) -> Vec<u8> {
        let mut message = encode_message(&Envelope {
            kind,
            sender: signer.public,
            record: None,
            body,
            signature: [0; 64],
        })
        .unwrap();
        let signature = sign(
            &signer.seed,
            &signed_bytes_of_live_message(&message).unwrap(),
        );
        let end = message.len() - 64;
        message[end..].copy_from_slice(&signature);
        message
    }

    fn body(schema: &str, fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
        let value = Value::Record(
            fields
                .into_iter()
                .map(|(name, bytes)| (name.to_owned(), Value::Fixed(bytes)))
                .collect(),
        );
        axt_schema(schema)
            .unwrap()
            .encode_single_object(&value)
            .unwrap()
    }

    /// The proof of `device` for its addition by `member`.
    pub(crate) fn proof_of(device: &TestKey, member: &TestKey) -> [u8; 64] {
        sign(
            &device.seed,
            &device_add_proof_bytes(&member.public, &device.public),
        )
    }

    /// A `DEVICE_ADD` of `device` by `member`, with the device's proof, or with `proof`
    /// and `device_key` in their places.
    pub(crate) fn device_add_with(
        member: &TestKey,
        device: &TestKey,
        proof: Option<[u8; 64]>,
        device_key: Option<Key>,
    ) -> Vec<u8> {
        let proof = proof.unwrap_or_else(|| proof_of(device, member));
        signed_message(
            member,
            Kind::DeviceAdd,
            body(
                "axt.DeviceAdd",
                vec![
                    ("device", device_key.unwrap_or(device.public).to_vec()),
                    ("proof", proof.to_vec()),
                ],
            ),
        )
    }

    /// A `DEVICE_ADD` of `device` by `member`.
    pub(crate) fn device_add(member: &TestKey, device: &TestKey) -> Vec<u8> {
        device_add_with(member, device, None, None)
    }

    /// A `DEVICE_REMOVE` of `device` by `signer`.
    pub(crate) fn device_remove(signer: &TestKey, device: &TestKey) -> Vec<u8> {
        signed_message(
            signer,
            Kind::DeviceRemove,
            body("axt.DeviceRemove", vec![("device", device.public.to_vec())]),
        )
    }

    /// A `DEVICE_JOIN` of `device` to `to`, with its proof or `proof`.
    pub(crate) fn device_join(device: &TestKey, to: &TestKey, proof: Option<[u8; 64]>) -> Vec<u8> {
        let proof = proof.unwrap_or_else(|| proof_of(device, to));
        signed_message(
            device,
            Kind::DeviceJoin,
            body(
                "axt.DeviceJoin",
                vec![("to", to.public.to_vec()), ("proof", proof.to_vec())],
            ),
        )
    }

    /// A signed `DELETE`, a message of another kind.
    pub(crate) fn delete(signer: &TestKey) -> Vec<u8> {
        signed_message(signer, Kind::Delete, Vec::new())
    }

    /// `message` with one byte of its signature changed.
    pub(crate) fn tampered(mut message: Vec<u8>) -> Vec<u8> {
        if let Some(last) = message.last_mut() {
            *last ^= 1;
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    struct Keys {
        a: TestKey,
        b: TestKey,
        c: TestKey,
        d: TestKey,
        e: TestKey,
    }

    fn keys() -> Keys {
        Keys {
            a: TestKey::named("a"),
            b: TestKey::named("b"),
            c: TestKey::named("c"),
            d: TestKey::named("d"),
            e: TestKey::named("e"),
        }
    }

    fn sender(name: &str, current: &[&TestKey], removed: &[&TestKey]) -> KnownSender {
        KnownSender {
            name: name.into(),
            current: current.iter().map(|k| k.public).collect(),
            removed: removed.iter().map(|k| k.public).collect(),
            records: BTreeMap::new(),
        }
    }

    fn receiver(senders: Vec<KnownSender>) -> DeviceSetReceiver {
        DeviceSetReceiver {
            senders,
            refused: BTreeSet::new(),
        }
    }

    fn codes(receiver: &mut DeviceSetReceiver, chain: Vec<Vec<u8>>) -> Vec<&'static str> {
        receiver
            .receive_chain(&chain)
            .into_iter()
            .map(ChangeResult::code)
            .collect()
    }

    #[test]
    fn adds_repeats_removes_and_rejects_what_a_removed_key_signs() {
        let Keys { a, b, c, e, .. } = keys();
        let mut r = receiver(vec![sender("s", &[&a], &[])]);
        let chain = vec![
            device_add(&a, &b),
            device_add(&a, &b),
            device_remove(&a, &b),
            device_add(&a, &b),
            device_remove(&b, &a),
            device_remove(&b, &b),
            device_remove(&a, &b),
            device_add(&b, &c),
        ];
        assert_eq!(
            codes(&mut r, chain),
            [
                "APPLIED",
                "IGNORED",
                "APPLIED",
                "IGNORED",
                "DEVICE_REJECTED",
                "DEVICE_REJECTED",
                "IGNORED",
                "DEVICE_REJECTED",
            ]
        );
        assert_eq!(r.state_of(&b.public), KeyState::Removed);
        assert_eq!(r.state_of(&a.public), KeyState::Current);
        assert_eq!(r.current_sender_of(&a.public).unwrap().name, "s");
        assert!(r.current_sender_of(&b.public).is_none());
        assert_eq!(r.state_of(&e.public), KeyState::Unknown);
    }

    #[test]
    fn a_removal_by_a_removed_key_of_a_key_it_does_not_have() {
        let Keys { a, b, c, .. } = keys();
        let mut r = receiver(vec![sender("s", &[&a], &[&b])]);
        assert_eq!(
            codes(&mut r, vec![device_remove(&b, &c)]),
            ["DEVICE_REJECTED"]
        );
    }

    #[test]
    fn joins_a_sender_of_one_key_into_the_signer_keeping_records() {
        let Keys { a, c, .. } = keys();
        let mut s = sender("s", &[&a], &[]);
        s.records.insert(
            "r1".into(),
            KeptRecord {
                version: 2,
                state: RecordState::There,
            },
        );
        let mut t = sender("t", &[&c], &[]);
        t.records.insert(
            "r1".into(),
            KeptRecord {
                version: 3,
                state: RecordState::Tombstone,
            },
        );
        t.records.insert(
            "r2".into(),
            KeptRecord {
                version: 1,
                state: RecordState::There,
            },
        );
        let mut r = receiver(vec![s, t]);
        assert_eq!(codes(&mut r, vec![device_add(&a, &c)]), ["APPLIED"]);
        assert_eq!(r.senders.len(), 1);
        assert_eq!(r.senders[0].name, "s");
        assert_eq!(r.senders[0].records["r1"].version, 3);
        assert_eq!(r.senders[0].records["r1"].state, RecordState::Tombstone);
        assert_eq!(r.senders[0].records["r2"].version, 1);
    }

    #[test]
    fn joins_the_signer_of_one_key_into_a_device_with_further_keys() {
        let Keys { a, b, c, .. } = keys();
        let mut r = receiver(vec![sender("s", &[&a, &b], &[]), sender("t", &[&c], &[])]);
        assert_eq!(codes(&mut r, vec![device_add(&c, &a)]), ["APPLIED"]);
        assert_eq!(r.senders.len(), 1);
        assert_eq!(r.senders[0].name, "s");
        assert_eq!(r.senders[0].current.len(), 3);
    }

    #[test]
    fn rejects_joining_two_senders_that_each_have_more_keys() {
        let Keys { a, b, c, d, .. } = keys();
        let mut r = receiver(vec![
            sender("s", &[&a, &b], &[]),
            sender("t", &[&c, &d], &[]),
        ]);
        assert_eq!(codes(&mut r, vec![device_add(&a, &c)]), ["DEVICE_REJECTED"]);
        let mut removed = receiver(vec![sender("s", &[&a], &[]), sender("t", &[&d], &[&c])]);
        assert_eq!(
            codes(&mut removed, vec![device_add(&a, &c)]),
            ["DEVICE_REJECTED"]
        );
    }

    #[test]
    fn refused_signers_and_devices() {
        let Keys { a, b, c, d, .. } = keys();
        let mut r = receiver(vec![sender("s", &[&a], &[])]);
        r.refused = [b.public, c.public].into();
        assert_eq!(
            codes(&mut r, vec![device_add(&b, &d), device_add(&a, &c)]),
            ["REFUSED", "DEVICE_REJECTED"]
        );
        assert_eq!(r.state_of(&b.public), KeyState::Refused);
    }

    #[test]
    fn an_unknown_signer_added_by_the_device_it_vouches_for() {
        let Keys { a, b, .. } = keys();
        let mut r = receiver(vec![sender("s", &[&a], &[])]);
        assert_eq!(codes(&mut r, vec![device_add(&b, &a)]), ["APPLIED"]);
        assert_eq!(r.current_sender_of(&b.public).unwrap().name, "s");
    }

    #[test]
    fn keeps_what_it_cannot_place_and_tries_it_again() {
        let Keys { a, b, c, d, e } = keys();
        let mut r = receiver(vec![sender("s", &[&a], &[])]);
        let chain = vec![
            device_add(&b, &c),
            device_remove(&a, &d),
            device_remove(&e, &d),
            device_add(&a, &b),
            device_add(&a, &d),
        ];
        assert_eq!(
            codes(&mut r, chain),
            ["APPLIED", "APPLIED", "NOT_PLACED", "APPLIED", "APPLIED"]
        );
        assert_eq!(r.state_of(&c.public), KeyState::Current);
        assert_eq!(r.state_of(&d.public), KeyState::Removed);
        let mut later = receiver(vec![sender("s", &[&a], &[])]);
        assert_eq!(codes(&mut later, vec![device_remove(&a, &e)]), ["IGNORED"]);
    }

    #[test]
    fn bad_signatures_bad_proofs_bad_keys_and_other_kinds() {
        let Keys { a, b, .. } = keys();
        let mut r = receiver(vec![sender("s", &[&a], &[])]);
        let chain = vec![
            tampered(device_add(&a, &b)),
            device_add_with(&a, &b, Some([0; 64]), None),
            device_add_with(&a, &b, None, Some([0; 32])),
            delete(&a),
        ];
        assert_eq!(
            codes(&mut r, chain),
            [
                "SIGNATURE_INVALID",
                "DEVICE_REJECTED",
                "DEVICE_REJECTED",
                "DEVICE_REJECTED",
            ]
        );
    }

    #[test]
    fn a_member_answers_a_device_join() {
        let Keys { a, b, c, .. } = keys();
        let none = BTreeSet::new();
        let with_b: BTreeSet<Key> = [b.public].into();
        let answer = |message: Vec<u8>,
                      current: &BTreeSet<Key>,
                      removed: &BTreeSet<Key>,
                      first: Option<&Key>| {
            let member = Member {
                key: &a.public,
                current,
                removed,
            };
            answer_device_join(&message, &member, first)
        };
        let code = |r: Result<JoinAction, Error>| r.unwrap_err().code().unwrap();
        assert_eq!(
            answer(device_join(&b, &a, None), &none, &none, None).unwrap(),
            JoinAction::Ask
        );
        assert_eq!(
            answer(device_join(&b, &c, None), &none, &none, None).unwrap(),
            JoinAction::Ignore
        );
        assert_eq!(
            answer(device_join(&b, &a, None), &none, &none, Some(&c.public)).unwrap(),
            JoinAction::Ignore
        );
        assert_eq!(
            answer(device_join(&b, &a, None), &none, &none, Some(&b.public)).unwrap(),
            JoinAction::Ask
        );
        assert_eq!(
            answer(device_join(&b, &a, None), &with_b, &none, None).unwrap(),
            JoinAction::SendChain
        );
        assert_eq!(
            answer(device_join(&a, &a, None), &none, &none, None).unwrap(),
            JoinAction::SendChain
        );
        assert_eq!(
            code(answer(device_join(&b, &a, None), &none, &with_b, None)),
            ErrorCode::DeviceRejected
        );
        assert_eq!(
            code(answer(
                device_join(&b, &a, Some([0; 64])),
                &none,
                &none,
                None
            )),
            ErrorCode::DeviceRejected
        );
        assert_eq!(
            code(answer(
                tampered(device_join(&b, &a, None)),
                &none,
                &none,
                None
            )),
            ErrorCode::SignatureInvalid
        );
        assert_eq!(
            code(answer(device_add(&a, &b), &none, &none, None)),
            ErrorCode::InvalidMessage
        );
    }

    #[test]
    fn a_new_device_takes_the_chain_that_adds_it() {
        let Keys { a, b, c, .. } = keys();
        let takes = |chain: Vec<Vec<u8>>| takes_join_chain(&chain, &a.public, &b.public);
        assert!(takes(vec![device_add(&a, &c), device_add(&a, &b)]));
        assert!(!takes(vec![device_add(&c, &b)]));
        assert!(!takes(vec![device_add_with(
            &a,
            &b,
            Some(proof_of(&b, &c)),
            None
        )]));
        assert!(!takes(vec![device_add(&a, &b), device_remove(&c, &b)]));
        assert!(!takes(vec![tampered(device_add(&a, &b))]));
        assert!(!takes(vec![delete(&a)]));
        assert!(!takes(vec![]));
    }

    #[test]
    fn a_device_change_decodes_additions_and_removals_only() {
        let Keys { a, b, .. } = keys();
        let change = DeviceChange::decode(&device_remove(&a, &b)).unwrap();
        assert_eq!(change.kind, Kind::DeviceRemove);
        assert!(change.proof.is_none());
        assert_eq!(
            DeviceChange::decode(&delete(&a))
                .err()
                .and_then(|e| e.code()),
            Some(ErrorCode::InvalidMessage)
        );
    }
}
