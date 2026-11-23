//! The AXT envelope of format 1 and the bodies of its kinds (AXT `spec/envelope.md`,
//! sections 2, 3 and 5).

use crate::error::{Error, ErrorCode};
use crate::schema::{Fingerprint, Schema};
use crate::schemas::axt_schema;
use crate::value::Value;

/// The largest live message, 16 MiB, its single-object header included (the limit
/// `envelope.message`; `spec/envelope.md`, section 8).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// The envelope format this library reads and writes.
pub const ENVELOPE_FORMAT: i32 = 1;

/// What a message is, and so which schema its body has (section 2.2).
///
/// The order is that of the symbols of `axt.Kind`: the position is the value in the
/// binary encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `MANIFEST`.
    Manifest,
    /// `OFFER`.
    Offer,
    /// `ACCEPT`.
    Accept,
    /// `DECLINE`.
    Decline,
    /// `DATA`.
    Data,
    /// `DELETE`.
    Delete,
    /// `ACK`.
    Ack,
    /// `ERROR`.
    Error,
    /// `DEVICE_JOIN`.
    DeviceJoin,
    /// `DEVICE_ADD`.
    DeviceAdd,
    /// `DEVICE_REMOVE`.
    DeviceRemove,
    /// `CHANGE`.
    Change,
    /// `RESYNC`.
    Resync,
    /// `FORWARD`.
    Forward,
    /// `WITHDRAW`.
    Withdraw,
    /// `PROPOSAL`.
    Proposal,
    /// `PROPOSAL_REPLY`.
    ProposalReply,
}

impl Kind {
    /// Every kind, in the order of the symbols of `axt.Kind`.
    pub const ALL: [Self; 17] = [
        Self::Manifest,
        Self::Offer,
        Self::Accept,
        Self::Decline,
        Self::Data,
        Self::Delete,
        Self::Ack,
        Self::Error,
        Self::DeviceJoin,
        Self::DeviceAdd,
        Self::DeviceRemove,
        Self::Change,
        Self::Resync,
        Self::Forward,
        Self::Withdraw,
        Self::Proposal,
        Self::ProposalReply,
    ];

    /// The symbol of `axt.Kind`, such as `DEVICE_ADD`.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Manifest => "MANIFEST",
            Self::Offer => "OFFER",
            Self::Accept => "ACCEPT",
            Self::Decline => "DECLINE",
            Self::Data => "DATA",
            Self::Delete => "DELETE",
            Self::Ack => "ACK",
            Self::Error => "ERROR",
            Self::DeviceJoin => "DEVICE_JOIN",
            Self::DeviceAdd => "DEVICE_ADD",
            Self::DeviceRemove => "DEVICE_REMOVE",
            Self::Change => "CHANGE",
            Self::Resync => "RESYNC",
            Self::Forward => "FORWARD",
            Self::Withdraw => "WITHDRAW",
            Self::Proposal => "PROPOSAL",
            Self::ProposalReply => "PROPOSAL_REPLY",
        }
    }

    /// The full name of the body's schema of format 1; `None` for `DATA`, whose body has
    /// the record type's offered schema, and for `DELETE`, whose body is empty.
    #[must_use]
    pub const fn body_schema(self) -> Option<&'static str> {
        match self {
            Self::Manifest => Some("axt.Manifest"),
            Self::Offer => Some("axt.Offer"),
            Self::Accept => Some("axt.Accept"),
            Self::Decline => Some("axt.Decline"),
            Self::Data | Self::Delete => None,
            Self::Ack => Some("axt.Ack"),
            Self::Error => Some("axt.Error"),
            Self::DeviceJoin => Some("axt.DeviceJoin"),
            Self::DeviceAdd => Some("axt.DeviceAdd"),
            Self::DeviceRemove => Some("axt.DeviceRemove"),
            Self::Change => Some("axt.Change"),
            Self::Resync => Some("axt.Resync"),
            Self::Forward => Some("axt.Forward"),
            Self::Withdraw => Some("axt.Withdraw"),
            Self::Proposal => Some("axt.Proposal"),
            Self::ProposalReply => Some("axt.ProposalReply"),
        }
    }

    /// The kind of `symbol`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidMessage`] for a symbol that format 1 does not have.
    pub fn from_symbol(symbol: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.symbol() == symbol)
            .ok_or_else(|| Error::axt(ErrorCode::InvalidMessage, format!("no kind {symbol}")))
    }
}

/// The record a message is about: its id and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRef {
    /// The record's id, as received: a UUID text, not checked here.
    pub id: String,
    /// The record's version.
    pub version: i64,
}

/// One AXT message of envelope format 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// What the message is.
    pub kind: Kind,
    /// The Ed25519 public key of the sending device.
    pub sender: [u8; 32],
    /// The record the message is about, if any.
    pub record: Option<RecordRef>,
    /// Empty, or one datum in single-object encoding.
    pub body: Vec<u8>,
    /// The sender's Ed25519 signature.
    pub signature: [u8; 64],
}

/// The envelope schema of format 1.
fn envelope_schema() -> Result<&'static Schema, Error> {
    axt_schema("axt.Envelope")
        .ok_or_else(|| Error::axt(ErrorCode::InvalidMessage, "the envelope schema is missing"))
}

/// The CRC-64-AVRO fingerprint of the envelope schema of format 1, the first bytes
/// after the marker of every live message (section 3.1).
///
/// # Errors
///
/// Never for the embedded schema; [`ErrorCode::InvalidMessage`] if it were missing.
pub fn envelope_fingerprint() -> Result<Fingerprint, Error> {
    envelope_schema().map(Schema::fingerprint)
}

/// A rejection of a message as `INVALID_MESSAGE`.
fn invalid(message: impl Into<String>) -> Error {
    Error::axt(ErrorCode::InvalidMessage, message)
}

/// Decodes a live message: the marker, the envelope fingerprint and the envelope
/// (sections 2 and 3). Checks only the envelope, not the signature and not the body.
///
/// # Errors
///
/// [`ErrorCode::TooLarge`] above [`MAX_MESSAGE_BYTES`], [`ErrorCode::FormatUnsupported`]
/// for an envelope fingerprint of no format this library reads, and
/// [`ErrorCode::InvalidMessage`] for anything else that is not an envelope of format 1
/// with no bytes left over.
pub fn decode_message(message: &[u8]) -> Result<Envelope, Error> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(Error::axt(
            ErrorCode::TooLarge,
            format!("{} bytes, the limit is {MAX_MESSAGE_BYTES}", message.len()),
        ));
    }
    let schema = envelope_schema()?;
    match crate::avro::split_single_object(message) {
        None => return Err(invalid("no single-object encoding")),
        Some((fingerprint, _)) if fingerprint != schema.fingerprint().0 => {
            return Err(Error::axt(
                ErrorCode::FormatUnsupported,
                "the envelope fingerprint is of no format this library reads",
            ));
        }
        Some(_) => {}
    }
    let value = schema.decode_single_object(message).map_err(invalid)?;
    envelope_of(&value)
}

/// The envelope of a decoded `axt.Envelope`.
fn envelope_of(value: &Value) -> Result<Envelope, Error> {
    let field = |name: &str| {
        value
            .field(name)
            .ok_or_else(|| invalid(format!("no field {name}")))
    };
    match field("format")? {
        Value::Int(ENVELOPE_FORMAT) => {}
        other => {
            return Err(invalid(format!(
                "format {other:?} under the fingerprint of format 1"
            )));
        }
    }
    let kind = match field("kind")? {
        Value::Enum { symbol, .. } => Kind::from_symbol(symbol)?,
        _ => return Err(invalid("the kind is no enum")),
    };
    let record = match field("record")? {
        Value::Null => None,
        record @ Value::Record(_) => match (record.field("id"), record.field("version")) {
            (Some(Value::String(id)), Some(Value::Long(version))) => Some(RecordRef {
                id: id.clone(),
                version: *version,
            }),
            _ => return Err(invalid("the record is no id and version")),
        },
        _ => return Err(invalid("the record is neither null nor a record")),
    };
    let body = match field("body")? {
        Value::Bytes(body) => body.clone(),
        _ => return Err(invalid("the body is no bytes")),
    };
    Ok(Envelope {
        kind,
        sender: fixed(field("sender")?)?,
        record,
        body,
        signature: fixed(field("signature")?)?,
    })
}

/// The bytes of a fixed of `N` bytes.
fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], Error> {
    match value {
        Value::Fixed(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid(format!("a fixed of {} bytes, not {N}", bytes.len()))),
        _ => Err(invalid("no fixed")),
    }
}

/// Encodes `envelope` as a live message (section 3).
///
/// # Errors
///
/// Never for the embedded envelope schema; [`ErrorCode::InvalidMessage`] if it did not
/// take the envelope.
pub fn encode_message(envelope: &Envelope) -> Result<Vec<u8>, Error> {
    let record = match &envelope.record {
        None => Value::Null,
        Some(r) => Value::Record(vec![
            ("id".into(), Value::String(r.id.clone())),
            ("version".into(), Value::Long(r.version)),
        ]),
    };
    let kind = envelope.kind;
    let value = Value::Record(vec![
        ("format".into(), Value::Int(ENVELOPE_FORMAT)),
        (
            "kind".into(),
            Value::Enum {
                index: kind as u32,
                symbol: kind.symbol().into(),
            },
        ),
        ("sender".into(), Value::Fixed(envelope.sender.to_vec())),
        ("record".into(), record),
        ("body".into(), Value::Bytes(envelope.body.clone())),
        (
            "signature".into(),
            Value::Fixed(envelope.signature.to_vec()),
        ),
    ]);
    envelope_schema()?
        .encode_single_object(&value)
        .map_err(invalid)
}

/// Decodes the body of a message of `kind` with its kind's schema of format 1, to
/// values of the underlying types (section 2.3).
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] for a body that is not a complete single-object
/// encoding of that schema, and for `DATA` and `DELETE`, which have no schema of the
/// specification.
pub fn decode_body(kind: Kind, body: &[u8]) -> Result<Value, Error> {
    let name = kind
        .body_schema()
        .ok_or_else(|| invalid(format!("{} has no body schema", kind.symbol())))?;
    let schema =
        axt_schema(name).ok_or_else(|| invalid(format!("the schema {name} is missing")))?;
    schema.decode_single_object(body).map_err(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    // The DELETE of the AXT 0.1.0 vector encoding/decode_message/a-delete-with-an-empty-body.
    const DELETE_HEX: &str = concat!(
        "c30116306f71b9ce9ea8020a1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471c",
        "ce6410d53c26ec4a024864346333623261312d306639652d346438632d623761362d3566",
        "346533643263316230610800ea32efa326af397ee5c8f40a8c3e7ad77009210de20c6005",
        "6ee1dd1e6eb27f8dad916c2bf409d553a5b49f71004497a56771ce21ea19f5a5986aaf49",
        "ec1f5e09",
    );

    fn code(result: Result<impl std::fmt::Debug, Error>) -> ErrorCode {
        result.unwrap_err().code().unwrap()
    }

    #[test]
    fn reads_the_envelope_of_a_delete() {
        let envelope = decode_message(&unhex(DELETE_HEX)).unwrap();
        assert_eq!(envelope.kind, Kind::Delete);
        let record = envelope.record.unwrap();
        assert_eq!(record.id, "d4c3b2a1-0f9e-4d8c-b7a6-5f4e3d2c1b0a");
        assert_eq!(record.version, 4);
        assert!(envelope.body.is_empty());
    }

    #[test]
    fn encodes_it_back_to_the_same_bytes() {
        let bytes = unhex(DELETE_HEX);
        assert_eq!(
            encode_message(&decode_message(&bytes).unwrap()).unwrap(),
            bytes
        );
    }

    #[test]
    fn keeps_a_record_id_that_is_no_uuid_as_received() {
        let mut envelope = decode_message(&unhex(DELETE_HEX)).unwrap();
        envelope.record = Some(RecordRef {
            id: "NOT-A-UUID".into(),
            version: 4,
        });
        let again = decode_message(&encode_message(&envelope).unwrap()).unwrap();
        assert_eq!(again.record.unwrap().id, "NOT-A-UUID");
    }

    #[test]
    fn encodes_and_reads_a_message_without_a_record() {
        let envelope = Envelope {
            kind: Kind::Manifest,
            sender: [0; 32],
            record: None,
            body: Vec::new(),
            signature: [0; 64],
        };
        let again = decode_message(&encode_message(&envelope).unwrap()).unwrap();
        assert_eq!(again, envelope);
    }

    #[test]
    fn rejects_a_message_above_16_mib_as_too_large() {
        let bytes = vec![0; MAX_MESSAGE_BYTES + 1];
        assert_eq!(code(decode_message(&bytes)), ErrorCode::TooLarge);
    }

    #[test]
    fn rejects_another_envelope_fingerprint_as_format_unsupported() {
        let mut bytes = unhex(DELETE_HEX);
        bytes[2] ^= 1;
        assert_eq!(code(decode_message(&bytes)), ErrorCode::FormatUnsupported);
    }

    #[test]
    fn rejects_what_is_no_envelope_as_invalid_message() {
        let bytes = unhex(DELETE_HEX);
        let mut no_marker = bytes.clone();
        no_marker[0] = 0;
        let mut left_over = bytes.clone();
        left_over.push(0);
        let cut = &bytes[..bytes.len() - 1];
        let mut format_2 = bytes.clone();
        format_2[10] = 4;
        let mut kind_17 = bytes.clone();
        kind_17[11] = 34;
        for bad in [
            &no_marker[..],
            &bytes[..9],
            &left_over,
            cut,
            &format_2,
            &kind_17,
        ] {
            assert_eq!(code(decode_message(bad)), ErrorCode::InvalidMessage);
        }
    }

    #[test]
    fn every_kind_reads_back_from_its_symbol() {
        for kind in Kind::ALL {
            assert_eq!(Kind::from_symbol(kind.symbol()).unwrap(), kind);
        }
        assert_eq!(
            code(Kind::from_symbol("NOTHING")),
            ErrorCode::InvalidMessage
        );
    }

    #[test]
    fn decodes_a_body_of_its_kind_only() {
        // The body of a RESYNC: the fixed `to` of 32 bytes.
        let schema = axt_schema("axt.Resync").unwrap();
        let body = schema
            .encode_single_object(&Value::Record(vec![(
                "to".into(),
                Value::Fixed(vec![7; 32]),
            )]))
            .unwrap();
        let value = decode_body(Kind::Resync, &body).unwrap();
        assert_eq!(value.field("to"), Some(&Value::Fixed(vec![7; 32])));
        assert_eq!(
            code(decode_body(Kind::Withdraw, &body)),
            ErrorCode::InvalidMessage
        );
        assert_eq!(
            code(decode_body(Kind::Resync, &[])),
            ErrorCode::InvalidMessage
        );
        assert_eq!(
            code(decode_body(Kind::Data, &body)),
            ErrorCode::InvalidMessage
        );
        let mut left_over = body.clone();
        left_over.push(0);
        assert_eq!(
            code(decode_body(Kind::Resync, &left_over)),
            ErrorCode::InvalidMessage
        );
    }

    #[test]
    fn reads_a_withdraw_body() {
        let body = unhex(concat!(
            "c301d57da92315f555e3da9e54c9aa2db43244df99889d9138c1ca7175d4ca0908168f",
            "63530e4a7dedb7",
        ));
        let value = decode_body(Kind::Withdraw, &body).unwrap();
        match value.field("to") {
            Some(Value::Fixed(to)) => assert_eq!(to.len(), 32),
            other => panic!("no key: {other:?}"),
        }
    }

    #[test]
    fn every_kind_has_the_symbol_of_axt_kind_at_its_index() {
        let symbols: Vec<String> = Kind::ALL
            .iter()
            .map(|k| format!("\"{}\"", k.symbol()))
            .collect();
        let expected = format!("\"symbols\":[{}]", symbols.join(","));
        assert!(
            envelope_schema()
                .unwrap()
                .canonical_form()
                .contains(&expected)
        );
    }

    #[test]
    fn the_envelope_fingerprint_is_that_of_format_1() {
        assert_eq!(
            envelope_fingerprint().unwrap().to_string(),
            "16306f71b9ce9ea8"
        );
    }
}
