//! The errors of AXT (`spec/protocol.md`, section 8.2, and `spec/conformance.md`,
//! section 4.2).

use std::fmt;

/// An error code of AXT, as the specification names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `TOO_LARGE`: above a limit of the specification.
    TooLarge,
    /// `FORMAT_UNSUPPORTED`: an envelope format the library does not read.
    FormatUnsupported,
    /// `INVALID_MESSAGE`: not a well-formed message.
    InvalidMessage,
    /// `SCHEMA_UNKNOWN`: a `DATA` whose body fingerprint is of no current offer.
    SchemaUnknown,
    /// `DOES_NOT_RESOLVE`: a schema that does not resolve (`spec/envelope.md`, section 6).
    DoesNotResolve,
    /// `UNDECODABLE`: a `DATA` whose body does not decode with its offered schema.
    Undecodable,
    /// `VALUE_INVALID`: a value that breaks a check of its field.
    ValueInvalid,
    /// `SIGNATURE_INVALID`: a signature that does not verify.
    SignatureInvalid,
    /// `KEY_INVALID`: an Ed25519 public key that fails the strict verification.
    KeyInvalid,
    /// `ENCRYPTION_KEY_INVALID`: an X25519 public key of small order.
    EncryptionKeyInvalid,
    /// `NOT_OPENED`: a sealed message that no private key opens.
    NotOpened,
    /// `PADDING_INVALID`: an opened plaintext with a broken padding.
    PaddingInvalid,
    /// `DEVICE_REJECTED`: a device change that is not taken.
    DeviceRejected,
    /// `JOIN_INVALID`: a chain that a new device does not take.
    JoinInvalid,
    /// `MANIFEST_INVALID`: a manifest that breaks a rule.
    ManifestInvalid,
    /// `RECORD_ID_INVALID`: a record id that is not valid.
    RecordIdInvalid,
    /// `VERSION_INVALID`: a record version that is not valid.
    VersionInvalid,
    /// `TYPE_CHANGED`: a record whose type changed.
    TypeChanged,
    /// `DESCRIPTION_INVALID`: a type description that is not valid.
    DescriptionInvalid,
    /// `FILE_REJECTED`: a file rejected as a whole.
    FileRejected,
    /// `OFFER_INVALID`: an offer that breaks a rule.
    OfferInvalid,
    /// `NOT_ACCEPTED`: a record of a type the receiver did not accept.
    NotAccepted,
    /// `PROPOSALS_NOT_TAKEN`: a `PROPOSAL` for a record whose sender takes none from the proposer.
    ProposalsNotTaken,
}

impl ErrorCode {
    /// Every code, in the order of the specification.
    pub const ALL: [Self; 23] = [
        Self::TooLarge,
        Self::FormatUnsupported,
        Self::InvalidMessage,
        Self::SchemaUnknown,
        Self::DoesNotResolve,
        Self::Undecodable,
        Self::ValueInvalid,
        Self::SignatureInvalid,
        Self::KeyInvalid,
        Self::EncryptionKeyInvalid,
        Self::NotOpened,
        Self::PaddingInvalid,
        Self::DeviceRejected,
        Self::JoinInvalid,
        Self::ManifestInvalid,
        Self::RecordIdInvalid,
        Self::VersionInvalid,
        Self::TypeChanged,
        Self::DescriptionInvalid,
        Self::FileRejected,
        Self::OfferInvalid,
        Self::NotAccepted,
        Self::ProposalsNotTaken,
    ];

    /// The code as the specification writes it, such as `INVALID_MESSAGE`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "TOO_LARGE",
            Self::FormatUnsupported => "FORMAT_UNSUPPORTED",
            Self::InvalidMessage => "INVALID_MESSAGE",
            Self::SchemaUnknown => "SCHEMA_UNKNOWN",
            Self::DoesNotResolve => "DOES_NOT_RESOLVE",
            Self::Undecodable => "UNDECODABLE",
            Self::ValueInvalid => "VALUE_INVALID",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::KeyInvalid => "KEY_INVALID",
            Self::EncryptionKeyInvalid => "ENCRYPTION_KEY_INVALID",
            Self::NotOpened => "NOT_OPENED",
            Self::PaddingInvalid => "PADDING_INVALID",
            Self::DeviceRejected => "DEVICE_REJECTED",
            Self::JoinInvalid => "JOIN_INVALID",
            Self::ManifestInvalid => "MANIFEST_INVALID",
            Self::RecordIdInvalid => "RECORD_ID_INVALID",
            Self::VersionInvalid => "VERSION_INVALID",
            Self::TypeChanged => "TYPE_CHANGED",
            Self::DescriptionInvalid => "DESCRIPTION_INVALID",
            Self::FileRejected => "FILE_REJECTED",
            Self::OfferInvalid => "OFFER_INVALID",
            Self::NotAccepted => "NOT_ACCEPTED",
            Self::ProposalsNotTaken => "PROPOSALS_NOT_TAKEN",
        }
    }

    /// The code the specification writes as `text`, if there is one.
    #[must_use]
    pub fn from_name(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == text)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error of the library.
#[derive(Debug)]
pub enum Error {
    /// A rejection with an AXT error code.
    Axt {
        /// Why AXT rejects it.
        code: ErrorCode,
        /// What went wrong, in words.
        message: String,
        /// For `VALUE_INVALID`: the field path of the value (`spec/metadata.md`,
        /// section 7.2), or `None` for a path above the limit `protocol.error_field`.
        field: Option<String>,
    },
    /// A failure of the app's store, passed through unchanged.
    Store(Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    /// A rejection with `code` and no field path.
    #[must_use]
    pub fn axt(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Axt {
            code,
            message: message.into(),
            field: None,
        }
    }

    /// The AXT error code, or `None` for a failure of the store.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Axt { code, .. } => Some(*code),
            Self::Store(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Axt {
                code,
                message,
                field: Some(field),
            } => write!(f, "{code} at {field}: {message}"),
            Self::Axt { code, message, .. } => write!(f, "{code}: {message}"),
            Self::Store(e) => write!(f, "the store failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Axt { .. } => None,
            Self::Store(e) => Some(e.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_reads_back_from_its_name() {
        for code in ErrorCode::ALL {
            assert_eq!(ErrorCode::from_name(code.as_str()), Some(code));
        }
        assert_eq!(ErrorCode::from_name("QR_INVALID"), None);
    }

    #[test]
    fn the_codes_are_those_of_the_specification() {
        let names: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), 23);
        assert_eq!(names[0], "TOO_LARGE");
        assert_eq!(names[22], "PROPOSALS_NOT_TAKEN");
    }

    #[test]
    fn a_store_failure_has_no_code() {
        let e = Error::Store("disk full".into());
        assert_eq!(e.code(), None);
        assert_eq!(e.to_string(), "the store failed: disk full");
        let e = Error::axt(ErrorCode::InvalidMessage, "cut short");
        assert_eq!(e.code(), Some(ErrorCode::InvalidMessage));
        assert_eq!(e.to_string(), "INVALID_MESSAGE: cut short");
    }
}
