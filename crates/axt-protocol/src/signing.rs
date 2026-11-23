//! The signatures of messages and of added devices, and the short fingerprint (AXT
//! `spec/keys.md`, sections 2.2, 3.1 and 5.2).

use sha2::{Digest, Sha256};

use crate::ed25519::verify_strict;

/// The prefix of the signed bytes of a message: `AXT-v1 message` and a zero byte.
const MESSAGE_PREFIX: &[u8] = b"AXT-v1 message\0";

/// The prefix of the proof of an added device: `AXT-v1 device add` and a zero byte.
const DEVICE_ADD_PREFIX: &[u8] = b"AXT-v1 device add\0";

/// The prefix of the hash of a short fingerprint: `AXT-v1 fingerprint` and a zero byte.
const FINGERPRINT_PREFIX: &[u8] = b"AXT-v1 fingerprint\0";

/// The length of the single-object marker and the envelope fingerprint of a live message.
const LIVE_HEADER: usize = 10;

/// The length of a signature, the last bytes of every envelope.
const SIGNATURE_LENGTH: usize = 64;

/// The bytes the signature of the live message `message` covers: the prefix and the
/// envelope without its last 64 bytes, as received; `None` for a message too short to
/// hold an envelope.
pub(crate) fn signed_bytes_of_live_message(message: &[u8]) -> Option<Vec<u8>> {
    let end = message.len().checked_sub(SIGNATURE_LENGTH)?;
    let envelope = message.get(LIVE_HEADER..end)?;
    Some([MESSAGE_PREFIX, envelope].concat())
}

/// Whether the live message `message`, of `sender`, carries a signature that verifies by
/// the strict rule over the bytes as received.
pub(crate) fn verify_live_message(message: &[u8], sender: &[u8; 32]) -> bool {
    let Some(signed) = signed_bytes_of_live_message(message) else {
        return false;
    };
    let Some((_, signature)) = message.split_last_chunk::<SIGNATURE_LENGTH>() else {
        return false;
    };
    verify_strict(sender, &signed, signature)
}

/// The bytes the proof of an added device covers: the prefix, the member's key and the
/// new key.
pub(crate) fn device_add_proof_bytes(member: &[u8; 32], device: &[u8; 32]) -> Vec<u8> {
    [DEVICE_ADD_PREFIX, member.as_slice(), device.as_slice()].concat()
}

/// The short fingerprint of an Ed25519 public key (section 3.1): five groups of five
/// decimal digits.
pub(crate) fn short_fingerprint(public_key: &[u8]) -> String {
    let hash = Sha256::new()
        .chain_update(FINGERPRINT_PREFIX)
        .chain_update(public_key)
        .finalize();
    let groups: Vec<String> = hash
        .as_chunks::<5>()
        .0
        .iter()
        .take(5)
        .map(|group| {
            let mut bytes = [0; 8];
            if let Some((_, low)) = bytes.split_last_chunk_mut::<5>() {
                *low = *group;
            }
            format!("{:05}", u64::from_be_bytes(bytes).rem_euclid(100_000))
        })
        .collect();
    groups.join(" ")
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

    #[test]
    fn the_short_fingerprints_of_the_test_keys_of_keys_md() {
        let old = unhex("1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a");
        assert_eq!(short_fingerprint(&old), "24773 42899 01908 98427 81734");
        let new = unhex("bc8213b9e5a1325c8ac9877a72555aa19f7b8b6841cbffb9345aad04328e1f7b");
        assert_eq!(short_fingerprint(&new), "09244 67325 13841 38603 74394");
    }

    #[test]
    fn the_signed_bytes_leave_out_the_header_and_the_signature() {
        let message: Vec<u8> = (0..80).collect();
        let signed = signed_bytes_of_live_message(&message).unwrap();
        assert_eq!(&signed[..15], MESSAGE_PREFIX);
        assert_eq!(&signed[15..], &message[10..16]);
        assert_eq!(signed_bytes_of_live_message(&message[..73]), None);
        assert!(!verify_live_message(&message[..20], &[0; 32]));
    }

    #[test]
    fn the_proof_bytes_are_the_prefix_and_both_keys() {
        let bytes = device_add_proof_bytes(&[1; 32], &[2; 32]);
        assert_eq!(bytes.len(), 82);
        assert_eq!(&bytes[..18], DEVICE_ADD_PREFIX);
        assert_eq!(bytes[18], 1);
        assert_eq!(bytes[81], 2);
    }
}
