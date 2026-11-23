//! Ed25519 with the strict verification of AXT (`spec/keys.md`, section 2.3).
//!
//! Signing and the equation of step 5 come from `ed25519-dalek`; steps 1 to 3, which
//! libraries choose differently, are checked here with the points of `curve25519-dalek`.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::keys::SigningSeed;

/// Whether `encoded` passes steps 2 and 3 of the strict verification: it is the canonical
/// encoding of a point (RFC 8032, section 5.1.3), and that point has the order L.
pub(crate) fn is_point_of_order_l(encoded: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 32]>::try_from(encoded) else {
        return false;
    };
    let compressed = CompressedEdwardsY(bytes);
    let Some(point) = compressed.decompress() else {
        return false;
    };
    // The decoding reduces y modulo p and takes x = 0 whatever the sign bit; encoding the
    // point again gives other bytes for each of these encodings, which step 2 rejects.
    point.compress() == compressed && !point.is_identity() && point.is_torsion_free()
}

/// The public key of the Ed25519 private key `seed` (RFC 8032, section 5.1.5).
pub(crate) fn public_key_of(seed: &SigningSeed) -> [u8; 32] {
    SigningKey::from_bytes(seed.as_bytes())
        .verifying_key()
        .to_bytes()
}

/// The pure Ed25519 signature of `data` with the private key `seed`.
pub(crate) fn sign(seed: &SigningSeed, data: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed.as_bytes())
        .sign(data)
        .to_bytes()
}

/// Whether `signature` over `data` verifies with `public_key` by the strict rule of
/// `spec/keys.md`, section 2.3.
pub(crate) fn verify_strict(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (
        <[u8; 32]>::try_from(public_key),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    let Some((r, s)) = signature.split_first_chunk::<32>() else {
        return false;
    };
    let Ok(s) = <[u8; 32]>::try_from(s) else {
        return false;
    };
    // Step 1: S below L.
    if !bool::from(Scalar::from_canonical_bytes(s).is_some()) {
        return false;
    }
    // Steps 2 and 3, for the key and for R.
    if !is_point_of_order_l(&key) || !is_point_of_order_l(r) {
        return false;
    }
    // Steps 4 and 5.
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    key.verify_strict(data, &Signature::from_bytes(&signature))
        .is_ok()
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

    // RFC 8032, section 7.1, TEST 1.
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIGNATURE: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    fn seed() -> SigningSeed {
        SigningSeed::new(unhex(SEED).try_into().unwrap())
    }

    #[test]
    fn signs_and_verifies_the_test_of_rfc_8032() {
        assert_eq!(public_key_of(&seed()).to_vec(), unhex(PUBLIC));
        assert_eq!(sign(&seed(), &[]).to_vec(), unhex(SIGNATURE));
        assert!(verify_strict(&unhex(PUBLIC), &[], &unhex(SIGNATURE)));
        assert!(!verify_strict(&unhex(PUBLIC), &[1], &unhex(SIGNATURE)));
    }

    #[test]
    fn rejects_s_of_l_or_above_bad_lengths_and_bad_points() {
        let mut big = unhex(SIGNATURE);
        big[32..].fill(0xff);
        assert!(!verify_strict(&unhex(PUBLIC), &[], &big));
        assert!(!verify_strict(&unhex(PUBLIC), &[], &[0; 63]));
        assert!(!verify_strict(&[0; 31], &[], &unhex(SIGNATURE)));
        let mut neutral_r = unhex(SIGNATURE);
        neutral_r[..32].fill(0);
        neutral_r[0] = 1;
        assert!(!verify_strict(&unhex(PUBLIC), &[], &neutral_r));
    }

    #[test]
    fn a_point_of_order_l_and_the_ones_that_are_not() {
        assert!(is_point_of_order_l(&unhex(PUBLIC)));
        for small in [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            // The neutral element with y = p + 1, and with the sign bit set.
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0100000000000000000000000000000000000000000000000000000000000080",
            // A key with a component of order 8 (keys.md, section 7.6).
            "3708fc86c0d0892ddcc160bc020324ebe7a6a51799f526f06f34dce0e430bce2",
        ] {
            assert!(!is_point_of_order_l(&unhex(small)), "{small}");
        }
        assert!(!is_point_of_order_l(&[0; 31]));
        // Some y have no x at all.
        let outcomes: Vec<bool> = (2u8..40)
            .map(|y| {
                let mut bytes = [0; 32];
                bytes[0] = y;
                is_point_of_order_l(&bytes)
            })
            .collect();
        assert!(outcomes.contains(&false));
    }
}
