//! Encryption for the relay: padding, and sealing and opening with HPKE (AXT
//! `spec/keys.md`, sections 4.1 to 4.5; RFC 9180).
//!
//! HPKE is built here from X25519, HKDF-SHA256 and ChaCha20-Poly1305 as RFC 9180, sections
//! 4 and 5, describe: base mode, single-shot, the suite DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256 and ChaCha20-Poly1305.

#[cfg(any(test, feature = "conformance"))]
use chacha20poly1305::aead::{Aead, KeyInit};
#[cfg(any(test, feature = "conformance"))]
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
#[cfg(any(test, feature = "conformance"))]
use hkdf::{Hkdf, HkdfExtract};
#[cfg(any(test, feature = "conformance"))]
use sha2::Sha256;
#[cfg(any(test, feature = "conformance"))]
use x25519_dalek::{PublicKey, StaticSecret};
#[cfg(any(test, feature = "conformance"))]
use zeroize::Zeroizing;

#[cfg(any(test, feature = "conformance"))]
use crate::error::{Error, ErrorCode};
#[cfg(any(test, feature = "conformance"))]
use crate::keys::EncryptionSeed;

/// The `info` of every sealed message.
#[cfg(any(test, feature = "conformance"))]
const INFO: &[u8] = b"AXT-v1 relay message";

/// The suite of the KEM, DHKEM(X25519, HKDF-SHA256): `KEM` and the identifier 0x0020.
#[cfg(any(test, feature = "conformance"))]
const KEM_SUITE: &[u8] = b"KEM\x00\x20";

/// The suite of HPKE: `HPKE`, the KEM 0x0020, HKDF-SHA256 0x0001, ChaCha20-Poly1305 0x0003.
#[cfg(any(test, feature = "conformance"))]
const HPKE_SUITE: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

/// The version label of RFC 9180.
#[cfg(any(test, feature = "conformance"))]
const VERSION: &[u8] = b"HPKE-v1";

/// The byte that names the construction of section 4.3.
#[cfg(any(test, feature = "conformance"))]
const SEALED_VERSION: u8 = 1;

/// The length of the encapsulated key.
#[cfg(any(test, feature = "conformance"))]
const ENC_LENGTH: usize = 32;

/// The length of the tag of ChaCha20-Poly1305.
#[cfg(any(test, feature = "conformance"))]
const TAG_LENGTH: usize = 16;

/// The byte that ends a message inside its padding.
#[cfg(any(test, feature = "conformance"))]
const PADDING_MARK: u8 = 0x80;

/// The smallest padded length.
#[cfg(any(test, feature = "conformance"))]
const MIN_PADDED: u64 = 1024;

/// The padded length P(n) of a message of `length` bytes (section 4.4): max(1024,
/// Padmé(n + 1)); `None` above the range of `u64`.
#[cfg(any(test, feature = "conformance"))]
pub(crate) fn padded_length(length: u64) -> Option<u64> {
    let x = length.checked_add(1)?;
    if x <= MIN_PADDED {
        return Some(MIN_PADDED);
    }
    let e = x.ilog2();
    let s = e.ilog2().checked_add(1)?;
    let last_bits = e.checked_sub(s)?;
    let mask = 1u64.checked_shl(last_bits)?.checked_sub(1)?;
    Some(x.checked_add(mask)? & !mask)
}

/// `LabeledExtract` of RFC 9180, section 4, with HKDF-SHA256: the pseudorandom key, ready
/// to expand.
#[cfg(any(test, feature = "conformance"))]
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Hkdf<Sha256> {
    let mut extract = HkdfExtract::<Sha256>::new(Some(salt));
    for part in [VERSION, suite, label, ikm] {
        extract.input_ikm(part);
    }
    extract.finalize().1
}

/// `LabeledExpand` of RFC 9180, section 4, of `N` bytes; `None` only for a length HKDF
/// cannot give, which no caller asks for.
#[cfg(any(test, feature = "conformance"))]
fn labeled_expand<const N: usize>(
    suite: &[u8],
    prk: &Hkdf<Sha256>,
    label: &[u8],
    info: &[u8],
) -> Option<Zeroizing<[u8; N]>> {
    let length = u16::try_from(N).ok()?.to_be_bytes();
    let mut out = Zeroizing::new([0; N]);
    prk.expand_multi_info(&[&length, VERSION, suite, label, info], out.as_mut_slice())
        .ok()?;
    Some(out)
}

/// The shared secret of the KEM for the X25519 output `dh` and the KEM context `enc`
/// and the receiver's public key (RFC 9180, section 4.1, `ExtractAndExpand`).
#[cfg(any(test, feature = "conformance"))]
fn shared_secret(dh: &[u8], enc: &[u8; 32], receiver: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    let prk = labeled_extract(KEM_SUITE, &[], b"eae_prk", dh);
    let kem_context = [enc.as_slice(), receiver.as_slice()].concat();
    labeled_expand(KEM_SUITE, &prk, b"shared_secret", &kem_context)
}

/// The AEAD key and base nonce of the base mode for `shared_secret` (RFC 9180, section
/// 5.1, `KeySchedule`).
#[cfg(any(test, feature = "conformance"))]
type Schedule = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 12]>);

/// `KeySchedule` of the base mode with the `info` of AXT.
#[cfg(any(test, feature = "conformance"))]
fn key_schedule(shared_secret: &[u8; 32]) -> Option<Schedule> {
    // The context is the mode, base = 0, and the hashes of the empty `psk_id` and of
    // the `info`, each the pseudorandom key of its extraction.
    let mut context = vec![0u8];
    context.extend_from_slice(&prk_bytes(HPKE_SUITE, b"psk_id_hash", &[]));
    context.extend_from_slice(&prk_bytes(HPKE_SUITE, b"info_hash", INFO));
    let secret = labeled_extract(HPKE_SUITE, shared_secret, b"secret", &[]);
    Some((
        labeled_expand(HPKE_SUITE, &secret, b"key", &context)?,
        labeled_expand(HPKE_SUITE, &secret, b"base_nonce", &context)?,
    ))
}

/// The bytes of `LabeledExtract` with an empty salt, for the hashes of the key schedule's
/// context.
#[cfg(any(test, feature = "conformance"))]
fn prk_bytes(suite: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut extract = HkdfExtract::<Sha256>::new(Some(&[]));
    for part in [VERSION, suite, label, ikm] {
        extract.input_ikm(part);
    }
    extract.finalize().0.into()
}

/// Whether `dh` is the all-zero value of X25519.
fn all_zero(dh: &[u8]) -> bool {
    dh.iter().all(|b| *b == 0)
}

/// Whether `encryption_key` is an X25519 key of small order, for which every private key
/// gives the all-zero value (section 4.2), or not 32 bytes long.
pub(crate) fn is_small_order_encryption_key(encryption_key: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(encryption_key) else {
        return true;
    };
    all_zero(&x25519_dalek::x25519([0x42; 32], key))
}

/// A rejection of the encryption key.
#[cfg(any(test, feature = "conformance"))]
fn key_invalid(message: &str) -> Error {
    Error::axt(ErrorCode::EncryptionKeyInvalid, message)
}

/// Seals `message` for `encryption_key` (section 4.3): `01`, the encapsulated key, then
/// the padded message encrypted with HPKE and a fresh ephemeral key.
///
/// # Errors
///
/// [`ErrorCode::EncryptionKeyInvalid`] for a key of small order, and also if the system
/// gives no random bytes for the ephemeral key, or the message is beyond what the
/// padding and the AEAD take.
#[cfg(any(test, feature = "conformance"))]
pub(crate) fn seal(message: &[u8], encryption_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut ephemeral = Zeroizing::new([0; 32]);
    getrandom::fill(ephemeral.as_mut_slice())
        .map_err(|_| key_invalid("the system gives no random bytes for the ephemeral key"))?;
    seal_with(
        &pad(message).ok_or_else(|| key_invalid("the message is too long to pad"))?,
        encryption_key,
        &StaticSecret::from(*ephemeral),
    )
}

/// `message`, the byte `80` and as many zero bytes as bring it to its padded length.
#[cfg(any(test, feature = "conformance"))]
fn pad(message: &[u8]) -> Option<Vec<u8>> {
    let length = usize::try_from(padded_length(u64::try_from(message.len()).ok()?)?).ok()?;
    let mut padded = Vec::with_capacity(length);
    padded.extend_from_slice(message);
    padded.push(PADDING_MARK);
    padded.resize(length, 0);
    Some(padded)
}

/// Encrypts `plaintext`, already padded, for `encryption_key` with HPKE and the ephemeral
/// key `ephemeral`, and puts `01` and the encapsulated key in front.
#[cfg(any(test, feature = "conformance"))]
fn seal_with(
    plaintext: &[u8],
    encryption_key: &[u8; 32],
    ephemeral: &StaticSecret,
) -> Result<Vec<u8>, Error> {
    let enc = PublicKey::from(ephemeral).to_bytes();
    let dh = Zeroizing::new(
        ephemeral
            .diffie_hellman(&PublicKey::from(*encryption_key))
            .to_bytes(),
    );
    if all_zero(dh.as_slice()) {
        return Err(key_invalid("the X25519 output is all zero"));
    }
    let failed = || key_invalid("the key schedule failed");
    let shared = shared_secret(dh.as_slice(), &enc, encryption_key).ok_or_else(failed)?;
    let (key, nonce) = key_schedule(&shared).ok_or_else(failed)?;
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let box_ = cipher
        .encrypt(&Nonce::from(*nonce), plaintext)
        .map_err(|_| key_invalid("the message is too long to encrypt"))?;
    let mut sealed = Vec::with_capacity(box_.len().saturating_add(1 + ENC_LENGTH));
    sealed.push(SEALED_VERSION);
    sealed.extend_from_slice(&enc);
    sealed.extend_from_slice(&box_);
    Ok(sealed)
}

/// Opens `sealed` with the first of `private_keys` that opens it, and removes the padding
/// (section 4.5).
///
/// # Errors
///
/// [`ErrorCode::NotOpened`] when it does not begin with `01` or no key opens it, and
/// [`ErrorCode::PaddingInvalid`] for a plaintext that does not end with `80` followed only
/// by zero bytes.
#[cfg(any(test, feature = "conformance"))]
pub(crate) fn open(sealed: &[u8], private_keys: &[EncryptionSeed]) -> Result<Vec<u8>, Error> {
    let not_opened = |message: &str| Error::axt(ErrorCode::NotOpened, message);
    let Some((&SEALED_VERSION, rest)) = sealed.split_first() else {
        return Err(not_opened("not a sealed message"));
    };
    let Some((enc, ciphertext)) = rest.split_first_chunk::<ENC_LENGTH>() else {
        return Err(not_opened("not a sealed message"));
    };
    if ciphertext.len() < TAG_LENGTH {
        return Err(not_opened("not a sealed message"));
    }
    for private_key in private_keys {
        let secret = StaticSecret::from(*private_key.as_bytes());
        let dh = Zeroizing::new(secret.diffie_hellman(&PublicKey::from(*enc)).to_bytes());
        if all_zero(dh.as_slice()) {
            continue;
        }
        let own = PublicKey::from(&secret).to_bytes();
        let Some((key, nonce)) =
            shared_secret(dh.as_slice(), enc, &own).and_then(|shared| key_schedule(&shared))
        else {
            continue;
        };
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        let Ok(mut padded) = cipher.decrypt(&Nonce::from(*nonce), ciphertext) else {
            continue;
        };
        return match padded.iter().rposition(|b| *b != 0) {
            Some(end) if padded.get(end) == Some(&PADDING_MARK) => {
                padded.truncate(end);
                Ok(padded)
            }
            _ => Err(Error::axt(
                ErrorCode::PaddingInvalid,
                "the plaintext does not end with 80 and zero bytes",
            )),
        };
    }
    Err(not_opened("no key opens it"))
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        crate::value::hex(bytes)
    }

    fn key32(text: &str) -> [u8; 32] {
        unhex(text).try_into().unwrap()
    }

    /// The DATA message of keys.md, section 7.2.
    const MESSAGE: &str = concat!(
        "c30116306f71b9ce9ea802081b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26",
        "ec4a024830623561336331652d346432662d346136622d396338642d376536663561346233633264027c",
        "c30173acdcca160ef237245665742c20547565736461792031303a3030d21f161e16000000021a457572",
        "6f70652f4265726c696e02a0380280d4a8efd0668ddef4429c183d9ca38e0a0d7b90088418f71fe94310",
        "0ea9b76b4a965c60b0250de8561e84d10ccab3e2cb6ca7e0eca916929737c4fc264c5c6a523967dfc106",
    );
    /// Old Brain Fix's X25519 test key.
    const PRIVATE: &str = "8a5e1abca252aefadec7cf0764f52c64b587cdbef900ea3d9046cbf51bc6ed97";
    const PUBLIC: &str = "34fa7e71770d8d94c76001ac8d575609f005981f80c115bb7a8fe312687ea40b";
    /// The ephemeral key of keys.md, section 7.4.
    const SK_E: &str = "4ccbb85253cbd95b84478d2edb1194aaaf35f1a1753721114884779049287323";

    fn random_secret() -> StaticSecret {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).unwrap();
        StaticSecret::from(bytes)
    }

    fn pair() -> (EncryptionSeed, [u8; 32]) {
        let secret = random_secret();
        let public = PublicKey::from(&secret).to_bytes();
        (EncryptionSeed::new(secret.to_bytes()), public)
    }

    #[test]
    fn pads_to_p_of_n() {
        for (n, p) in [
            (0, 1024),
            (210, 1024),
            (1023, 1024),
            (1024, 1088),
            (4000, 4096),
            (100_000, 100_352),
            (16_777_216, 17_301_504),
        ] {
            assert_eq!(padded_length(n), Some(p), "{n}");
        }
        assert_eq!(padded_length(u64::MAX), None);
    }

    #[test]
    fn the_sealed_message_of_keys_md_section_7_4() {
        let ephemeral = StaticSecret::from(key32(SK_E));
        let enc = PublicKey::from(&ephemeral).to_bytes();
        assert_eq!(
            hex(&enc),
            "ed7a4a213ac37cdffc78372805f51ea53b592174ea7bd2bceacf6b359438b336"
        );
        let dh = ephemeral.diffie_hellman(&PublicKey::from(key32(PUBLIC)));
        let shared = shared_secret(dh.as_bytes(), &enc, &key32(PUBLIC)).unwrap();
        assert_eq!(
            hex(shared.as_slice()),
            "39da902e661e8410c3ce9a69037c3f67f82d1c7de7d5a58792baca43bcda2bc4"
        );
        let (key, nonce) = key_schedule(&shared).unwrap();
        assert_eq!(
            hex(key.as_slice()),
            "c06224435dd8746e228c29cb8398d7fa42733ef05ebadf09281080ed7caddbaa"
        );
        assert_eq!(hex(nonce.as_slice()), "7a348d859da32b0b186b5b9b");
        let message = unhex(MESSAGE);
        let sealed = seal_with(&pad(&message).unwrap(), &key32(PUBLIC), &ephemeral).unwrap();
        assert_eq!(sealed.len(), 1073);
        assert_eq!(
            hex(&sha2::Sha256::digest(&sealed)),
            "64a9988bd3e1e8210d592e29115d5b3252d2e75be5c219ca67583608cfdb878a"
        );
        let opened = open(&sealed, &[EncryptionSeed::new(key32(PRIVATE))]).unwrap();
        assert_eq!(opened, message);
    }

    #[test]
    fn seals_and_opens_with_the_right_key_among_others() {
        let (private, public) = pair();
        let (other, _) = pair();
        let message = unhex(MESSAGE);
        let sealed = seal(&message, &public).unwrap();
        assert_eq!(sealed.len(), 1 + 32 + 1024 + 16);
        assert_eq!(sealed[0], 1);
        let both = [EncryptionSeed::new(*other.as_bytes()), private];
        assert_eq!(open(&sealed, &both).unwrap(), message);
        let code = |r: Result<Vec<u8>, Error>| r.unwrap_err().code();
        assert_eq!(code(open(&sealed, &both[..1])), Some(ErrorCode::NotOpened));
        let mut changed = sealed.clone();
        changed[0] = 2;
        assert_eq!(code(open(&changed, &both)), Some(ErrorCode::NotOpened));
        assert_eq!(code(open(&[1, 2, 3], &both)), Some(ErrorCode::NotOpened));
        assert_eq!(
            code(open(&sealed, &[EncryptionSeed::new([0; 32])])),
            Some(ErrorCode::NotOpened)
        );
    }

    #[test]
    fn rejects_a_plaintext_without_its_padding() {
        let (private, public) = pair();
        let ephemeral = random_secret();
        for plaintext in [vec![0; 1024], vec![1, 2, 3]] {
            let sealed = seal_with(&plaintext, &public, &ephemeral).unwrap();
            assert_eq!(
                open(&sealed, std::slice::from_ref(&private))
                    .unwrap_err()
                    .code(),
                Some(ErrorCode::PaddingInvalid)
            );
        }
    }

    #[test]
    fn rejects_encryption_keys_of_small_order() {
        let (_, public) = pair();
        assert!(!is_small_order_encryption_key(&public));
        assert!(is_small_order_encryption_key(&[0; 32]));
        assert!(is_small_order_encryption_key(&[0; 31]));
        assert_eq!(
            seal(&[1], &[0; 32]).unwrap_err().code(),
            Some(ErrorCode::EncryptionKeyInvalid)
        );
    }
}
