//! The Avro object container file of AXT, read to the bytes of each datum as stored, since
//! a message's signature covers those bytes (AXT `spec/envelope.md`, sections 4 and 8;
//! `spec/keys.md`, section 2.2).

use std::collections::BTreeMap;

use crate::error::{Error, ErrorCode};

/// The largest file as stored.
pub(crate) const MAX_FILE_BYTES: usize = 256 * 1024 * 1024;

/// The largest metadata of a file, keys and values together.
pub(crate) const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

/// The largest data block after decompression.
pub(crate) const MAX_BLOCK_BYTES: usize = 64 * 1024 * 1024;

/// The largest sum of all data blocks after decompression.
pub(crate) const MAX_TOTAL_BYTES: usize = 1024 * 1024 * 1024;

/// The magic bytes of an Avro object container file.
const MAGIC: [u8; 4] = [0x4f, 0x62, 0x6a, 1];

/// The length of a sync marker.
const SYNC_LENGTH: usize = 16;

/// A rejection of the whole file.
pub(crate) fn rejected(why: impl Into<String>) -> Error {
    Error::axt(ErrorCode::FileRejected, why)
}

/// A reader of Avro binary data that rejects instead of reading beyond the end.
struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// A zig-zag varint `long`.
    fn long(&mut self) -> Result<i64, Error> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let b = match self.bytes.get(self.offset) {
                Some(b) if shift <= 63 => *b,
                _ => return Err(rejected("a varint is cut")),
            };
            self.offset = self.offset.saturating_add(1);
            value |= u64::from(b & 0x7f).wrapping_shl(shift);
            if b & 0x80 == 0 {
                break;
            }
            shift = shift.saturating_add(7);
        }
        let magnitude = i64::from_ne_bytes(value.wrapping_shr(1).to_ne_bytes());
        let sign = i64::from_ne_bytes((value & 1).to_ne_bytes()).wrapping_neg();
        Ok(magnitude ^ sign)
    }

    /// The next `length` bytes.
    fn take(&mut self, length: i64) -> Result<&'a [u8], Error> {
        let beyond = || rejected("a length is beyond the end");
        let length = usize::try_from(length).map_err(|_| beyond())?;
        let end = self.offset.checked_add(length).ok_or_else(beyond)?;
        let out = self.bytes.get(self.offset..end).ok_or_else(beyond)?;
        self.offset = end;
        Ok(out)
    }

    /// Bytes after their length.
    fn length_prefixed(&mut self) -> Result<&'a [u8], Error> {
        let length = self.long()?;
        self.take(length)
    }
}

/// The header and the datums of a container file.
#[derive(Debug)]
pub(crate) struct Container {
    /// The metadata entries, values as stored.
    pub(crate) metadata: BTreeMap<String, Vec<u8>>,
    /// The bytes of each datum, in the order of the file.
    pub(crate) datums: Vec<Vec<u8>>,
}

impl Container {
    /// Reads `file`, splitting each block into datums with [`envelope_length`].
    ///
    /// # Errors
    ///
    /// `FILE_REJECTED` for bytes that are no container file, a codec other than `null`
    /// and `deflate`, or a size above a limit.
    pub(crate) fn read(file: &[u8]) -> Result<Self, Error> {
        if file.len() > MAX_FILE_BYTES {
            return Err(rejected("the file is above 256 MiB"));
        }
        let mut input = Input {
            bytes: file,
            offset: 0,
        };
        if input.take(4)? != MAGIC {
            return Err(rejected("no Avro object container file"));
        }
        let start = input.offset;
        let mut metadata = BTreeMap::new();
        loop {
            let mut count = input.long()?;
            if count == 0 {
                break;
            }
            if count < 0 {
                count = count
                    .checked_neg()
                    .ok_or_else(|| rejected("a metadata count is out of range"))?;
                input.long()?;
            }
            for _ in 0..count {
                let key = String::from_utf8(input.length_prefixed()?.to_vec())
                    .map_err(|_| rejected("a metadata key is no UTF-8"))?;
                let value = input.length_prefixed()?.to_vec();
                metadata.insert(key, value);
            }
            if input.offset.saturating_sub(start) > MAX_METADATA_BYTES {
                return Err(rejected("the metadata is above 8 MiB"));
            }
        }
        let deflate = match metadata.get("avro.codec").map(Vec::as_slice) {
            None | Some(b"null") => false,
            Some(b"deflate") => true,
            Some(other) => {
                return Err(rejected(format!(
                    "the codec {} is neither null nor deflate",
                    String::from_utf8_lossy(other)
                )));
            }
        };
        let sync = input.take(16)?;
        let mut datums = Vec::new();
        let mut total: usize = 0;
        while input.remaining() > 0 {
            let count = input.long()?;
            let stored = input.length_prefixed()?;
            let inflated;
            let block = if deflate {
                inflated = inflate(stored)?;
                inflated.as_slice()
            } else {
                stored
            };
            if block.len() > MAX_BLOCK_BYTES {
                return Err(rejected("a block is above 64 MiB"));
            }
            total = total.saturating_add(block.len());
            if total > MAX_TOTAL_BYTES {
                return Err(rejected("the blocks are above 1 GiB"));
            }
            if count < 0 {
                return Err(rejected("a negative block count"));
            }
            let mut offset = 0;
            for _ in 0..count {
                let length = envelope_length(block, offset)?;
                let end = offset.saturating_add(length);
                let datum = block
                    .get(offset..end)
                    .ok_or_else(|| rejected("a datum is beyond its block"))?;
                datums.push(datum.to_vec());
                offset = end;
            }
            if offset != block.len() {
                return Err(rejected("bytes are left over in a block"));
            }
            if input.take(16)? != sync {
                return Err(rejected("a block ends without the sync marker"));
            }
        }
        Ok(Self { metadata, datums })
    }
}

/// The raw deflate stream `stored`, inflated to at most [`MAX_BLOCK_BYTES`].
fn inflate(stored: &[u8]) -> Result<Vec<u8>, Error> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(stored, MAX_BLOCK_BYTES).map_err(|e| {
        if e.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput {
            rejected("a block is above 64 MiB")
        } else {
            rejected("a block does not inflate")
        }
    })
}

/// The length of the `axt.Envelope` of format 1 that starts at `offset` of `block`, found
/// from its bytes alone (keys.md, section 2.2): `format`, `kind`, `sender`, `record`,
/// `body` and `signature`.
pub(crate) fn envelope_length(block: &[u8], offset: usize) -> Result<usize, Error> {
    let mut input = Input {
        bytes: block,
        offset,
    };
    input.long()?;
    input.long()?;
    input.take(32)?;
    match input.long()? {
        0 => {}
        1 => {
            input.length_prefixed()?;
            input.long()?;
        }
        _ => return Err(rejected("a record union index is neither 0 nor 1")),
    }
    input.length_prefixed()?;
    input.take(64)?;
    Ok(input.offset.saturating_sub(offset))
}

/// Appends the zig-zag varint of `value`.
fn write_long(out: &mut Vec<u8>, value: i64) {
    let mut v = u64::from_ne_bytes((value.wrapping_shl(1) ^ value.wrapping_shr(63)).to_ne_bytes());
    while v & !0x7f != 0 {
        out.push(u8::try_from(v & 0x7f).unwrap_or(0) | 0x80);
        v = v.wrapping_shr(7);
    }
    out.push(u8::try_from(v).unwrap_or(0));
}

/// Appends `value` after its length.
fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
    write_long(out, i64::try_from(value.len()).unwrap_or(i64::MAX));
    out.extend_from_slice(value);
}

/// Writes a container file of `datums`, each already encoded, with `metadata` first and
/// then `avro.codec`, `deflate` or `null`, in one block.
pub(crate) fn write_container(
    metadata: &[(&str, Vec<u8>)],
    datums: &[Vec<u8>],
    sync_marker: [u8; SYNC_LENGTH],
    deflate: bool,
) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    let codec: &[u8] = if deflate { b"deflate" } else { b"null" };
    write_long(
        &mut out,
        i64::try_from(metadata.len().saturating_add(1)).unwrap_or(i64::MAX),
    );
    for (key, value) in metadata {
        write_bytes(&mut out, key.as_bytes());
        write_bytes(&mut out, value);
    }
    write_bytes(&mut out, b"avro.codec");
    write_bytes(&mut out, codec);
    write_long(&mut out, 0);
    out.extend_from_slice(&sync_marker);
    if !datums.is_empty() {
        let raw = datums.concat();
        write_long(&mut out, i64::try_from(datums.len()).unwrap_or(i64::MAX));
        if deflate {
            write_bytes(&mut out, &miniz_oxide::deflate::compress_to_vec(&raw, 6));
        } else {
            write_bytes(&mut out, &raw);
        }
        out.extend_from_slice(&sync_marker);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long(value: i64) -> Vec<u8> {
        let mut out = Vec::new();
        write_long(&mut out, value);
        out
    }

    /// An envelope datum of format 1 with a record, a body and a signature.
    fn envelope_datum(body: &[u8]) -> Vec<u8> {
        let mut out = long(1);
        out.extend(long(3));
        out.extend([7; 32]);
        out.extend(long(1));
        write_bytes(&mut out, b"id");
        out.extend(long(5));
        write_bytes(&mut out, body);
        out.extend([9; 64]);
        out
    }

    #[test]
    fn varints_go_both_ways() {
        for value in [0, 1, -1, 63, -64, 64, 1 << 40, i64::MAX, i64::MIN] {
            let bytes = long(value);
            let mut input = Input {
                bytes: &bytes,
                offset: 0,
            };
            assert_eq!(input.long().unwrap(), value);
            assert_eq!(input.remaining(), 0);
        }
        let mut cut = Input {
            bytes: &[0x80],
            offset: 0,
        };
        assert!(cut.long().is_err());
        let mut long_run = Input {
            bytes: &[0xff; 11],
            offset: 0,
        };
        assert!(long_run.long().is_err());
    }

    #[test]
    fn a_container_goes_both_ways_with_and_without_deflate() {
        let datums = vec![envelope_datum(b"one"), envelope_datum(b"")];
        for deflate in [false, true] {
            let file = write_container(&[("axt.x", b"y".to_vec())], &datums, [5; 16], deflate);
            let read = Container::read(&file).unwrap();
            assert_eq!(read.datums, datums);
            assert_eq!(read.metadata["axt.x"], b"y");
            let codec: &[u8] = if deflate { b"deflate" } else { b"null" };
            assert_eq!(read.metadata["avro.codec"], codec);
        }
        let empty = Container::read(&write_container(&[], &[], [0; 16], true)).unwrap();
        assert!(empty.datums.is_empty());
    }

    fn rejects(file: &[u8]) -> bool {
        Container::read(file).unwrap_err().code() == Some(ErrorCode::FileRejected)
    }

    #[test]
    fn the_container_rejects_what_is_no_container_file() {
        assert!(rejects(b""));
        assert!(rejects(b"Obj\x02"));
        let good = write_container(&[], &[envelope_datum(b"x")], [5; 16], false);
        // Cut short anywhere.
        for end in [5, good.len() - 1, good.len() - 17] {
            assert!(rejects(&good[..end]));
        }
        // A wrong sync marker at the end of the block.
        let mut bad = good.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(rejects(&bad));
        // Another codec.
        let mut file = MAGIC.to_vec();
        file.extend(long(1));
        write_bytes(&mut file, b"avro.codec");
        write_bytes(&mut file, b"snappy");
        file.extend(long(0));
        file.extend([0; 16]);
        assert!(rejects(&file));
        // A key that is no UTF-8.
        let mut file = MAGIC.to_vec();
        file.extend(long(1));
        write_bytes(&mut file, &[0xff]);
        write_bytes(&mut file, b"");
        file.extend(long(0));
        file.extend([0; 16]);
        assert!(rejects(&file));
        // Bytes left over in a block, and a negative count.
        for (count, datum) in [(1, [envelope_datum(b"x"), vec![0]].concat()), (-1, vec![])] {
            let mut file = MAGIC.to_vec();
            file.extend(long(0));
            file.extend([0; 16]);
            file.extend(long(count));
            write_bytes(&mut file, &datum);
            file.extend([0; 16]);
            assert!(rejects(&file));
        }
        // A block that does not inflate.
        let mut file = MAGIC.to_vec();
        file.extend(long(1));
        write_bytes(&mut file, b"avro.codec");
        write_bytes(&mut file, b"deflate");
        file.extend(long(0));
        file.extend([0; 16]);
        file.extend(long(1));
        write_bytes(&mut file, &[0xff, 0xff, 0xff]);
        file.extend([0; 16]);
        assert!(rejects(&file));
    }

    #[test]
    fn the_metadata_may_come_in_a_block_with_a_byte_size() {
        let mut file = MAGIC.to_vec();
        file.extend(long(-1));
        file.extend(long(9));
        write_bytes(&mut file, b"k");
        write_bytes(&mut file, b"v");
        file.extend(long(0));
        file.extend([0; 16]);
        let read = Container::read(&file).unwrap();
        assert_eq!(read.metadata["k"], b"v");
    }

    #[test]
    fn limits_of_the_metadata_and_of_a_block() {
        let mut file = MAGIC.to_vec();
        file.extend(long(1));
        write_bytes(&mut file, b"k");
        write_bytes(&mut file, &vec![0; MAX_METADATA_BYTES]);
        file.extend(long(0));
        file.extend([0; 16]);
        assert!(rejects(&file));
        let zeros = vec![0; MAX_BLOCK_BYTES + 1];
        let deflated = miniz_oxide::deflate::compress_to_vec(&zeros, 6);
        let mut file = MAGIC.to_vec();
        file.extend(long(1));
        write_bytes(&mut file, b"avro.codec");
        write_bytes(&mut file, b"deflate");
        file.extend(long(0));
        file.extend([0; 16]);
        file.extend(long(1));
        write_bytes(&mut file, &deflated);
        file.extend([0; 16]);
        assert!(rejects(&file));
    }

    #[test]
    fn an_envelope_has_its_length_from_its_bytes() {
        let datum = envelope_datum(b"body");
        assert_eq!(envelope_length(&datum, 0).unwrap(), datum.len());
        let mut no_union = datum.clone();
        no_union[34] = 4;
        assert!(envelope_length(&no_union, 0).is_err());
    }
}
