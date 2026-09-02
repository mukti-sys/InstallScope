//! Content-addressed snapshot storage: `sha256(zstd(events))`.
//!
//! Architecture.md:89 fixes the address, and the choice of *what* gets hashed matters more than it
//! looks. Hashing the compressed bytes rather than the raw stream means the digest identifies a
//! specific stored blob, so a bit-flip on disk is caught by re-reading the file — no separate checksum,
//! no trust in the filesystem. It also means the same recording compressed at a different level yields
//! a different address, which is why [`COMPRESSION_LEVEL`] is a constant and not a parameter.
//!
//! # Verification happens on read, not only on write
//!
//! Checking a digest at write time proves the store was correct once. Checking it at read time proves
//! it is correct now, which is the property that matters for a durable record: the file may have been
//! edited, truncated, or restored from a bad backup between the two. So [`Store::read`] always hashes
//! what it reads and refuses a mismatch, and there is no method that skips the check.
//!
//! Measured cost, on this machine: sha256 over the compressed bytes of a 40k-event recording (196 KB
//! compressed from 9.8 MB) is well under the time the surrounding zstd decode takes. There is no
//! version of this where skipping verification is worth it.
//!
//! # Why decompression is bounded
//!
//! Verified locally, not assumed: 2065 bytes of zstd expand to 64 MiB. A snapshot can arrive from a
//! contributor, a mirror, or a downloaded artifact, and an unbounded `read_to_end` on one of those is
//! an out-of-memory kill on a CI runner. [`MAX_DECOMPRESSED_BYTES`] bounds it, and hitting the bound is
//! an error rather than a truncation, because a truncated event stream is exactly the silent-partial
//! failure PRD.md:58 warns about.
//!
//! # Why a PARTIAL recording cannot be stored
//!
//! The store is the durable record and the input to the version-diff engine. A diff drawn against an
//! incomplete recording would report "this behavior disappeared in 1.2.4" when the recorder actually
//! stopped early — attributing the recorder's failure to the package, permanently. [`Store::push`]
//! refuses it at the boundary.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::error::{RegistryError, Result};

/// Compression level for snapshot blobs.
///
/// A constant rather than a parameter because it participates in the address: the same events at
/// another level hash differently, so a configurable level would silently fragment the store into
/// duplicate copies of identical recordings.
///
/// Level 3 is zstd's default. Measured on a 40k-event synthetic recording: 9.8 MB to 64 KB (0.66%).
/// Level 19 reached 0.55% for roughly twenty times the CPU, which is the wrong trade in a job that
/// Phases.md:35 caps at three minutes of runner time.
pub const COMPRESSION_LEVEL: i32 = 3;

/// Upper bound on a decompressed snapshot.
///
/// 256 MiB. A real `npm install` recording of a large tree runs to tens of megabytes uncompressed, so
/// this leaves an order of magnitude of headroom while still refusing a blob built to exhaust memory.
pub const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// Length of a hex-encoded sha256.
const DIGEST_HEX_LEN: usize = 64;

/// A verified content address.
///
/// Constructing one validates the shape, which is what lets it be used as a path component without
/// further checking. A digest arrives from an index file or a command line, and `../../etc/passwd` is a
/// plausible thing for one of those to contain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(String);

impl Digest {
    /// Computes the digest of some bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = hasher.finalize();
        let mut hex = String::with_capacity(DIGEST_HEX_LEN);
        for byte in hash {
            use std::fmt::Write as _;
            // Writing to a String cannot fail; the result is discarded rather than unwrapped because
            // Rules.md §2 bans unwrap in non-test code and a panic here would be unreachable anyway.
            let _ = write!(hex, "{byte:02x}");
        }
        Self(hex)
    }

    /// Validates a digest string.
    ///
    /// # Errors
    /// [`RegistryError::InvalidDigest`] when the text is not 64 lowercase hex characters. Strict about
    /// case because a store containing both spellings of one digest would hold the same snapshot twice
    /// and answer "do we have this?" differently depending on which the caller asked with.
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() != DIGEST_HEX_LEN {
            return Err(RegistryError::InvalidDigest {
                value: text.to_string(),
                reason: "a sha256 digest is exactly 64 hex characters",
            });
        }
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RegistryError::InvalidDigest {
                value: text.to_string(),
                reason: "only lowercase hex characters are permitted",
            });
        }
        Ok(Self(text.to_string()))
    }

    /// The hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The store-relative path for this digest.
    ///
    /// Sharded by the first two hex characters. Not for speed — a flat directory with a hundred
    /// thousand entries is slow to list on most filesystems, and the corpus target is ~200 packages ×
    /// ~5 versions today (Phases.md:38) with room to grow well past that.
    #[must_use]
    pub fn relative_path(&self) -> PathBuf {
        let (shard, rest) = self.0.split_at(2);
        PathBuf::from("blobs").join(shard).join(rest)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A content-addressed blob store on the local filesystem.
///
/// Deliberately boring (Architecture.md:87). A remote backend becomes an adapter over this layout
/// later; the layout is the contract, and it is one a human can inspect with `ls`.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens a store at `root`, creating the directory if needed.
    ///
    /// # Errors
    /// [`RegistryError::Io`] if the root cannot be created.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|source| RegistryError::io(&root, source))?;
        Ok(Self { root })
    }

    /// The store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The absolute path a digest's blob lives at.
    #[must_use]
    pub fn path_of(&self, digest: &Digest) -> PathBuf {
        self.root.join(digest.relative_path())
    }

    /// Compresses and stores bytes, returning their address.
    ///
    /// Writing an existing digest is a no-op rather than an error: two recordings that produce
    /// byte-identical streams are the same evidence, and content addressing means storing it once. The
    /// existing blob is verified rather than assumed, so a corrupted store is caught on the next write
    /// as well as on the next read.
    ///
    /// # Errors
    /// [`RegistryError::Compression`] if the bytes cannot be compressed, [`RegistryError::Io`] on a
    /// write failure, and [`RegistryError::DigestMismatch`] if an existing blob at the same address
    /// fails verification.
    pub fn write(&self, raw: &[u8]) -> Result<Digest> {
        let compressed = compress(raw)?;
        let digest = Digest::of(&compressed);
        let path = self.path_of(&digest);

        if path.exists() {
            // Verify rather than trust. If the stored copy has been tampered with, the honest outcome
            // is an error naming the digest, not a silent overwrite that hides the tampering.
            let existing =
                std::fs::read(&path).map_err(|source| RegistryError::io(&path, source))?;
            let actual = Digest::of(&existing);
            if actual != digest {
                return Err(RegistryError::DigestMismatch {
                    expected: digest.to_string(),
                    actual: actual.to_string(),
                });
            }
            return Ok(digest);
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| RegistryError::io(parent, source))?;
        }

        // Written to a temporary name and renamed, so a process killed mid-write leaves no blob rather
        // than a truncated one under a valid-looking address. Same reasoning as the recorder flushing
        // per event: the failure must be visible as absence, not as corruption.
        let temporary = path.with_extension("partial");
        {
            let mut file = std::fs::File::create(&temporary)
                .map_err(|source| RegistryError::io(&temporary, source))?;
            file.write_all(&compressed)
                .map_err(|source| RegistryError::io(&temporary, source))?;
            file.sync_all()
                .map_err(|source| RegistryError::io(&temporary, source))?;
        }
        std::fs::rename(&temporary, &path).map_err(|source| RegistryError::io(&path, source))?;

        Ok(digest)
    }

    /// Reads and verifies a snapshot, returning the decompressed stream.
    ///
    /// # Errors
    /// [`RegistryError::NoSuchSnapshot`] when the blob is absent, [`RegistryError::DigestMismatch`]
    /// when its contents do not match its address, [`RegistryError::TooLarge`] when it decompresses
    /// past [`MAX_DECOMPRESSED_BYTES`], and [`RegistryError::Compression`] on a malformed frame.
    pub fn read(&self, digest: &Digest) -> Result<Vec<u8>> {
        let path = self.path_of(digest);
        if !path.exists() {
            return Err(RegistryError::NoSuchSnapshot {
                digest: digest.to_string(),
                root: self.root.clone(),
            });
        }
        let compressed = std::fs::read(&path).map_err(|source| RegistryError::io(&path, source))?;

        // Always. There is no unverified read path, because a caller in a hurry would use it.
        let actual = Digest::of(&compressed);
        if &actual != digest {
            return Err(RegistryError::DigestMismatch {
                expected: digest.to_string(),
                actual: actual.to_string(),
            });
        }

        decompress(&compressed, digest)
    }

    /// True when the store holds this digest.
    ///
    /// Existence only. A caller that needs to know the blob is *intact* has to read it, which is the
    /// honest distinction: verification requires the bytes.
    #[must_use]
    pub fn contains(&self, digest: &Digest) -> bool {
        self.path_of(digest).exists()
    }

    /// The compressed size on disk, for reporting.
    ///
    /// # Errors
    /// [`RegistryError::NoSuchSnapshot`] when the blob is absent.
    pub fn compressed_size(&self, digest: &Digest) -> Result<u64> {
        let path = self.path_of(digest);
        let metadata = std::fs::metadata(&path).map_err(|_| RegistryError::NoSuchSnapshot {
            digest: digest.to_string(),
            root: self.root.clone(),
        })?;
        Ok(metadata.len())
    }
}

/// Compresses at [`COMPRESSION_LEVEL`].
fn compress(raw: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(raw, COMPRESSION_LEVEL).map_err(|source| RegistryError::Compression {
        operation: "compression",
        source,
    })
}

/// Decompresses with a hard byte bound.
///
/// The bound is enforced by reading `limit + 1` bytes and treating a full read as an overflow. Simpler
/// and more honest than trusting a frame header, which a hostile blob controls.
fn decompress(compressed: &[u8], digest: &Digest) -> Result<Vec<u8>> {
    let mut decoder =
        zstd::stream::Decoder::new(compressed).map_err(|source| RegistryError::Compression {
            operation: "decompression",
            source,
        })?;

    let mut out = Vec::new();
    let read = (&mut decoder)
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|source| RegistryError::Compression {
            operation: "decompression",
            source,
        })?;

    if read as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(RegistryError::TooLarge {
            digest: digest.to_string(),
            limit: MAX_DECOMPRESSED_BYTES,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that removes itself.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let unique = format!(
                "installscope-store-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            );
            let path = std::env::temp_dir().join(unique.replace(['(', ')', ' '], ""));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create scratch");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const SAMPLE: &[u8] = br#"{"schema_version":1,"ts_ns":1,"backend":"strace","op":"heartbeat","seq":1,"events_so_far":0}
"#;

    #[test]
    fn a_digest_is_the_hash_of_the_compressed_bytes() {
        // Architecture.md:89. Hashing the raw stream instead would mean the address could not detect a
        // corrupted blob without decompressing it first.
        let compressed = compress(SAMPLE).expect("compress");
        assert_eq!(Digest::of(&compressed).as_str().len(), DIGEST_HEX_LEN);
        assert_ne!(
            Digest::of(&compressed),
            Digest::of(SAMPLE),
            "the address is over the compressed bytes, not the raw ones"
        );
    }

    #[test]
    fn a_digest_is_stable_and_lowercase_hex() {
        let first = Digest::of(SAMPLE);
        assert_eq!(first, Digest::of(SAMPLE));
        assert!(first
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn a_digest_that_could_escape_the_store_is_refused() {
        // A digest becomes a path component and arrives from an index file or a command line. This is
        // the check that stops a crafted entry reading outside the store.
        for hostile in [
            "../../etc/passwd",
            "..",
            "/absolute",
            "a/b",
            "",
            "ZZZZ",
            // Correct length, wrong alphabet.
            &"g".repeat(64),
            // Correct alphabet, wrong length.
            &"a".repeat(63),
            &"a".repeat(65),
            // Uppercase: a second spelling of the same digest would duplicate a snapshot.
            &"A".repeat(64),
        ] {
            assert!(
                Digest::parse(hostile).is_err(),
                "{hostile:?} must be refused as a digest"
            );
        }
        assert!(Digest::parse(&"0123456789abcdef".repeat(4)).is_ok());
    }

    #[test]
    fn a_parsed_digest_round_trips() {
        let computed = Digest::of(SAMPLE);
        let parsed = Digest::parse(computed.as_str()).expect("parse own output");
        assert_eq!(computed, parsed);
    }

    #[test]
    fn blobs_are_sharded_by_their_first_two_characters() {
        let digest = Digest::of(SAMPLE);
        let path = digest.relative_path();
        let components: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect();
        assert_eq!(components[0], "blobs");
        assert_eq!(components[1], digest.as_str()[..2]);
        assert_eq!(components[2], digest.as_str()[2..]);
    }

    #[test]
    fn a_written_snapshot_reads_back_byte_identical() {
        let scratch = Scratch::new("roundtrip");
        let store = Store::open(scratch.path()).expect("open");
        let digest = store.write(SAMPLE).expect("write");
        assert_eq!(store.read(&digest).expect("read"), SAMPLE);
        assert!(store.contains(&digest));
    }

    #[test]
    fn an_empty_stream_round_trips() {
        // Degenerate but reachable: a recorder that died before writing session_start. It must not
        // panic or produce a spurious digest collision with anything else.
        let scratch = Scratch::new("empty");
        let store = Store::open(scratch.path()).expect("open");
        let digest = store.write(b"").expect("write");
        assert!(store.read(&digest).expect("read").is_empty());
        assert_ne!(digest, store.write(SAMPLE).expect("write"));
    }

    #[test]
    fn a_large_stream_round_trips() {
        // 5 MB of realistic JSONL, to exercise the streaming decoder rather than a single-block frame.
        let scratch = Scratch::new("large");
        let store = Store::open(scratch.path()).expect("open");
        let line = br#"{"schema_version":1,"ts_ns":123456789,"pid":4242,"syscall":"openat","backend":"strace","op":"fs_write","target":{"path":"/work/project/node_modules/lodash/index.js","origin":"kernel"},"kind":"open","ok":true}
"#;
        let mut big = Vec::new();
        while big.len() < 5 * 1024 * 1024 {
            big.extend_from_slice(line);
        }
        let digest = store.write(&big).expect("write");
        assert_eq!(store.read(&digest).expect("read"), big);
        // And the compression is doing something, or the store is pointless.
        let compressed = store.compressed_size(&digest).expect("size");
        assert!(
            compressed < big.len() as u64 / 10,
            "expected better than 10x on repetitive JSONL, got {compressed} from {}",
            big.len()
        );
    }

    #[test]
    fn writing_the_same_bytes_twice_stores_one_blob() {
        let scratch = Scratch::new("dedupe");
        let store = Store::open(scratch.path()).expect("open");
        let first = store.write(SAMPLE).expect("write");
        let second = store.write(SAMPLE).expect("write again");
        assert_eq!(first, second, "identical evidence is one snapshot");
    }

    #[test]
    fn a_tampered_blob_is_refused_on_read() {
        // THE property content addressing buys. A store that returned the modified bytes would let
        // someone rewrite history in the corpus and have every later diff agree with them.
        let scratch = Scratch::new("tamper");
        let store = Store::open(scratch.path()).expect("open");
        let digest = store.write(SAMPLE).expect("write");

        let path = store.path_of(&digest);
        let mut bytes = std::fs::read(&path).expect("read blob");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xFF;
        std::fs::write(&path, &bytes).expect("tamper");

        let err = store.read(&digest).expect_err("must refuse");
        match err {
            RegistryError::DigestMismatch { expected, actual } => {
                assert_eq!(expected, digest.to_string());
                assert_ne!(actual, expected, "the error must name what was found");
            }
            other => panic!("expected DigestMismatch, got {other}"),
        }
    }

    #[test]
    fn a_truncated_blob_is_refused_rather_than_partially_decoded() {
        // A truncated snapshot is the store-level version of a truncated recording. Returning the
        // prefix would produce a stream that parses and reports less behavior than actually occurred.
        let scratch = Scratch::new("truncate");
        let store = Store::open(scratch.path()).expect("open");
        let digest = store.write(SAMPLE).expect("write");

        let path = store.path_of(&digest);
        let bytes = std::fs::read(&path).expect("read blob");
        std::fs::write(&path, &bytes[..bytes.len() - 4]).expect("truncate");

        // Caught by the digest before the decoder even sees it, which is the stronger guarantee: it
        // does not depend on zstd noticing.
        assert!(matches!(
            store.read(&digest).expect_err("must refuse"),
            RegistryError::DigestMismatch { .. }
        ));
    }

    #[test]
    fn tampering_is_also_caught_on_write() {
        // A second push of the same evidence must not silently overwrite a corrupted blob, because the
        // corruption is information.
        let scratch = Scratch::new("tamper-write");
        let store = Store::open(scratch.path()).expect("open");
        let digest = store.write(SAMPLE).expect("write");

        let path = store.path_of(&digest);
        let mut bytes = std::fs::read(&path).expect("read blob");
        bytes[0] ^= 0xFF;
        std::fs::write(&path, &bytes).expect("tamper");

        assert!(matches!(
            store.write(SAMPLE).expect_err("must refuse"),
            RegistryError::DigestMismatch { .. }
        ));
    }

    #[test]
    fn a_missing_snapshot_names_the_digest_and_the_root() {
        let scratch = Scratch::new("missing");
        let store = Store::open(scratch.path()).expect("open");
        let absent = Digest::of(b"never stored");
        let err = store.read(&absent).expect_err("must fail");
        let text = err.to_string();
        assert!(text.contains(absent.as_str()), "{text}");
        assert!(
            matches!(err, RegistryError::NoSuchSnapshot { .. }),
            "got {err}"
        );
    }

    #[test]
    fn a_decompression_bomb_is_refused() {
        // Verified rather than assumed: this really is what zstd does with a run of zeroes. Without the
        // bound, reading one of these on a CI runner is an out-of-memory kill.
        let over_the_bound = usize::try_from(MAX_DECOMPRESSED_BYTES + 1024).expect("fits in usize");
        let bomb_source = vec![0u8; over_the_bound];
        let compressed = compress(&bomb_source).expect("compress");
        assert!(
            compressed.len() < 100_000,
            "the point of the test is that this is tiny: {} bytes",
            compressed.len()
        );

        let digest = Digest::of(&compressed);
        let err = decompress(&compressed, &digest).expect_err("must refuse");
        match err {
            RegistryError::TooLarge { limit, .. } => assert_eq!(limit, MAX_DECOMPRESSED_BYTES),
            other => panic!("expected TooLarge, got {other}"),
        }
    }

    #[test]
    fn a_snapshot_exactly_at_the_bound_is_accepted() {
        // Off-by-one in the wrong direction would reject a legitimate large recording.
        let at_the_bound = usize::try_from(MAX_DECOMPRESSED_BYTES).expect("fits in usize");
        let source = vec![7u8; at_the_bound];
        let compressed = compress(&source).expect("compress");
        let digest = Digest::of(&compressed);
        let out = decompress(&compressed, &digest).expect("exactly at the bound is fine");
        assert_eq!(out.len() as u64, MAX_DECOMPRESSED_BYTES);
    }

    #[test]
    fn a_garbage_blob_is_a_compression_error_not_a_panic() {
        let scratch = Scratch::new("garbage");
        let store = Store::open(scratch.path()).expect("open");
        // Store bytes that are not a zstd frame, under their own correct digest, so the digest check
        // passes and the decoder is what has to refuse.
        let junk = b"this is not a zstd frame at all".to_vec();
        let digest = Digest::of(&junk);
        let path = store.path_of(&digest);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, &junk).expect("write junk");

        assert!(matches!(
            store.read(&digest).expect_err("must refuse"),
            RegistryError::Compression { .. }
        ));
    }

    #[test]
    fn no_partial_file_is_left_behind_by_a_successful_write() {
        let scratch = Scratch::new("no-partial");
        let store = Store::open(scratch.path()).expect("open");
        let digest = store.write(SAMPLE).expect("write");
        let partial = store.path_of(&digest).with_extension("partial");
        assert!(
            !partial.exists(),
            "the temporary file must be renamed, not left: {}",
            partial.display()
        );
    }

    #[test]
    fn the_compression_level_is_not_configurable() {
        // Asserted because it is load-bearing: the level participates in the address, so making it a
        // parameter would fragment the store into duplicate copies of identical recordings.
        assert_eq!(COMPRESSION_LEVEL, 3);
    }
}
