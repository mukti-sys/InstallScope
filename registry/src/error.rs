//! Typed errors for the snapshot store and the diff engine.
//!
//! Every variant names the digest or path involved. A registry that reports "verification failed"
//! without saying which blob leaves an operator with a store they cannot reason about, and the whole
//! point of content addressing is that the failure is *locatable*.

/// Why a registry operation failed.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A blob's contents do not hash to the digest it is stored under.
    ///
    /// The failure content addressing exists to detect. Treated as fatal rather than as a warning: a
    /// snapshot that does not match its address is not weaker evidence, it is evidence of unknown
    /// provenance, and a behavioral diff computed from it would be a confident statement about bytes
    /// nobody can account for.
    #[error(
        "snapshot {expected} does not match its contents (found {actual}); the stored blob has been \
         modified or corrupted and must not be used as evidence"
    )]
    DigestMismatch {
        /// The digest the blob is stored under.
        expected: String,
        /// The digest its contents actually produce.
        actual: String,
    },

    /// A digest string was not a 64-character lowercase hex sha256.
    ///
    /// Validated because a digest becomes a path component. A digest containing `..` or `/` would let
    /// a crafted index entry read outside the store.
    #[error("{value:?} is not a sha256 digest: {reason}")]
    InvalidDigest {
        /// The offending text.
        value: String,
        /// What is wrong with it.
        reason: &'static str,
    },

    /// A snapshot was requested that the store does not hold.
    #[error("no snapshot {digest} in the store at {root}")]
    NoSuchSnapshot {
        /// The digest requested.
        digest: String,
        /// The store root searched.
        root: std::path::PathBuf,
    },

    /// A package version was requested that the index does not list.
    #[error("no recording of {package}@{version} in the index at {index}")]
    NoSuchVersion {
        /// Package name requested.
        package: String,
        /// Version requested.
        version: String,
        /// Index consulted.
        index: std::path::PathBuf,
    },

    /// A decompressed snapshot exceeded the size bound.
    ///
    /// A bound exists because a snapshot can arrive from anywhere: a few kilobytes of zstd expands to
    /// gigabytes if it was built to. Verified locally — 2065 compressed bytes expand to 64 MiB — so
    /// this is a real property of the format rather than a theoretical concern.
    #[error(
        "snapshot {digest} decompresses to more than {limit} bytes; refusing to continue rather than \
         exhausting memory on an untrusted blob"
    )]
    TooLarge {
        /// The digest being read.
        digest: String,
        /// The bound that was hit.
        limit: u64,
    },

    /// An index line was not a valid entry.
    ///
    /// Refused rather than skipped: an index that silently drops the lines it cannot read reports a
    /// smaller corpus than exists, and a diff against a version the index "does not have" would look
    /// like a first recording.
    #[error("index line {line} in {path} is not a valid entry: {source}")]
    MalformedIndexEntry {
        /// 1-based line number.
        line: usize,
        /// The index file.
        path: std::path::PathBuf,
        /// The underlying failure.
        #[source]
        source: serde_json::Error,
    },

    /// The event stream in a snapshot could not be read.
    #[error("snapshot {digest} does not contain a readable event stream: {source}")]
    UnreadableStream {
        /// The digest being read.
        digest: String,
        /// The underlying failure.
        #[source]
        source: installscope_core::CoreError,
    },

    /// A snapshot was pushed for a recording that is PARTIAL.
    ///
    /// Refused at the boundary. A registry is the durable record, and a version-to-version diff drawn
    /// against an incomplete recording would attribute the recorder's failure to the package —
    /// reporting behavior as "removed in 1.2.4" when the recorder simply stopped early. PRD.md:58
    /// makes silent incompleteness the worst failure mode of this product; the store is where it would
    /// become permanent.
    #[error(
        "refusing to store a PARTIAL recording of {package}@{version}: {reasons}. A diff against an \
         incomplete recording would attribute the recorder's failure to the package."
    )]
    PartialRecording {
        /// Package the recording claims to be of.
        package: String,
        /// Version.
        version: String,
        /// Why the recording is incomplete.
        reasons: String,
    },

    /// Compression or decompression failed.
    #[error("zstd {operation} failed: {source}")]
    Compression {
        /// Which direction.
        operation: &'static str,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// I/O against the store.
    #[error("i/o error on {path}: {source}")]
    Io {
        /// The path involved.
        path: std::path::PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

impl RegistryError {
    /// Attaches a path to an I/O error.
    pub fn io(path: impl Into<std::path::PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Convenience alias for this crate.
pub type Result<T> = std::result::Result<T, RegistryError>;
