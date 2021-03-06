//! Filesystem-based [`KvStore`] implementation

pub mod std_filer;

#[cfg(not(test))]
pub mod sgx_filer;

// sgx_tstd (v1.1.3) does not support `fs::read_dir`, so limit the following to tests, for now.
//
// See: https://github.com/apache/incubator-teaclave-sgx-sdk/blob/v1.1.3/release_notes.md#partially-supported-modstraits-in-sgx_tstd
use std::io;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::prelude::v1::*;

use serde::de::DeserializeOwned;
use serde::Serialize;
#[cfg(not(test))]
pub use sgx_filer::SgxFiler;

use super::KvStore;

/// Simplified interface for reading and writing files.
pub trait Filer {
    /// Read content of `path`, if any.
    ///
    /// Return [`None`] if `path` doesn't exist.
    ///
    fn get(&self, path: impl AsRef<Path>) -> io::Result<Option<Vec<u8>>>;

    /// Write `content` to `path`. Discard any existing content.
    fn put(&self, path: impl AsRef<Path>, content: impl AsRef<[u8]>) -> io::Result<()>;

    /// Delete `path`. Discard any existing content.
    fn delete(&self, path: impl AsRef<Path>) -> io::Result<()>;
}

/// [`KvStore`] using a file per key under `root_dir`.
pub struct FsStore<F: Filer> {
    pub(crate) root_dir: PathBuf,
    pub(crate) filer: F,
}

impl<F> FsStore<F>
where
    F: Filer,
{
    /// # Note
    ///
    /// The caller must ensure that `root` exists as a directory.
    ///
    #[cfg_attr(not(test), allow(dead_code))] // currently only referenced in tests
    pub fn new(root: impl AsRef<Path>, filer: F) -> Self {
        let root_dir = root.as_ref().to_path_buf();
        FsStore { root_dir, filer }
    }

    /// Resolve file name for the value of `key`.
    fn value_path(&self, key: &str) -> PathBuf {
        let file_name = encode_to_fs_safe(key);
        self.root_dir.join(file_name)
    }
}

impl<F, V> KvStore<V> for FsStore<F>
where
    F: Filer,
    V: Serialize + DeserializeOwned,
{
    // XXX: More explicit handling of serde_json::Error?
    type Error = io::Error;

    fn load(&self, key: &str) -> Result<Option<V>, Self::Error> {
        let value_file_name = self.value_path(key);

        // Note: Read all the data into memory first, then deserialize, for efficiency.
        // See the docs for [`serde_json::de::from_reader`],
        // and https://github.com/serde-rs/json/issues/160
        let loaded: Option<Vec<u8>> = self.filer.get(&value_file_name).map_err(|err| {
            // XXX: Annotate err with some basic debugging context, for now.
            Self::Error::new(
                err.kind(),
                format!("FsStore: read from {:?} failed: {}", value_file_name, err),
            )
        })?;
        let value: Option<V> = loaded
            .map(|serialised: Vec<u8>| serde_json::from_slice(serialised.as_slice()))
            .transpose()?;
        Ok(value)
    }

    fn save(&mut self, key: &str, value: &V) -> Result<(), Self::Error> {
        let value_file_name = self.value_path(key);
        let serialized: Vec<u8> = serde_json::to_vec(&value)?;
        self.filer
            .put(&value_file_name, serialized)
            .map_err(|err| {
                // XXX: Annotate err with some basic debugging context, for now.
                Self::Error::new(
                    err.kind(),
                    format!("FsStore: write to {:?} failed: {}", value_file_name, err),
                )
            })?;
        Ok(())
    }

    fn delete(&mut self, key: &str) -> Result<(), Self::Error> {
        let path = self.value_path(key);
        self.filer.delete(path)?;
        Ok(())
    }
}

/// Helper: Make `key` filesystem-safe.
pub(crate) fn encode_to_fs_safe(key: &str) -> String {
    let encoded = hex::encode(key);
    format!("x{}", encoded)
}

/// Inverse of [`encode_to_fs_safe`].
// FIXME: Just use a generic String as the error type, for now.
#[cfg_attr(not(test), allow(dead_code))] // currently only referenced in tests
pub(crate) fn decode_from_fs_safe(file_name: &str) -> Result<String, String> {
    let encoded: &str = file_name
        .strip_prefix("x")
        .ok_or_else(|| format!("decode_from_fs_safe: missing x prefix for {:?}", file_name))?;
    let bytes: Vec<u8> = hex::decode(encoded).map_err(|err| err.to_string())?;
    let decoded = String::from_utf8(bytes).map_err(|err| err.to_string())?;
    Ok(decoded)
}

#[cfg(test)]
mod inspect;

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{decode_from_fs_safe, encode_to_fs_safe};

    /// [`encode_to_fs_safe`] encodes to filesystem-safe, and [`decode_from_fs_safe`] round-trips.
    #[test]
    fn prop_fs_safe_roundtrip() {
        let test = |key: &String| {
            let encoded = &encode_to_fs_safe(key);
            assert!(
                is_fs_safe(encoded),
                "expected filesystem-safe, got encoded = {:?}",
                encoded
            );
            let decoded = &decode_from_fs_safe(encoded).unwrap();
            assert_eq!(key, decoded);
        };
        proptest!(|(key in ".*")| test(&key));
    }

    /// Helper: Very conservative definition of filesystem-safe.
    fn is_fs_safe(encoded: &str) -> bool {
        !encoded.is_empty() && encoded.chars().all(|c| c.is_ascii_alphanumeric())
    }
}
