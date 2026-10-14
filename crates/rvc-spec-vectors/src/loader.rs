//! Path-injected consensus-spec vector loader.
//!
//! Walks `tests/<config>/<fork>/<runner>/<handler>/<suite>/<case>/` under an
//! explicit root directory. Never reads the environment.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// `snap::raw::Decoder::decompress_vec` allocates `claimed_len` before validating
/// the body; cap that allocation. 128 MiB covers mainnet `BeaconState` vectors.
const MAX_SNAPPY_UNCOMPRESSED: usize = 128 * 1024 * 1024;

/// Failure while constructing a [`VectorRoot`] or parsing a case file.
#[derive(Debug, Error)]
pub enum VectorError {
    /// `dir` is missing or not a directory.
    #[error("vector root is not a directory: {path}")]
    MissingRoot { path: PathBuf },

    /// Filesystem error while walking or reading `path`.
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// `fork` / `runner` / `handler` was not a single normal path component.
    #[error("invalid path segment `{segment}`: must be a single normal component")]
    InvalidSegment { segment: String },

    /// A discovered case directory resolved outside the injected root.
    #[error("vector case path escapes root {root}: {path}")]
    PathEscape { root: PathBuf, path: PathBuf },

    /// `serialized.ssz_snappy` (or equivalent bytes) is not valid snappy.
    #[error("malformed snappy: {0}")]
    Snappy(#[from] snap::Error),

    /// Snappy varint claimed more uncompressed bytes than the 128 MiB cap.
    #[error("snappy claimed length {claimed} exceeds {max} bytes")]
    SnappyTooLarge { claimed: usize, max: usize },

    /// `roots.yaml` (or equivalent text) is not valid YAML / mapping.
    #[error("malformed YAML: {0}")]
    Yaml(String),
}

/// Extracted vector cache (or a hermetic fixture tree) whose layout is
/// `tests/<config>/<fork>/<runner>/<handler>/<suite>/<case>/`.
#[derive(Debug, Clone)]
pub struct VectorRoot {
    dir: PathBuf,
}

/// One spec-test case directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorCase {
    /// Absolute or caller-supplied path to the case directory.
    pub path: PathBuf,
    /// Preset / config directory name (`minimal`, `mainnet`, …).
    pub config: String,
    /// Fork directory name (`electra`, …).
    pub fork: String,
    /// Runner directory name (`ssz_static`, …).
    pub runner: String,
    /// Handler directory name (`AttestationData`, …).
    pub handler: String,
    /// Suite directory name (`ssz_random`, …).
    pub suite: String,
    /// Case directory name (`case_0`, …).
    pub case: String,
}

/// Iterator over [`VectorCase`]s for one `(fork, runner, handler)`.
///
/// [`cases_run`](Self::cases_run) is the discovered count, available before
/// iteration so suite runners can assert non-vacuity.
#[derive(Debug)]
pub struct Cases {
    inner: std::vec::IntoIter<VectorCase>,
    total: usize,
}

/// Parsed `roots.yaml` (`root` required, `signing_root` optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roots {
    pub root: String,
    pub signing_root: Option<String>,
}

impl VectorRoot {
    /// Treat `dir` as a vector root. Fails if it is not an existing directory.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::MissingRoot`] naming `dir` when it is not a directory.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, VectorError> {
        let dir = dir.as_ref().to_path_buf();
        if !dir.is_dir() {
            return Err(VectorError::MissingRoot { path: dir });
        }
        Ok(Self { dir })
    }

    /// Directory passed to [`VectorRoot::new`].
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Cases under `tests/<config>/<fork>/<runner>/<handler>/`.
    ///
    /// Every config directory is visited. Missing handler paths yield an empty
    /// iterator (`cases_run == 0`); a missing root is [`VectorError::MissingRoot`].
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::InvalidSegment`] if `fork`, `runner`, or `handler`
    /// is not a single normal path component; [`VectorError::PathEscape`] if a
    /// case directory resolves outside this root; [`VectorError::Io`] if a
    /// directory cannot be read.
    pub fn cases(&self, fork: &str, runner: &str, handler: &str) -> Result<Cases, VectorError> {
        let fork = normal_segment(fork)?;
        let runner = normal_segment(runner)?;
        let handler = normal_segment(handler)?;
        let tests_dir = self.dir.join("tests");
        let mut found = Vec::new();
        if !tests_dir.is_dir() {
            return Ok(Cases::from_vec(found));
        }
        for config_path in read_dir_sorted(&tests_dir)? {
            if !config_path.is_dir() {
                continue;
            }
            let handler_dir = config_path.join(fork).join(runner).join(handler);
            if !handler_dir.is_dir() {
                continue;
            }
            let config = file_name(&config_path);
            for suite_path in read_dir_sorted(&handler_dir)? {
                if !suite_path.is_dir() {
                    continue;
                }
                let suite = file_name(&suite_path);
                for case_path in read_dir_sorted(&suite_path)? {
                    if !is_case_dir(&case_path) {
                        continue;
                    }
                    ensure_under(&self.dir, &case_path)?;
                    let case = file_name(&case_path);
                    found.push(VectorCase {
                        path: case_path,
                        config: config.clone(),
                        fork: fork.to_owned(),
                        runner: runner.to_owned(),
                        handler: handler.to_owned(),
                        suite: suite.clone(),
                        case,
                    });
                }
            }
        }
        Ok(Cases::from_vec(found))
    }
}

impl Cases {
    fn from_vec(cases: Vec<VectorCase>) -> Self {
        let total = cases.len();
        Self { inner: cases.into_iter(), total }
    }

    /// Number of cases discovered for this `(fork, runner, handler)`.
    pub fn cases_run(&self) -> usize {
        self.total
    }
}

impl Iterator for Cases {
    type Item = VectorCase;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for Cases {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Decompress raw (block) snappy bytes from `serialized.ssz_snappy`.
///
/// # Errors
///
/// Returns [`VectorError::SnappyTooLarge`] when the snappy varint claims more
/// than 128 MiB, or [`VectorError::Snappy`] when `compressed` is not valid snappy.
pub fn decode_snappy(compressed: &[u8]) -> Result<Vec<u8>, VectorError> {
    let claimed = snap::raw::decompress_len(compressed)?;
    if claimed > MAX_SNAPPY_UNCOMPRESSED {
        return Err(VectorError::SnappyTooLarge { claimed, max: MAX_SNAPPY_UNCOMPRESSED });
    }
    Ok(snap::raw::Decoder::new().decompress_vec(compressed)?)
}

/// Parse a `roots.yaml` document.
///
/// # Errors
///
/// Returns [`VectorError::Yaml`] on syntax errors or a missing `root` string.
pub fn roots_yaml(yaml: &str) -> Result<Roots, VectorError> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|e| VectorError::Yaml(e.to_string()))?;
    let mapping = value
        .as_mapping()
        .ok_or_else(|| VectorError::Yaml("roots.yaml must be a mapping".to_owned()))?;
    let root = yaml_string(mapping, "root")?
        .ok_or_else(|| VectorError::Yaml("missing string field `root`".to_owned()))?;
    let signing_root = yaml_string(mapping, "signing_root")?;
    Ok(Roots { root, signing_root })
}

fn yaml_string(mapping: &serde_yaml::Mapping, field: &str) -> Result<Option<String>, VectorError> {
    let key = serde_yaml::Value::String(field.to_owned());
    match mapping.get(&key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s.clone())),
        // YAML 1.1 + serde_yaml 0.9: unquoted `0x` + ≤16 hex digits is a Number
        // (all-zero 32-byte roots included). Wider unquoted HTRs stay strings.
        Some(serde_yaml::Value::Number(n)) => Ok(Some(yaml_number_as_root_hex(n, field)?)),
        Some(_) => {
            Err(VectorError::Yaml(format!("field `{field}` must be a string or integer scalar")))
        }
    }
}

fn yaml_number_as_root_hex(n: &serde_yaml::Number, field: &str) -> Result<String, VectorError> {
    let Some(u) = n.as_u64() else {
        return Err(VectorError::Yaml(format!(
            "field `{field}` must be a string or integer scalar"
        )));
    };
    Ok(format!("0x{u:064x}"))
}

fn normal_segment(segment: &str) -> Result<&str, VectorError> {
    if is_single_normal_component(segment) {
        Ok(segment)
    } else {
        Err(VectorError::InvalidSegment { segment: segment.to_owned() })
    }
}

fn is_single_normal_component(segment: &str) -> bool {
    if segment.is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('\0')
    {
        return false;
    }
    let mut comps = Path::new(segment).components();
    matches!((comps.next(), comps.next()), (Some(Component::Normal(_)), None))
}

fn ensure_under(root: &Path, child: &Path) -> Result<(), VectorError> {
    let root_c = fs::canonicalize(root)
        .map_err(|source| VectorError::Io { path: root.to_path_buf(), source })?;
    let child_c = fs::canonicalize(child)
        .map_err(|source| VectorError::Io { path: child.to_path_buf(), source })?;
    if child_c.starts_with(&root_c) {
        Ok(())
    } else {
        Err(VectorError::PathEscape { root: root_c, path: child_c })
    }
}

fn read_dir_sorted(path: &Path) -> Result<Vec<PathBuf>, VectorError> {
    let mut entries = Vec::new();
    let dir = fs::read_dir(path)
        .map_err(|source| VectorError::Io { path: path.to_path_buf(), source })?;
    for ent in dir {
        let ent = ent.map_err(|source| VectorError::Io { path: path.to_path_buf(), source })?;
        entries.push(ent.path());
    }
    entries.sort();
    Ok(entries)
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn is_case_dir(path: &Path) -> bool {
    path.is_dir()
        && (path.join("serialized.ssz_snappy").is_file()
            || path.join("roots.yaml").is_file()
            || path.join("value.yaml").is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_snappy_roundtrip() {
        let payload = b"attestation-data-ssz";
        let compressed = snap::raw::Encoder::new().compress_vec(payload).unwrap();
        assert_eq!(decode_snappy(&compressed).unwrap(), payload);
    }

    #[test]
    fn roots_yaml_reads_optional_signing_root_field() {
        let parsed = roots_yaml("root: '0x00'\nsigning_root: '0x01'\n").unwrap();
        assert_eq!(parsed.root, "0x00");
        assert_eq!(parsed.signing_root.as_deref(), Some("0x01"));
    }

    #[test]
    fn roots_yaml_accepts_unquoted_all_zero_bytes32() {
        let parsed = roots_yaml(
            "root: 0x0000000000000000000000000000000000000000000000000000000000000000\n",
        )
        .unwrap();
        assert_eq!(
            parsed.root,
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn roots_yaml_accepts_unquoted_32_byte_htr() {
        let htr = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed = roots_yaml(&format!("root: {htr}\n")).unwrap();
        assert_eq!(parsed.root, htr);
    }

    #[test]
    fn cases_rejects_parent_dir_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let root = VectorRoot::new(tmp.path()).unwrap();
        let err = root.cases("..", "ssz_static", "AttestationData").unwrap_err();
        assert!(
            matches!(err, VectorError::InvalidSegment { ref segment } if segment == ".."),
            "{err:?}"
        );
    }

    #[test]
    fn cases_rejects_absolute_and_multi_component_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let root = VectorRoot::new(tmp.path()).unwrap();
        let abs = root.cases("electra", "ssz_static", "/etc").unwrap_err();
        assert!(matches!(abs, VectorError::InvalidSegment { .. }), "{abs:?}");
        let nested = root.cases("electra/ssz_static", "AttestationData", "x").unwrap_err();
        assert!(matches!(nested, VectorError::InvalidSegment { .. }), "{nested:?}");
    }

    #[cfg(unix)]
    #[test]
    fn cases_rejects_symlink_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let root_dir = tmp.path().join("root");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("roots.yaml"), "root: '0x00'\n").unwrap();
        let case_parent =
            root_dir.join("tests/minimal/electra/ssz_static/AttestationData/ssz_random");
        std::fs::create_dir_all(&case_parent).unwrap();
        std::os::unix::fs::symlink(&outside, case_parent.join("case_0")).unwrap();

        let root = VectorRoot::new(&root_dir).unwrap();
        let err = root.cases("electra", "ssz_static", "AttestationData").unwrap_err();
        assert!(matches!(err, VectorError::PathEscape { .. }), "{err:?}");
    }

    fn snappy_len_header(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
        out
    }

    #[test]
    fn decode_snappy_rejects_16mib_claim_with_tiny_body() {
        let mut bytes = snappy_len_header(16 * 1024 * 1024);
        bytes.extend_from_slice(&[0xff, 0x00]);
        let err = decode_snappy(&bytes).expect_err("16 MiB claim with tiny body must fail");
        assert!(
            matches!(err, VectorError::Snappy(_) | VectorError::SnappyTooLarge { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn decode_snappy_rejects_claimed_length_above_cap() {
        let claimed = (MAX_SNAPPY_UNCOMPRESSED as u64) + 1;
        let err = decode_snappy(&snappy_len_header(claimed)).expect_err("oversize claim");
        match err {
            VectorError::SnappyTooLarge { claimed: n, max } => {
                assert_eq!(n, MAX_SNAPPY_UNCOMPRESSED + 1);
                assert_eq!(max, MAX_SNAPPY_UNCOMPRESSED);
            }
            other => panic!("expected SnappyTooLarge, got {other:?}"),
        }
    }
}
