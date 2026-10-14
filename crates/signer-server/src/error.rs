//! Server-boundary error types for `rvc-signer`.
//!
//! Interior paths still surface `Box<dyn Error>` / string messages in places;
//! only the `server::run` boundary is classified here (RF5-19). Further
//! decomposition (RF5-20/21) tightens the interior.

use std::fmt;

/// Display + `Error` wrapper so string messages can carry `#[source]`.
#[derive(Debug)]
pub struct Detail(pub String);

impl Detail {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Detail {}

impl From<String> for Detail {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Detail {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for Detail {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self(e.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for Detail {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        Self(e.to_string())
    }
}

/// Failure classes at the `server::run` boundary.
///
/// Process exit code is still `1` for every variant (unchanged from the
/// pre-extraction `Box<dyn Error>` path). Classification is for tests and
/// future structured handling.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Slashing-protection gate or database open/validate failures.
    #[error("slashing protection error: {0}")]
    SlashingDb(#[source] Detail),

    /// Signing-backend construction / keystore load failures.
    #[error("backend error: {0}")]
    Backend(#[source] Detail),

    /// TLS material load or server TLS configuration failures.
    #[error("TLS error: {0}")]
    Tls(#[source] Detail),

    /// Listen/bind or serve accept-loop failures (gRPC, HTTP, metrics).
    #[error("bind error: {0}")]
    Bind(#[source] Detail),

    /// Configuration / password / flag resolution failures.
    #[error("configuration error: {0}")]
    Config(#[source] Detail),

    /// Raw I/O failures.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A supervised child panicked, or shutdown exceeded its deadline.
    #[error("server runtime error: {0}")]
    Runtime(#[source] Detail),
}

impl ServerError {
    pub fn slashing_db(msg: impl Into<Detail>) -> Self {
        Self::SlashingDb(msg.into())
    }

    pub fn backend(msg: impl Into<Detail>) -> Self {
        Self::Backend(msg.into())
    }

    pub fn tls(msg: impl Into<Detail>) -> Self {
        Self::Tls(msg.into())
    }

    pub fn bind(msg: impl Into<Detail>) -> Self {
        Self::Bind(msg.into())
    }

    pub fn config(msg: impl Into<Detail>) -> Self {
        Self::Config(msg.into())
    }

    pub fn runtime(msg: impl Into<Detail>) -> Self {
        Self::Runtime(msg.into())
    }
}

/// Default interior `Box<dyn Error>` → `Config` so `?` keeps working on the
/// moved body; explicit sites override with the correct variant.
impl From<Box<dyn std::error::Error>> for ServerError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        Self::Config(Detail::from(e))
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ServerError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::Config(Detail::from(e))
    }
}

impl From<String> for ServerError {
    fn from(s: String) -> Self {
        Self::Config(Detail(s))
    }
}

impl From<&str> for ServerError {
    fn from(s: &str) -> Self {
        Self::Config(Detail(s.to_string()))
    }
}
