#[derive(Debug, thiserror::Error)]
pub enum ValidatorStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("config error: {0}")]
    Config(String),
    /// The durable update did not publish.
    ///
    /// The pubkey was absent when the candidate was cloned, or its identity
    /// changed during the write (removed or replaced) and the in-flight delta
    /// was dropped. Neither case is a successful publish.
    #[error("validator not found")]
    NotFound,
}
