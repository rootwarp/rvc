//! Error types for gate- and service-guarded signing operations.
//!
//! # Signing error taxonomy (D3 / RF4-03)
//!
//! Both [`SigningGateError`] (rvc-signer / external path) and
//! [`crate::SignerError`] (VC / in-process path) distinguish two slashing-related
//! failures with **opposite** retry semantics:
//!
//! | Concept | Variants | DB write | Retry contract |
//! |---|---|---|---|
//! | **SlashingBlocked** | `SigningGateError::SlashingBlocked`, `SignerError::SlashingBlocked` | Slashable/policy stage rejections leave history that consumes slot/epoch semantics; pure stage I/O errors write nothing | **Never** treat as `CommitFailed` same-root advertising. Different-root retry for the same slot/epoch is unsafe after a slashable stage rejection. EIP-3076 same-root re-sign after a prior successful commit is a separate stage path — not what [`SigningGateError::permits_retry_with_root`] / `SignerError::permits_retry_with_root` authorize. |
//! | **CommitFailed** | `SigningGateError::CommitFailed`, `SignerError::CommitFailed` | Nothing written (txn rolled back) | Same-root retry is **safe**. Different-root retry must be refused by the caller (use the carried `signing_root`). |
//!
//! # Transport classification
//!
//! External transports (gRPC and HTTP) must not match on [`SigningGateError`]
//! variants directly. Call [`classify`] once and map [`GateErrClass`] to the
//! transport status + sanitized body. That keeps both edges on one taxonomy so
//! sanitization cannot drift.

use eth_types::Root;
use slashing::SlashingError;
use thiserror::Error;

/// Errors that can occur during gate-guarded signing operations.
#[derive(Debug, Error)]
pub enum SigningGateError {
    /// The doppelganger gate denied signing for this pubkey.
    ///
    /// Either the validator is not yet cleared through the monitoring window, or
    /// the pubkey is unknown to the enablement implementation (fail-closed).
    ///
    /// The slot/epoch was NOT consumed: no slashing-DB row was written.
    #[error("signing blocked by doppelganger gate")]
    BlockedByDoppelganger,

    /// The slashing-protection database rejected the sign request at the *stage*
    /// step — a potential double-vote or double-block-proposal was detected.
    ///
    /// See module-level **SlashingBlocked** retry contract: do not retry with a
    /// different root for the same slot/epoch.
    ///
    /// Display intentionally omits the raw `SlashingError` internals (which may
    /// contain SQLite paths or lock messages) so this variant is safe to surface
    /// to API callers.  The underlying error is available via `source()`.
    #[error("signing blocked by slashing protection")]
    SlashingBlocked(#[source] SlashingError),

    /// Slashing-protection persist failed; no new history row was written.
    ///
    /// Production `reserve_then_sign` maps reserve-time `ReserveCommitFailed`
    /// here (no sign is attempted). The retained `stage_then_sign` path emits
    /// this when `commit()` fails after a successful BLS sign.
    ///
    /// See module-level **CommitFailed** retry contract: same-root retry is safe;
    /// `signing_root` is the only root a caller may retry with.  Any BLS
    /// signature bytes from a post-sign commit failure are lost.
    ///
    /// Display intentionally omits raw SQLite internals.  The underlying error
    /// is available via `source()`.
    #[error("slashing-protection commit failed (no row written; same-root retry is safe)")]
    CommitFailed {
        /// Signing root that was staged (and must be used for any retry).
        signing_root: Root,
        #[source]
        source: SlashingError,
    },

    /// The BLS signing backend failed, timed out, or the blocking task panicked.
    ///
    /// # Reserved-row fate (do not assume discard)
    ///
    /// Production [`crate::sign_slashable`] commits the history row **before**
    /// the sign (`reserve_then_sign`). Fate of that row:
    ///
    /// | Cause | Row fate |
    /// |---|---|
    /// | Unambiguous no-signature (`KeyNotFound`, `LocalRejected`, `UnsupportedSigningType`, `UnsupportedDuty`) | `reconcile_unsigned` (failed delete **retains**) |
    /// | Sign **timeout** + [`crate::TimeoutPolicy::DiscardStagedRow`] | `reconcile_unsigned` (failed delete **retains**) |
    /// | Sign **timeout** + [`crate::TimeoutPolicy::RetainStagedRow`] | row already committed (no action) |
    /// | Ambiguous backend error + [`crate::TimeoutPolicy::DiscardStagedRow`] | `reconcile_unsigned` (failed delete **retains**) |
    /// | Ambiguous backend error + [`crate::TimeoutPolicy::RetainStagedRow`] | row already committed (no action) |
    /// | Panic of the blocking task after reserve | row already committed; sign never released |
    ///
    /// A failed compensating delete **retains** the row (C1) for every class
    /// that calls `reconcile_unsigned`.
    ///
    /// Callers **must not** treat `SigningFailed` as “slot free / different-root
    /// retry safe.” After a retain path, a conflicting different-root retry is
    /// blocked by reserve (EIP-3076); only same-root re-sign may apply.
    /// [`SigningGateError::permits_retry_with_root`] does **not** special-case
    /// this variant (it only authorizes `CommitFailed` same-root retry).
    ///
    /// See [`crate::TimeoutPolicy`]: policy applies to timeout **and** ambiguous
    /// non-timeout signer errors (not `KeyNotFound`).
    #[error("signing backend failed: {0}")]
    SigningFailed(String),

    /// The signing backend has no key for the requested pubkey.
    ///
    /// No signature was produced. Production `reserve_then_sign` reconciles
    /// the reserved row; a failed delete retains it (see the table on
    /// [`Self::SigningFailed`]). Not used for retain-on-timeout.
    #[error("key not found in signing backend")]
    KeyNotFound,

    /// The pubkey is not registered with the signing enablement implementation.
    ///
    /// Currently **unconstructed** by the gate.  When an unknown pubkey is
    /// presented, `SigningEnablement::is_signing_enabled` returns `false` (the
    /// fail-closed default) and the gate returns `BlockedByDoppelganger` —
    /// it cannot distinguish "unknown pubkey" from "doppelganger-blocked pubkey"
    /// because `is_signing_enabled` exposes only a `bool`, not a status enum.
    ///
    /// This variant is retained for the future path where `SigningEnablement`
    /// is extended to return a richer status (unknown vs. blocked vs. allowed),
    /// at which point the gate can route unknown pubkeys here instead of into
    /// `BlockedByDoppelganger`.
    #[error("pubkey not registered with signing gate")]
    UnknownPubkey,
}

impl SigningGateError {
    /// Taxonomy-level check for **commit-failure same-root retry** only.
    ///
    /// - `CommitFailed` → `true` only when `proposed_root` equals the carried root.
    /// - `SlashingBlocked` → always `false` here (conservative; not an EIP-3076
    ///   same-root re-sign oracle — that is a separate stage check).
    /// - Other variants → `false`.
    ///
    /// Not a general oracle for stage I/O recoverability.
    pub fn permits_retry_with_root(&self, proposed_root: &Root) -> bool {
        match self {
            Self::CommitFailed { signing_root, .. } => signing_root == proposed_root,
            Self::SlashingBlocked(_) => false,
            _ => false,
        }
    }
}

/// Bounded classification of a [`SigningGateError`] for external transports.
///
/// gRPC and HTTP map this enum to their status codes; neither transport should
/// match on [`SigningGateError`] variants directly.
///
/// # HTTP status for `CommitFailed`
///
/// `CommitFailed` maps to **HTTP 500** / gRPC `Internal` (not 412 /
/// `FailedPrecondition`). The sign itself succeeded and same-root retry is
/// safe; clients should treat this as a retriable server fault, not a
/// permanent slashing rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateErrClass {
    /// Doppelganger enablement denied the pubkey.
    BlockedByDoppelganger,
    /// Stage-time rejection (slashable conflict or DB I/O during stage).
    ///
    /// `client_message` is always sanitized for the wire (slot/epoch detail for
    /// real violations; a static generic string for DB internals).
    SlashingBlocked {
        /// Client-safe body text.
        client_message: String,
        /// `true` for `SlashableBlock` / `SlashableAttestation`.
        is_slashable_violation: bool,
        /// Server-side detail to log when the client message is generic.
        log_detail: Option<String>,
    },
    /// Slashing-DB persist failed; no new history row (same-root retry safe).
    CommitFailed {
        /// Server-side detail (SQLite path / lock message) — log only.
        log_detail: String,
    },
    /// Backend has no key, or pubkey is unregistered with the gate.
    KeyNotFound,
    /// BLS backend failure, timeout, or task panic.
    Internal {
        /// Server-side backend detail — log only.
        log_detail: String,
    },
}

impl GateErrClass {
    /// Client-safe response body. Never contains SQLite paths or backend internals.
    pub fn client_message(&self) -> &str {
        match self {
            Self::BlockedByDoppelganger => "signing blocked by doppelganger gate",
            Self::SlashingBlocked { client_message, .. } => client_message.as_str(),
            Self::CommitFailed { .. } => "slashing DB commit failed; same-root retry is safe",
            Self::KeyNotFound => "unknown public key",
            Self::Internal { .. } => "internal signing error",
        }
    }

    /// Bounded metrics / audit label shared by gRPC and HTTP.
    ///
    /// Values: `doppelganger`, `slashing`, `slashing_db_error`, `key_not_found`,
    /// `internal`. Cardinality is fixed regardless of error message content.
    pub fn metrics_label(&self) -> &'static str {
        match self {
            Self::BlockedByDoppelganger => "doppelganger",
            Self::SlashingBlocked { is_slashable_violation: true, .. } => "slashing",
            Self::SlashingBlocked { is_slashable_violation: false, .. } => "slashing_db_error",
            Self::CommitFailed { .. } | Self::Internal { .. } => "internal",
            Self::KeyNotFound => "key_not_found",
        }
    }

    /// Emit the server-side `error!` log for classes whose client body is sanitized.
    ///
    /// Safe to call once per classified error at the transport edge.
    pub fn emit_server_log(&self) {
        match self {
            Self::SlashingBlocked { log_detail: Some(detail), .. } => {
                tracing::error!(error = %detail, "slashing DB error during staging");
            }
            Self::CommitFailed { log_detail } => {
                tracing::error!(
                    error = %log_detail,
                    "slashing DB persist failed; no new history row"
                );
            }
            Self::Internal { log_detail } => {
                tracing::error!(error = %log_detail, "signing backend error");
            }
            Self::BlockedByDoppelganger
            | Self::KeyNotFound
            | Self::SlashingBlocked { log_detail: None, .. } => {}
        }
    }
}

/// Classify a gate error for external transport mapping.
///
/// Pure with respect to the returned class (no I/O). Server-side logging of
/// sanitized-away detail is left to [`GateErrClass::emit_server_log`] so
/// metrics classification can call this without double-logging.
///
/// The match is exhaustive over [`SigningGateError`]: adding a variant is a
/// compile error here, which forces both transports to pick up the new class.
pub fn classify(err: &SigningGateError) -> GateErrClass {
    match err {
        SigningGateError::BlockedByDoppelganger => GateErrClass::BlockedByDoppelganger,
        SigningGateError::SlashingBlocked(inner) => match inner {
            // Slot/epoch violation detail is safe to surface on the wire.
            SlashingError::SlashableBlock(_) | SlashingError::SlashableAttestation(_) => {
                GateErrClass::SlashingBlocked {
                    client_message: format!("slashing protection violation: {inner}"),
                    is_slashable_violation: true,
                    log_detail: None,
                }
            }
            // Other DB errors may contain rusqlite paths / lock messages.
            other => GateErrClass::SlashingBlocked {
                client_message: "slashing protection error".to_string(),
                is_slashable_violation: false,
                log_detail: Some(other.to_string()),
            },
        },
        SigningGateError::CommitFailed { source: inner, .. } => {
            GateErrClass::CommitFailed { log_detail: inner.to_string() }
        }
        SigningGateError::KeyNotFound | SigningGateError::UnknownPubkey => {
            GateErrClass::KeyNotFound
        }
        SigningGateError::SigningFailed(msg) => GateErrClass::Internal { log_detail: msg.clone() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slashing::{AttestationSlashingViolation, BlockSlashingViolation};

    fn all_gate_errors() -> Vec<SigningGateError> {
        vec![
            SigningGateError::BlockedByDoppelganger,
            SigningGateError::SlashingBlocked(SlashingError::SlashableBlock(
                BlockSlashingViolation::DoubleBlockProposal { slot: 1 },
            )),
            SigningGateError::SlashingBlocked(SlashingError::SlashableAttestation(
                AttestationSlashingViolation::DoubleVote { target_epoch: 2 },
            )),
            SigningGateError::SlashingBlocked(SlashingError::MigrationFailed(
                "/secret/path.db lock".into(),
            )),
            SigningGateError::CommitFailed {
                signing_root: [0u8; 32],
                source: SlashingError::MigrationFailed("/secret/commit.db".into()),
            },
            SigningGateError::KeyNotFound,
            SigningGateError::UnknownPubkey,
            SigningGateError::SigningFailed("blst internal x0042".into()),
        ]
    }

    #[test]
    fn test_classify_is_exhaustive_over_gate_errors() {
        // If a new SigningGateError variant is added, `classify` fails to compile
        // until this table and both transport mappers are updated. Runtime check:
        // every constructed variant produces a defined class.
        for err in all_gate_errors() {
            let class = classify(&err);
            assert!(!class.client_message().is_empty());
            assert!(!class.metrics_label().is_empty());
        }
    }

    #[test]
    fn test_sanitized_messages_are_static_and_leak_free() {
        let secret = "/var/lib/rvc/slashing.db lock contention";
        let cases: Vec<(SigningGateError, &str, bool)> = vec![
            (
                SigningGateError::BlockedByDoppelganger,
                "signing blocked by doppelganger gate",
                false,
            ),
            (
                SigningGateError::SlashingBlocked(SlashingError::MigrationFailed(secret.into())),
                "slashing protection error",
                true,
            ),
            (
                SigningGateError::CommitFailed {
                    signing_root: [9u8; 32],
                    source: SlashingError::MigrationFailed(secret.into()),
                },
                "slashing DB commit failed; same-root retry is safe",
                true,
            ),
            (SigningGateError::KeyNotFound, "unknown public key", false),
            (SigningGateError::UnknownPubkey, "unknown public key", false),
            (
                SigningGateError::SigningFailed("blst internal x0042".into()),
                "internal signing error",
                true,
            ),
        ];
        for (err, expected_msg, must_not_leak) in cases {
            let class = classify(&err);
            assert_eq!(class.client_message(), expected_msg, "err={err:?}");
            if must_not_leak {
                assert!(
                    !class.client_message().contains(secret),
                    "client message leaked secret: {}",
                    class.client_message()
                );
                assert!(
                    !class.client_message().contains("x0042"),
                    "client message leaked backend detail: {}",
                    class.client_message()
                );
                assert!(
                    !class.client_message().contains(".db"),
                    "client message leaked path: {}",
                    class.client_message()
                );
            }
        }

        let violation = SigningGateError::SlashingBlocked(SlashingError::SlashableBlock(
            BlockSlashingViolation::DoubleBlockProposal { slot: 42 },
        ));
        let class = classify(&violation);
        assert!(
            class.client_message().contains("42"),
            "slot detail must surface: {}",
            class.client_message()
        );
        assert!(matches!(
            class,
            GateErrClass::SlashingBlocked { is_slashable_violation: true, .. }
        ));
    }

    #[test]
    fn test_metrics_label_taxonomy() {
        assert_eq!(
            classify(&SigningGateError::BlockedByDoppelganger).metrics_label(),
            "doppelganger"
        );
        assert_eq!(
            classify(&SigningGateError::SlashingBlocked(SlashingError::SlashableBlock(
                BlockSlashingViolation::DoubleBlockProposal { slot: 1 },
            )))
            .metrics_label(),
            "slashing"
        );
        assert_eq!(
            classify(&SigningGateError::SlashingBlocked(SlashingError::MigrationFailed(
                "x".into()
            )))
            .metrics_label(),
            "slashing_db_error"
        );
        assert_eq!(
            classify(&SigningGateError::CommitFailed {
                signing_root: [0u8; 32],
                source: SlashingError::MigrationFailed("x".into()),
            })
            .metrics_label(),
            "internal"
        );
        assert_eq!(classify(&SigningGateError::KeyNotFound).metrics_label(), "key_not_found");
        assert_eq!(classify(&SigningGateError::UnknownPubkey).metrics_label(), "key_not_found");
        assert_eq!(
            classify(&SigningGateError::SigningFailed("x".into())).metrics_label(),
            "internal"
        );
    }
}
