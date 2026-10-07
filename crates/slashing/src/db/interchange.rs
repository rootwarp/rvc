//! EIP-3076 interchange import/export and genesis validators root metadata.
//!
//! Pure code motion from the former monolithic `db` module (E2 part 2).

use rusqlite::{OptionalExtension, TransactionBehavior};

use observability::logging::TruncatedPubkey;
use observability::pubkey::CanonicalPubkey;

use super::watermarks::{read_watermark, WatermarkKind};
use super::{normalize_pubkey, SlashingDb};
use crate::error::SlashingError;
use crate::metrics;
use crate::types::{
    InterchangeAttestation, InterchangeBlock, InterchangeFormat, InterchangeMetadata,
    SignedAttestation, SignedBlock, ValidatorRecord,
};
use eth_types::{Epoch, Root, Slot};

fn wire_attestation(attestation: SignedAttestation) -> InterchangeAttestation {
    InterchangeAttestation {
        source_epoch: attestation.source_epoch.to_string(),
        target_epoch: attestation.target_epoch.to_string(),
        signing_root: attestation.signing_root.map(String::from),
    }
}

fn wire_block(block: SignedBlock) -> InterchangeBlock {
    InterchangeBlock {
        slot: block.slot.to_string(),
        signing_root: block.signing_root.map(String::from),
    }
}

/// Records elapsed milliseconds into `histogram` on drop, unless disarmed.
///
/// `observe_now` samples immediately so a later drop does not sample twice.
struct ImportElapsedMs {
    start: std::time::Instant,
    histogram: &'static ::metrics::Histogram,
    armed: bool,
}

impl ImportElapsedMs {
    fn start(histogram: &'static ::metrics::Histogram) -> Self {
        Self { start: std::time::Instant::now(), histogram, armed: true }
    }

    fn observe_now(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let ms = self.start.elapsed().as_secs_f64() * 1000.0;
        self.histogram.observe(ms);
    }
}

impl Drop for ImportElapsedMs {
    fn drop(&mut self) {
        self.observe_now();
    }
}

// Test-only pause after the GVR check and before `import` takes `conn`.
// A successful genesis-validators-root check cannot be made slow: the wire
// value is 32 bytes. The pause stands in for that pre-lock work so a test
// can show the hold sample excludes it. Production builds omit it.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static IMPORT_PRE_LOCK_PAUSE: std::cell::Cell<Option<std::time::Duration>> =
        const { std::cell::Cell::new(None) };
}

/// Fixed point `(S*, T*)`. `Err` is that pair when `S* > T*`.
fn attestation_synthetic_bounds(
    rows: &[(Epoch, Epoch)],
    source_wm: Epoch,
    target_wm: Epoch,
) -> Result<(Epoch, Epoch), (Epoch, Epoch)> {
    let mut target_bound = target_wm;
    let mut source_bound;
    loop {
        source_bound = source_wm;
        for &(source, target) in rows {
            if target <= target_bound {
                source_bound = source_bound.max(source);
            }
        }
        let mut raised: Option<Epoch> = None;
        for &(source, target) in rows {
            if target > target_bound && source < source_bound {
                raised = Some(raised.map_or(target, |current| current.max(target)));
            }
        }
        match raised {
            Some(next) => target_bound = next,
            None => break,
        }
    }
    if source_bound > target_bound {
        Err((source_bound, target_bound))
    } else {
        Ok((source_bound, target_bound))
    }
}

fn export_validator(
    conn: &rusqlite::Connection,
    pubkey: String,
) -> Result<(ValidatorRecord, u64), SlashingError> {
    let attestations = SlashingDb::read_attestations(conn, &pubkey)?;
    let blocks = SlashingDb::read_blocks(conn, &pubkey)?;
    let source_wm = read_watermark(conn, &pubkey, WatermarkKind::AttestationSource)?;
    let target_wm = read_watermark(conn, &pubkey, WatermarkKind::AttestationTarget)?;
    let block_wm = read_watermark(conn, &pubkey, WatermarkKind::Block)?;

    let mut synthetics = 0u64;
    let signed_attestations = match (source_wm, target_wm) {
        (None, None) => attestations.into_iter().map(wire_attestation).collect(),
        (Some(source_wm), Some(target_wm)) => {
            let rows: Vec<(Epoch, Epoch)> =
                attestations.iter().map(|att| (att.source_epoch, att.target_epoch)).collect();
            let (source_bound, target_bound) =
                match attestation_synthetic_bounds(&rows, source_wm, target_wm) {
                    Ok(bounds) => bounds,
                    Err((source_bound, target_bound)) => {
                        return Err(SlashingError::UnrepresentableFloor {
                            pubkey,
                            source_bound,
                            target_bound,
                        });
                    }
                };
            synthetics += 1;
            let mut out = Vec::with_capacity(1 + attestations.len());
            out.push(InterchangeAttestation {
                source_epoch: source_bound.to_string(),
                target_epoch: target_bound.to_string(),
                signing_root: None,
            });
            for attestation in attestations {
                if attestation.target_epoch > target_bound {
                    out.push(wire_attestation(attestation));
                }
            }
            out
        }
        (source_wm, target_wm) => {
            return Err(SlashingError::UnrepresentableFloor {
                pubkey,
                source_bound: source_wm.unwrap_or(0),
                target_bound: target_wm.unwrap_or(0),
            });
        }
    };

    let signed_blocks = if let Some(slot_wm) = block_wm {
        synthetics += 1;
        let mut out = Vec::with_capacity(1 + blocks.len());
        out.push(InterchangeBlock { slot: slot_wm.to_string(), signing_root: None });
        for block in blocks {
            if block.slot > slot_wm {
                out.push(wire_block(block));
            }
        }
        out
    } else {
        blocks.into_iter().map(wire_block).collect()
    };

    Ok((ValidatorRecord { pubkey, signed_blocks, signed_attestations }, synthetics))
}

/// One attestation row parsed before the connection is taken.
struct ParsedAttestation<'a> {
    source_epoch: Epoch,
    target_epoch: Epoch,
    signing_root: &'a Option<String>,
}

/// One block row parsed before the connection is taken.
struct ParsedBlock<'a> {
    slot: Slot,
    signing_root: &'a Option<String>,
}

/// One interchange validator, parsed before `conn.lock()`.
///
/// Carries the normalised pubkey, the per-row attestations and blocks, and the
/// `max_source` / `max_target` / `max_slot` maxima used for raise-only watermarks.
struct ParsedValidator<'a> {
    pubkey: CanonicalPubkey,
    attestations: Vec<ParsedAttestation<'a>>,
    blocks: Vec<ParsedBlock<'a>>,
    max_source: Option<Epoch>,
    max_target: Option<Epoch>,
    max_slot: Option<Slot>,
}

const INSERT_ATTESTATION_SQL: &str = "\
INSERT INTO attestations \
(client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root) \
SELECT 'local-vc', ?1, ?2, ?3, ?4, ?5 \
WHERE NOT EXISTS ( \
SELECT 1 FROM attestations WHERE pubkey = ?1 AND target_epoch = ?3 \
)";

const INSERT_BLOCK_SQL: &str = "\
INSERT INTO blocks \
(client_cn, pubkey, slot, signing_root, genesis_validators_root) \
SELECT 'local-vc', ?1, ?2, ?3, ?4 \
WHERE NOT EXISTS ( \
SELECT 1 FROM blocks WHERE pubkey = ?1 AND slot = ?2 \
)";

/// Parse pubkeys and numeric fields before `import` takes `conn`.
///
/// A malformed `source_epoch`, `target_epoch`, or `slot` returns `Err` here.
/// The caller does not lock the database for that file. The format-version
/// check and the genesis-validators-root check stay in `import`, ahead of this
/// function.
fn parse_interchange(
    interchange: &InterchangeFormat,
) -> Result<Vec<ParsedValidator<'_>>, SlashingError> {
    let mut parsed = Vec::with_capacity(interchange.data.len());
    for validator in &interchange.data {
        let pubkey = normalize_pubkey(&validator.pubkey)?;
        let mut attestations = Vec::with_capacity(validator.signed_attestations.len());
        let mut blocks = Vec::with_capacity(validator.signed_blocks.len());
        let mut max_source: Option<Epoch> = None;
        let mut max_target: Option<Epoch> = None;
        let mut max_slot: Option<Slot> = None;

        for attestation in &validator.signed_attestations {
            let source_epoch: Epoch = attestation.source_epoch.parse().map_err(|_| {
                SlashingError::InvalidInterchangeFormat(format!(
                    "invalid source_epoch: {}",
                    attestation.source_epoch
                ))
            })?;
            let target_epoch: Epoch = attestation.target_epoch.parse().map_err(|_| {
                SlashingError::InvalidInterchangeFormat(format!(
                    "invalid target_epoch: {}",
                    attestation.target_epoch
                ))
            })?;
            max_source = Some(max_source.map_or(source_epoch, |current| current.max(source_epoch)));
            max_target = Some(max_target.map_or(target_epoch, |current| current.max(target_epoch)));
            attestations.push(ParsedAttestation {
                source_epoch,
                target_epoch,
                signing_root: &attestation.signing_root,
            });
        }

        for block in &validator.signed_blocks {
            let slot: Slot = block.slot.parse().map_err(|_| {
                SlashingError::InvalidInterchangeFormat(format!("invalid slot: {}", block.slot))
            })?;
            max_slot = Some(max_slot.map_or(slot, |current| current.max(slot)));
            blocks.push(ParsedBlock { slot, signing_root: &block.signing_root });
        }

        parsed.push(ParsedValidator {
            pubkey,
            attestations,
            blocks,
            max_source,
            max_target,
            max_slot,
        });
    }
    Ok(parsed)
}

impl SlashingDb {
    /// Parse a hex string (with or without `0x` prefix) into a `Root`.
    ///
    /// Delegates length/prefix/hex validation to
    /// [`eth_types::canonical::gvr_hex::parse_gvr_hex`], then rejects the all-zeros
    /// builder-registration sentinel (slashing-specific policy, not in eth-types).
    ///
    /// Returns `SlashingError::InvalidInterchangeFormat` if the string is not
    /// valid hex, not exactly 32 bytes, or all zeros.
    pub(crate) fn parse_gvr_hex(s: &str) -> Result<Root, SlashingError> {
        use eth_types::canonical::{gvr_hex, ParseError};
        let root = gvr_hex::parse_gvr_hex(s).map_err(|e| {
            let msg = match e {
                ParseError::DoublePrefix => {
                    "genesis_validators_root has double 0x prefix".to_string()
                }
                ParseError::InvalidHex(detail) => {
                    format!("genesis_validators_root is not valid hex: {detail}")
                }
                ParseError::InvalidLength { expected, got } => {
                    format!("genesis_validators_root must be exactly {expected} bytes, got {got}")
                }
            };
            SlashingError::InvalidInterchangeFormat(msg)
        })?;
        // All-zeros is the builder-registration sentinel and never a real chain
        // identifier. Reject it to catch operator misconfiguration.
        if root == [0u8; 32] {
            return Err(SlashingError::InvalidInterchangeFormat(
                "genesis_validators_root must not be all zeros".to_string(),
            ));
        }
        Ok(root)
    }

    /// Read `metadata.genesis_validators_root` from the DB (acquires the mutex).
    ///
    /// Returns `Ok(None)` if no row is present (backward compat: skip the check).
    /// Returns `Ok(Some(root))` if the row is present and parseable.
    pub(super) fn read_metadata_gvr(&self) -> Result<Option<Root>, SlashingError> {
        let conn = self.conn.lock();
        let hex_str: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'genesis_validators_root'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match hex_str {
            None => Ok(None),
            Some(s) => Ok(Some(Self::parse_gvr_hex(&s)?)),
        }
    }

    /// Export all slashing-protection records as an EIP-3076 interchange.
    ///
    /// # Drop-and-synthesise
    ///
    /// Sub-watermark rows are not copied out. For each validator with
    /// attestation watermarks `(S_wm, T_wm)`, export derives a fixed point
    /// `(S*, T*)`: start at `T* = T_wm`, set `S*` to the max of `S_wm` and
    /// the sources of rows with `target <= T*`, and if any row has
    /// `target > T*` and `source < S*` raise `T*` to the largest such target
    /// and repeat. Rows with `target <= T*` are dropped and replaced by one
    /// synthetic attestation `{source: S*, target: T*, signing_root: null}`.
    /// Rows with `target > T*` are kept. Block rows with `slot <= B_wm` are
    /// dropped and replaced by one synthetic block `{slot: B_wm, signing_root: null}`.
    ///
    /// Appending `(S_wm, T_wm)` beside the lower rows was rejected. Importers
    /// floor on the file's **minimum**, so a lower neighbour keeps that
    /// minimum below the watermark — the floor never travels — and the two
    /// records are a double vote or a surround inside the file.
    ///
    /// `S* > T*`, or only one of the two attestation watermarks, fails the
    /// whole export with [`SlashingError::UnrepresentableFloor`]. No partial
    /// interchange is returned. A validator with neither attestation
    /// watermark exports its attestation rows unchanged.
    ///
    /// The protection invariant is non-weakening: if this database would
    /// refuse a candidate, an EIP-3076 importer of the file refuses it too.
    /// Exported minima are at least the database watermarks, not necessarily
    /// equal to them.
    ///
    /// # Consistent-snapshot guarantee (KM-1/ADR-008)
    ///
    /// The lock on `self.conn` is acquired ONCE and held for the entire
    /// duration of the export — `read_all_pubkeys`, watermark reads,
    /// `read_attestations`, and `read_blocks` all operate on the
    /// already-borrowed `&Connection`. Because `parking_lot::Mutex` is NOT
    /// reentrant, calling the public getters from here would deadlock; the
    /// private `read_*` helpers avoid re-locking.
    ///
    /// Holding a single lock = no concurrent `seed_attestation` or
    /// `seed_block` write can interleave between the pubkey scan and the
    /// per-pubkey row reads, so the exported interchange is an atomic,
    /// consistent snapshot of the DB at the moment of the call.
    #[tracing::instrument(name = "slashing.db.export", skip_all)]
    pub fn export(
        &self,
        genesis_validators_root: &Root,
    ) -> Result<InterchangeFormat, SlashingError> {
        // KM-1/ADR-008: single held lock = consistent snapshot; no interleaved writes.
        let conn = self.conn.lock();

        let pubkeys = Self::read_all_pubkeys(&conn)?;

        let mut data = Vec::with_capacity(pubkeys.len());
        let mut synthetic_records = 0u64;
        for pubkey in pubkeys {
            let (record, synthetics) = export_validator(&conn, pubkey)?;
            synthetic_records += synthetics;
            data.push(record);
        }
        if synthetic_records > 0 {
            metrics::RVC_SLASHING_EXPORT_SYNTHETIC_RECORDS_TOTAL.inc_by(synthetic_records);
        }

        let record_count = data.len();
        // Always emit canonical 0x+lowercase hex (RF3-18) so re-import compares
        // cleanly against any accepted encoding of the same Root.
        let gvr_hex = Self::root_to_hex(genesis_validators_root);
        let result = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: gvr_hex,
            },
            data,
        };
        tracing::info!(
            record_count,
            path = self.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            "slashing DB export completed"
        );
        Ok(result)
    }

    #[tracing::instrument(name = "slashing.db.import", skip_all)]
    /// Import an EIP-3076 interchange into the history tables and raise per-pubkey
    /// watermarks to the interchange maxima.
    ///
    /// # Watermarks (RF2-12 / B5)
    ///
    /// For each validator in the interchange, after inserting rows:
    /// - block watermark ← `MAX(signed_blocks.slot)`
    /// - attestation watermarks ← `(MAX(source_epoch), MAX(target_epoch))`
    ///
    /// Watermark updates are **raise-only** and share the same transaction as the
    /// row inserts: a partial import cannot leave watermarks ahead of rows, and
    /// re-importing an older (lower-maxima) interchange **does not lower**
    /// watermarks and **does not fail** the import (EIP-3076 import is additive;
    /// `WatermarkLowered` is reserved for the explicit `set_*_watermark` APIs).
    ///
    /// A `WHERE NOT EXISTS` conflict drops the row and still raises the watermark
    /// from the parsed maxima. An audit table for those drops was rejected: no
    /// schema migration; the drop is a `warn` plus `rvc_slashing_import_conflicts_total`.
    ///
    /// # Metrics
    ///
    /// `rvc_slashing_import_duration_ms` is the whole call.
    /// `rvc_slashing_import_conn_hold_ms` is `conn.lock()` through `COMMIT`
    /// (one sample on rollback after the lock is taken; none if the call
    /// returns before the lock). Numeric fields are parsed by
    /// [`parse_interchange`] before the lock.
    pub fn import(
        &self,
        interchange: &InterchangeFormat,
        expected_genesis_validators_root: &Root,
    ) -> Result<(), SlashingError> {
        let _duration = ImportElapsedMs::start(&metrics::RVC_SLASHING_IMPORT_DURATION_MS);
        if interchange.metadata.interchange_format_version != "5" {
            return Err(SlashingError::InvalidInterchangeFormat(format!(
                "unsupported interchange_format_version: expected \"5\", got \"{}\"",
                interchange.metadata.interchange_format_version
            )));
        }

        // RF3-18: byte-based metadata compare — bare hex, 0x-prefixed, and mixed-case
        // encodings of the same 32-byte root must not spuriously reject a valid import.
        // Use eth-types parse (no all-zeros policy) so interchange wire forms stay open;
        // row storage always uses the caller's typed Root in canonical form.
        let expected_hex = Self::root_to_hex(expected_genesis_validators_root);
        let actual_root = match eth_types::canonical::gvr_hex::parse_gvr_hex(
            &interchange.metadata.genesis_validators_root,
        ) {
            Ok(root) => root,
            Err(_) => {
                return Err(SlashingError::GenesisValidatorsRootMismatch {
                    expected: expected_hex,
                    actual: interchange.metadata.genesis_validators_root.clone(),
                });
            }
        };
        if actual_root != *expected_genesis_validators_root {
            return Err(SlashingError::GenesisValidatorsRootMismatch {
                expected: expected_hex,
                actual: interchange.metadata.genesis_validators_root.clone(),
            });
        }

        // Canonical 0x+lowercase for every imported row so the v3 unique index
        // (pubkey, genesis_validators_root, slot/target_epoch) matches runtime
        // inserts that also go through root_to_hex (RF3-18).  SQLite treats NULL
        // as DISTINCT, so a NULL gvr would bypass the index silently.
        let gvr_hex = expected_hex;
        let parsed = parse_interchange(interchange)?;

        #[cfg(any(test, feature = "test-utils"))]
        if let Some(pause) = IMPORT_PRE_LOCK_PAUSE.with(std::cell::Cell::get) {
            std::thread::sleep(pause);
        }

        let mut hold = ImportElapsedMs::start(&metrics::RVC_SLASHING_IMPORT_CONN_HOLD_MS);
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        {
            let mut insert_attestation = tx.prepare_cached(INSERT_ATTESTATION_SQL)?;
            let mut insert_block = tx.prepare_cached(INSERT_BLOCK_SQL)?;
            let mut raise_watermark =
                tx.prepare_cached(super::watermarks::RAISE_WATERMARK_MAX_SQL)?;

            for validator in &parsed {
                let pubkey = validator.pubkey.as_ref();
                for attestation in &validator.attestations {
                    let inserted = insert_attestation.execute((
                        pubkey,
                        attestation.source_epoch as i64,
                        attestation.target_epoch as i64,
                        attestation.signing_root,
                        &gvr_hex,
                    ))?;
                    if inserted == 0 {
                        tracing::warn!(
                            pubkey = %TruncatedPubkey::new(pubkey),
                            source_epoch = attestation.source_epoch,
                            target_epoch = attestation.target_epoch,
                            "dropped conflicting interchange attestation (source, target)=({}, {}); watermark still raised",
                            attestation.source_epoch,
                            attestation.target_epoch
                        );
                        metrics::RVC_SLASHING_IMPORT_CONFLICTS_TOTAL.inc();
                    }
                }

                for block in &validator.blocks {
                    let inserted = insert_block.execute((
                        pubkey,
                        block.slot as i64,
                        block.signing_root,
                        &gvr_hex,
                    ))?;
                    if inserted == 0 {
                        tracing::warn!(
                            pubkey = %TruncatedPubkey::new(pubkey),
                            slot = block.slot,
                            "dropped conflicting interchange block slot={}",
                            block.slot
                        );
                        metrics::RVC_SLASHING_IMPORT_CONFLICTS_TOTAL.inc();
                    }
                }

                // Raise watermarks from this interchange's maxima (same transaction).
                // Raise-only SQL: re-import of older maxima is a silent no-op.
                if let Some(slot) = validator.max_slot {
                    raise_watermark.execute((
                        pubkey,
                        WatermarkKind::Block.as_sql_str(),
                        slot as i64,
                    ))?;
                }
                if let (Some(source), Some(target)) = (validator.max_source, validator.max_target) {
                    raise_watermark.execute((
                        pubkey,
                        WatermarkKind::AttestationSource.as_sql_str(),
                        source as i64,
                    ))?;
                    raise_watermark.execute((
                        pubkey,
                        WatermarkKind::AttestationTarget.as_sql_str(),
                        target as i64,
                    ))?;
                }
            }
        }

        tx.commit()?;
        hold.observe_now();
        let record_count = interchange.data.len();
        tracing::info!(
            record_count,
            path = self.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            "slashing DB import completed"
        );
        Ok(())
    }

    /// Pause after the GVR check and before `import` takes `conn`, on this thread.
    ///
    /// # Test-only
    ///
    /// Production builds omit the pause. Pass `None` to clear it. `import` is
    /// synchronous, so the pause applies to imports on the calling thread.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_import_pre_lock_pause_for_test(pause: Option<std::time::Duration>) {
        IMPORT_PRE_LOCK_PAUSE.with(|cell| cell.set(pause));
    }

    /// Read the stored genesis validators root from the metadata table.
    pub fn genesis_validators_root(&self) -> Result<Option<String>, SlashingError> {
        let conn = self.conn.lock();
        let result: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'genesis_validators_root'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    }

    /// Store the genesis validators root in the metadata table.
    ///
    /// Comparison is **byte-based** (RF3-17): bare hex, `0x`-prefixed, and mixed-case
    /// hex that decode to the same 32 bytes are treated as the same chain. On first
    /// insert the value is written in canonical form (`0x` + lowercase hex). On a
    /// match against a non-canonical stored form, the row is rewritten to canonical
    /// in the same transaction (one-time upgrade compatibility).
    ///
    /// Takes a typed [`Root`] (RF3-18). All-zeros is rejected (builder-registration
    /// sentinel, not a real chain id).
    pub fn set_genesis_validators_root(&self, root: &Root) -> Result<(), SlashingError> {
        // All-zeros is the builder-registration sentinel and never a real chain
        // identifier. Reject it to catch operator misconfiguration.
        if *root == [0u8; 32] {
            return Err(SlashingError::InvalidInterchangeFormat(
                "genesis_validators_root must not be all zeros".to_string(),
            ));
        }
        let canonical_hex = Self::root_to_hex(root);

        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key = 'genesis_validators_root'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(stored) => {
                let stored_root = Self::parse_gvr_hex(&stored)?;
                if stored_root != *root {
                    return Err(SlashingError::GenesisValidatorsRootMismatch {
                        expected: stored,
                        actual: canonical_hex,
                    });
                }
                // Same chain: normalise legacy bare/mixed-case metadata to canonical.
                if stored != canonical_hex {
                    tx.execute(
                        "UPDATE metadata SET value = ?1 WHERE key = 'genesis_validators_root'",
                        [&canonical_hex],
                    )?;
                }
                tx.commit()?;
                Ok(())
            }
            None => {
                tx.execute(
                    "INSERT INTO metadata (key, value) VALUES ('genesis_validators_root', ?1)",
                    [&canonical_hex],
                )?;
                tx.commit()?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SignedAttestation, SignedBlock};
    use tempfile::tempdir;

    const TEST_GVR: Root = [0u8; 32];

    /// Non-zero chain GVR used by import/export/set tests (RF3-18 typed API).
    const CHAIN_GVR_HEX: &str =
        "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

    fn chain_gvr() -> Root {
        gvr_from_hex(CHAIN_GVR_HEX)
    }

    fn gvr_from_hex(hex: &str) -> Root {
        let h = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(h).expect("valid hex");
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        root
    }

    #[test]
    fn test_export_empty_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();

        let interchange = db.export(&genesis_root_bytes).expect("export should succeed");

        assert_eq!(interchange.metadata.interchange_format_version, "5");
        assert_eq!(interchange.metadata.genesis_validators_root, genesis_root);
        assert!(interchange.data.is_empty());
    }

    #[test]
    fn test_export_with_attestations() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root_bytes = chain_gvr();

        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";
        db.seed_attestation(pubkey, 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("record should succeed");
        db.seed_attestation(pubkey, 101, 102, None, &TEST_GVR).expect("record should succeed");

        let interchange = db.export(&genesis_root_bytes).expect("export should succeed");

        assert_eq!(interchange.data.len(), 1);
        let validator = &interchange.data[0];
        assert_eq!(validator.pubkey, pubkey);
        assert_eq!(validator.signed_attestations.len(), 2);
        assert_eq!(validator.signed_attestations[0].source_epoch, "100");
        assert_eq!(validator.signed_attestations[0].target_epoch, "101");
        assert_eq!(validator.signed_attestations[0].signing_root, Some("0xabcd".to_string()));
        assert_eq!(validator.signed_attestations[1].source_epoch, "101");
        assert_eq!(validator.signed_attestations[1].target_epoch, "102");
        assert!(validator.signed_attestations[1].signing_root.is_none());
    }

    #[test]
    fn test_export_with_blocks() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root_bytes = chain_gvr();

        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";
        let block = SignedBlock::new(pubkey, 1000, Some("0xefgh")).expect("valid hex pubkey");
        db.insert_block(&block, &TEST_GVR).expect("insert should succeed");

        let interchange = db.export(&genesis_root_bytes).expect("export should succeed");

        assert_eq!(interchange.data.len(), 1);
        let validator = &interchange.data[0];
        assert_eq!(validator.pubkey, pubkey);
        assert_eq!(validator.signed_blocks.len(), 1);
        assert_eq!(validator.signed_blocks[0].slot, "1000");
        assert_eq!(validator.signed_blocks[0].signing_root, Some("0xefgh".to_string()));
    }

    #[test]
    fn test_export_multiple_validators() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root_bytes = chain_gvr();

        let pubkey1 = "0x1111";
        let pubkey2 = "0x2222";

        db.seed_attestation(pubkey1, 100, 101, None, &TEST_GVR).expect("record should succeed");
        db.seed_attestation(pubkey2, 200, 201, None, &TEST_GVR).expect("record should succeed");

        let interchange = db.export(&genesis_root_bytes).expect("export should succeed");

        assert_eq!(interchange.data.len(), 2);
    }

    #[test]
    fn test_import_empty_interchange() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![],
        };

        let result = db.import(&interchange, &genesis_root_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_genesis_root_mismatch() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let expected_root_hex = CHAIN_GVR_HEX;
        let expected_root = chain_gvr();
        let actual_root = "0xdifferent00000000000000000000000000000000000000000000000000000000";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: actual_root.to_string(), // mismatched chain
            },
            data: vec![],
        };

        let result = db.import(&interchange, &expected_root);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::GenesisValidatorsRootMismatch { expected, actual } => {
                assert_eq!(expected, expected_root_hex);
                assert_eq!(actual, actual_root);
            }
            _ => panic!("expected GenesisValidatorsRootMismatch error"),
        }
    }

    #[test]
    fn test_import_with_attestations() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![
                    InterchangeAttestation {
                        source_epoch: "100".to_string(),
                        target_epoch: "101".to_string(),
                        signing_root: Some("0xabcd".to_string()),
                    },
                    InterchangeAttestation {
                        source_epoch: "101".to_string(),
                        target_epoch: "102".to_string(),
                        signing_root: None,
                    },
                ],
            }],
        };

        db.import(&interchange, &genesis_root_bytes).expect("import should succeed");

        let attestations = db.get_attestations(pubkey).expect("get should succeed");
        assert_eq!(attestations.len(), 2);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[0].signing_root.as_ref().map(|r| r.as_hex()), Some("0xabcd"));
        assert_eq!(attestations[1].source_epoch, 101);
        assert_eq!(attestations[1].target_epoch, 102);
        assert!(attestations[1].signing_root.is_none());
    }

    #[test]
    fn test_import_with_blocks() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![InterchangeBlock {
                    slot: "1000".to_string(),
                    signing_root: Some("0xefgh".to_string()),
                }],
                signed_attestations: vec![],
            }],
        };

        db.import(&interchange, &genesis_root_bytes).expect("import should succeed");

        let blocks = db.get_blocks(pubkey).expect("get should succeed");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 1000);
        assert_eq!(blocks[0].signing_root.as_ref().map(|r| r.as_hex()), Some("0xefgh"));
    }

    #[test]
    fn test_roundtrip_export_import() {
        let db1 = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        db1.seed_attestation(pubkey, 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("record should succeed");
        db1.seed_attestation(pubkey, 101, 102, None, &TEST_GVR).expect("record should succeed");

        let block = SignedBlock::new(pubkey, 1000, Some("0xefgh")).expect("valid hex pubkey");
        db1.insert_block(&block, &TEST_GVR).expect("insert should succeed");

        let interchange = db1.export(&genesis_root_bytes).expect("export should succeed");

        let json =
            serde_json::to_string_pretty(&interchange).expect("serialization should succeed");
        let parsed: InterchangeFormat =
            serde_json::from_str(&json).expect("deserialization should succeed");

        let db2 = SlashingDb::open_in_memory().expect("failed to open db");
        db2.import(&parsed, &genesis_root_bytes).expect("import should succeed");

        let attestations = db2.get_attestations(pubkey).expect("get should succeed");
        assert_eq!(attestations.len(), 2);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[1].source_epoch, 101);
        assert_eq!(attestations[1].target_epoch, 102);

        let blocks = db2.get_blocks(pubkey).expect("get should succeed");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 1000);
    }

    #[test]
    fn test_import_idempotent() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "100".to_string(),
                    target_epoch: "101".to_string(),
                    signing_root: None,
                }],
            }],
        };

        db.import(&interchange, &genesis_root_bytes).expect("first import should succeed");
        db.import(&interchange, &genesis_root_bytes).expect("second import should succeed");

        let attestations = db.get_attestations(pubkey).expect("get should succeed");
        assert_eq!(attestations.len(), 1);
    }

    // ── RF2-12: interchange import raises watermarks from maxima ─────────────

    /// RF2-12: import sets block and attestation watermarks to interchange maxima.
    #[test]
    fn test_import_sets_watermarks_from_interchange_maxima() {
        let db = SlashingDb::open_in_memory().expect("open");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![
                    InterchangeBlock { slot: "100".to_string(), signing_root: None },
                    InterchangeBlock { slot: "500".to_string(), signing_root: None },
                    InterchangeBlock { slot: "250".to_string(), signing_root: None },
                ],
                signed_attestations: vec![
                    InterchangeAttestation {
                        source_epoch: "10".to_string(),
                        target_epoch: "20".to_string(),
                        signing_root: None,
                    },
                    InterchangeAttestation {
                        source_epoch: "30".to_string(),
                        target_epoch: "40".to_string(),
                        signing_root: None,
                    },
                    InterchangeAttestation {
                        source_epoch: "15".to_string(),
                        target_epoch: "35".to_string(),
                        signing_root: None,
                    },
                ],
            }],
        };

        assert!(db.get_block_watermark(pubkey).unwrap().is_none());
        assert!(db.get_attestation_watermark(pubkey).unwrap().is_none());

        db.import(&interchange, &genesis_root_bytes).expect("import");

        assert_eq!(db.get_block_watermark(pubkey).unwrap(), Some(500));
        assert_eq!(db.get_attestation_watermark(pubkey).unwrap(), Some((30, 40)));
        // Rows also landed.
        assert_eq!(db.get_blocks(pubkey).unwrap().len(), 3);
        assert_eq!(db.get_attestations(pubkey).unwrap().len(), 3);
    }

    /// RF2-12 / A1: after import with max target T, stage at T is blocked and T+1 is allowed.
    #[test]
    fn test_import_watermark_blocks_stage_at_equality_allows_above() {
        let db = SlashingDb::open_in_memory().expect("open");
        let genesis_root = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let genesis_root_bytes = TEST_GVR;
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";
        const T: u64 = 200;
        const BLOCK_MAX: u64 = 1000;

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![InterchangeBlock {
                    slot: BLOCK_MAX.to_string(),
                    signing_root: None,
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "100".to_string(),
                    target_epoch: T.to_string(),
                    signing_root: None,
                }],
            }],
        };

        db.import(&interchange, &genesis_root_bytes).expect("import");

        // Attestation at target == T blocked (A1 `<=`).
        let err = db
            .stage_attestation(pubkey, 100, T, Some("0xat_eq".into()), &TEST_GVR)
            .expect_err("target == watermark must be blocked");
        let msg = err.to_string();
        assert!(msg.contains("b845089a"), "msg names pubkey: {msg}");
        assert!(msg.contains(&T.to_string()), "msg names target: {msg}");
        match err {
            SlashingError::BelowAttestationWatermark {
                pubkey: ref err_pk,
                target_epoch,
                watermark_target,
            } => {
                assert!(err_pk.contains("b845089a"), "pubkey in error: {err_pk}");
                assert_eq!(target_epoch, T);
                assert_eq!(watermark_target, T);
            }
            other => panic!("expected BelowAttestationWatermark, got: {other:?}"),
        }

        // Attestation at target T+1 allowed.
        db.stage_attestation(pubkey, 100, T + 1, Some("0xat_above".into()), &TEST_GVR)
            .expect("target T+1 must stage")
            .discard();

        // Block at slot == max blocked.
        let err = db
            .stage_block(pubkey, BLOCK_MAX, Some("0xblk_eq".into()), &TEST_GVR)
            .expect_err("slot == watermark must be blocked");
        match err {
            SlashingError::BelowBlockWatermark { pubkey: ref err_pk, slot, watermark_slot } => {
                assert!(err_pk.contains("b845089a"), "pubkey in error: {err_pk}");
                assert_eq!(slot, BLOCK_MAX);
                assert_eq!(watermark_slot, BLOCK_MAX);
            }
            other => panic!("expected BelowBlockWatermark, got: {other:?}"),
        }

        // Block at max+1 allowed.
        db.stage_block(pubkey, BLOCK_MAX + 1, Some("0xblk_above".into()), &TEST_GVR)
            .expect("slot max+1 must stage")
            .discard();
    }

    /// RF2-12: re-importing an older interchange does not lower watermarks and succeeds.
    #[test]
    fn test_reimport_older_interchange_does_not_lower_watermarks() {
        let db = SlashingDb::open_in_memory().expect("open");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let newer = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![InterchangeBlock {
                    slot: "9000".to_string(),
                    signing_root: None,
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "500".to_string(),
                    target_epoch: "600".to_string(),
                    signing_root: None,
                }],
            }],
        };
        let older = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![InterchangeBlock {
                    slot: "100".to_string(),
                    signing_root: None,
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "10".to_string(),
                    target_epoch: "20".to_string(),
                    signing_root: None,
                }],
            }],
        };

        db.import(&newer, &genesis_root_bytes).expect("import newer");
        assert_eq!(db.get_block_watermark(pubkey).unwrap(), Some(9000));
        assert_eq!(db.get_attestation_watermark(pubkey).unwrap(), Some((500, 600)));

        // Re-import older maxima: must succeed and leave watermarks raised.
        db.import(&older, &genesis_root_bytes).expect("re-import older must not fail");
        assert_eq!(db.get_block_watermark(pubkey).unwrap(), Some(9000));
        assert_eq!(db.get_attestation_watermark(pubkey).unwrap(), Some((500, 600)));

        // Older rows are still additive.
        assert!(db.get_blocks(pubkey).unwrap().iter().any(|b| b.slot == 100));
        assert!(db.get_attestations(pubkey).unwrap().iter().any(|a| a.target_epoch == 20));
    }

    /// RF2-12: import of only blocks sets block watermark; att watermark stays unset.
    #[test]
    fn test_import_blocks_only_sets_block_watermark() {
        let db = SlashingDb::open_in_memory().expect("open");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![InterchangeBlock {
                    slot: "42".to_string(),
                    signing_root: Some("0xef".to_string()),
                }],
                signed_attestations: vec![],
            }],
        };

        db.import(&interchange, &genesis_root_bytes).expect("import");
        assert_eq!(db.get_block_watermark(pubkey).unwrap(), Some(42));
        assert!(db.get_attestation_watermark(pubkey).unwrap().is_none());
    }

    /// RF2-12: import of only attestations sets att watermarks; block watermark stays unset.
    #[test]
    fn test_import_attestations_only_sets_attestation_watermark() {
        let db = SlashingDb::open_in_memory().expect("open");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "7".to_string(),
                    target_epoch: "9".to_string(),
                    signing_root: None,
                }],
            }],
        };

        db.import(&interchange, &genesis_root_bytes).expect("import");
        assert!(db.get_block_watermark(pubkey).unwrap().is_none());
        assert_eq!(db.get_attestation_watermark(pubkey).unwrap(), Some((7, 9)));
    }

    /// RF2-12-M1: clear_watermarks is test-only and wipes import floors (strategy isolation).
    #[test]
    fn test_clear_watermarks_wipes_import_floors() {
        let db = SlashingDb::open_in_memory().expect("open");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![InterchangeBlock {
                    slot: "100".to_string(),
                    signing_root: None,
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "1".to_string(),
                    target_epoch: "2".to_string(),
                    signing_root: None,
                }],
            }],
        };

        db.import(&interchange, &genesis_root_bytes).expect("import");
        assert_eq!(db.get_block_watermark(pubkey).unwrap(), Some(100));
        assert_eq!(db.get_attestation_watermark(pubkey).unwrap(), Some((1, 2)));

        db.clear_watermarks().expect("clear");
        assert!(db.get_block_watermark(pubkey).unwrap().is_none());
        assert!(db.get_attestation_watermark(pubkey).unwrap().is_none());
        // History rows remain.
        assert_eq!(db.get_blocks(pubkey).unwrap().len(), 1);
        assert_eq!(db.get_attestations(pubkey).unwrap().len(), 1);
    }

    /// RF2-12: WatermarkLowered error message names pubkey and offending values.
    #[test]
    fn test_watermark_lowered_error_names_pubkey_and_values() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_block_watermark("0xabc", 1000).expect("set");
        let err = db.set_block_watermark("0xabc", 500).expect_err("must not lower");
        let msg = err.to_string();
        assert!(msg.contains("0xabc") || msg.contains("abc"), "names pubkey: {msg}");
        assert!(msg.contains("1000"), "names current: {msg}");
        assert!(msg.contains("500"), "names attempted: {msg}");
        match err {
            SlashingError::WatermarkLowered {
                ref pubkey,
                ref watermark_type,
                current,
                attempted,
            } => {
                assert!(pubkey.contains("abc"));
                assert_eq!(watermark_type, "block");
                assert_eq!(current, 1000);
                assert_eq!(attempted, 500);
            }
            other => panic!("expected WatermarkLowered, got: {other:?}"),
        }
    }

    #[test]
    fn test_import_invalid_epoch_format() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "not_a_number".to_string(),
                    target_epoch: "101".to_string(),
                    signing_root: None,
                }],
            }],
        };

        let result = db.import(&interchange, &genesis_root_bytes);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::InvalidInterchangeFormat(_) => {}
            _ => panic!("expected InvalidInterchangeFormat error"),
        }
    }

    /// RF2-11: pin the documented contract that `seed_attestation` / `seed_block`
    /// perform **no** EIP-3076 rule evaluation. Fixtures may plant history that
    /// `check_and_record_*` would reject (e.g. a surrounding-vote pair, or a
    /// same-slot double proposal that only fails on the production path).

    #[test]
    fn test_integrity_genesis_validators_root_empty() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let root = db.genesis_validators_root().expect("query should succeed");
        assert!(root.is_none());
    }

    #[test]
    fn test_integrity_set_genesis_validators_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        db.set_genesis_validators_root(&gvr_from_hex(root)).expect("set should succeed");

        let stored = db.genesis_validators_root().expect("query should succeed");
        assert_eq!(stored, Some(root.to_string()));
    }

    #[test]
    fn test_integrity_genesis_validators_root_roundtrip() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        db.set_genesis_validators_root(&gvr_from_hex(root)).expect("first set should succeed");
        db.set_genesis_validators_root(&gvr_from_hex(root)).expect("same root should succeed");

        let stored = db.genesis_validators_root().expect("query should succeed");
        assert_eq!(stored, Some(root.to_string()));
    }

    #[test]
    fn test_integrity_genesis_validators_root_mismatch() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let root1 = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        // Must be valid 32-byte hex that differs by value (parse-before-compare).
        let root2 = "0xd1ffe00000000000000000000000000000000000000000000000000000000000";

        db.set_genesis_validators_root(&gvr_from_hex(root1)).expect("first set should succeed");
        let result = db.set_genesis_validators_root(&gvr_from_hex(root2));
        assert!(result.is_err());

        match result.unwrap_err() {
            // Stored form is canonical (0x + lowercase); root1 already is.
            SlashingError::GenesisValidatorsRootMismatch { expected, actual } => {
                assert_eq!(expected, root1);
                assert_eq!(actual, root2);
            }
            other => panic!("expected GenesisValidatorsRootMismatch, got: {other:?}"),
        }
    }

    // ── RF3-17: byte-based GVR metadata comparison + upgrade compatibility ──

    /// Upgrade hazard: existing nodes store bare lowercase hex (startup pre-RF3-17).
    /// A release that starts passing `0x`-prefixed form must not fail to start.
    #[test]
    fn test_existing_bare_hex_metadata_matches_canonical_prefixed_root() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("bare_gvr.db");
        let bare = "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let prefixed = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        // Simulate pre-RF3-17 startup write: bare lowercase hex in metadata.
        {
            let db = SlashingDb::open(&path).expect("open");
            let conn = db.conn.lock();
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('genesis_validators_root', ?1)",
                [bare],
            )
            .expect("insert bare-hex metadata");
        }

        let db = SlashingDb::open(&path).expect("reopen");
        db.set_genesis_validators_root(&gvr_from_hex(prefixed))
            .expect("bare stored + 0x input must match by bytes");
    }

    /// On a successful match against non-canonical metadata, rewrite to canonical.
    #[test]
    fn test_metadata_normalised_to_canonical_on_first_match() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("normalize_gvr.db");
        let bare = "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let prefixed = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        {
            let db = SlashingDb::open(&path).expect("open");
            let conn = db.conn.lock();
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('genesis_validators_root', ?1)",
                [bare],
            )
            .expect("insert bare-hex metadata");
        }

        let db = SlashingDb::open(&path).expect("reopen");
        db.set_genesis_validators_root(&gvr_from_hex(prefixed)).expect("match");

        let stored = db.genesis_validators_root().expect("read");
        assert_eq!(stored.as_deref(), Some(prefixed));
    }

    /// First-run insert always writes canonical form regardless of input encoding.
    #[test]
    fn test_first_insert_writes_canonical_form() {
        let db = SlashingDb::open_in_memory().expect("open");
        let bare = "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let canonical = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        db.set_genesis_validators_root(&gvr_from_hex(bare)).expect("set bare");
        assert_eq!(db.genesis_validators_root().expect("read").as_deref(), Some(canonical));
    }

    #[test]
    fn test_different_chain_still_rejected() {
        let db = SlashingDb::open_in_memory().expect("open");
        let chain_a = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        // Valid 32-byte hex that differs by bytes from chain_a.
        let chain_b = "0xd1ffe00000000000000000000000000000000000000000000000000000000000";
        let chain_b_bare = "d1ffe00000000000000000000000000000000000000000000000000000000000";

        db.set_genesis_validators_root(&gvr_from_hex(chain_a)).expect("pin chain A");
        let err =
            db.set_genesis_validators_root(&gvr_from_hex(chain_b)).expect_err("different chain");
        match err {
            SlashingError::GenesisValidatorsRootMismatch { expected, actual } => {
                assert_eq!(expected, chain_a);
                assert_eq!(actual, chain_b);
            }
            other => panic!("expected GenesisValidatorsRootMismatch, got: {other:?}"),
        }
        // Bare form of a different root must also mismatch (not a false positive from
        // encoding-only differences).
        let err = db
            .set_genesis_validators_root(&gvr_from_hex(chain_b_bare))
            .expect_err("bare different chain");
        assert!(matches!(err, SlashingError::GenesisValidatorsRootMismatch { .. }));
    }

    #[test]
    fn test_all_zero_gvr_still_rejected() {
        let db = SlashingDb::open_in_memory().expect("open");
        let zeros = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let err = db.set_genesis_validators_root(&gvr_from_hex(zeros)).expect_err("all zeros");
        match err {
            SlashingError::InvalidInterchangeFormat(msg) => {
                assert!(msg.contains("all zeros"), "msg={msg}");
            }
            other => panic!("expected InvalidInterchangeFormat, got: {other:?}"),
        }
    }

    #[test]
    fn test_mixed_case_stored_value_matches() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("mixed_gvr.db");
        let mixed = "0x04700007FaBc8282644AeD6d1c7c9E21d38a03a0c4Ba193f3AfE428824B3a673";
        let canonical = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        {
            let db = SlashingDb::open(&path).expect("open");
            let conn = db.conn.lock();
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('genesis_validators_root', ?1)",
                [mixed],
            )
            .expect("insert mixed-case metadata");
        }

        let db = SlashingDb::open(&path).expect("reopen");
        db.set_genesis_validators_root(&gvr_from_hex(canonical))
            .expect("mixed-case stored must match lowercase input");
        assert_eq!(db.genesis_validators_root().expect("read").as_deref(), Some(canonical));
    }

    // ── RF3-18: typed GVR through rows, import/export, interchange compare ───

    /// Spurious-rejection bug: interchange metadata with `0x` prefix against a bare
    /// config (or vice versa) must import successfully via byte comparison.
    #[test]
    fn test_import_with_0x_prefixed_metadata_against_bare_config_succeeds() {
        let db = SlashingDb::open_in_memory().expect("open");
        let bare = "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let prefixed = CHAIN_GVR_HEX;
        let expected = chain_gvr();

        // Interchange carries 0x-prefixed metadata; expected Root is the same chain.
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: prefixed.to_string(),
            },
            data: vec![],
        };
        db.import(&interchange, &expected)
            .expect("0x-prefixed interchange must match bare-equivalent Root");

        // Reverse encoding: bare-hex interchange metadata vs same Root.
        let interchange_bare = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: bare.to_string(),
            },
            data: vec![],
        };
        db.import(&interchange_bare, &expected)
            .expect("bare-hex interchange must match 0x-derived Root");

        // Mixed-case metadata of the same chain also matches.
        let mixed = "0x04700007FaBc8282644AeD6d1c7c9E21d38a03a0c4Ba193f3AfE428824B3a673";
        let interchange_mixed = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: mixed.to_string(),
            },
            data: vec![],
        };
        db.import(&interchange_mixed, &expected)
            .expect("mixed-case interchange must match by bytes");
    }

    /// Import-written and runtime-written rows for the same chain must share one
    /// canonical GVR encoding so the v3 unique index actually fires across both paths.
    #[test]
    fn test_import_and_runtime_rows_share_one_gvr_encoding() {
        let db = SlashingDb::open_in_memory().expect("open");
        let gvr = chain_gvr();
        // Simulate a bare-hex "config" encoding on the interchange wire form.
        let bare_meta = "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";
        let target_epoch = 42u64;

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: bare_meta.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "40".to_string(),
                    target_epoch: target_epoch.to_string(),
                    signing_root: Some("0ximport_root".to_string()),
                }],
            }],
        };
        db.import(&interchange, &gvr).expect("import with bare metadata");

        // Prove the import path stored the *canonical* form (not the bare wire string).
        let stored_gvr: String = {
            let conn = db.conn.lock();
            conn.query_row(
                "SELECT genesis_validators_root FROM attestations WHERE pubkey = ?1 AND target_epoch = ?2",
                (normalize_pubkey(pubkey).expect("valid hex pubkey").as_ref(), target_epoch as i64),
                |row| row.get(0),
            )
            .expect("import row must exist")
        };
        assert_eq!(
            stored_gvr,
            SlashingDb::root_to_hex(&gvr),
            "import must write canonical 0x+lowercase, not the wire form"
        );

        // Runtime path uses the same root_to_hex encoding; plain INSERT must hit the
        // v3 unique index (pubkey, gvr, target_epoch). insert_attestation bypasses
        // EIP-3076 checks so the unique-index backstop is what we measure.
        let dup = SignedAttestation::new(pubkey, 41, target_epoch, Some("0xruntime_root"))
            .expect("valid hex pubkey");
        let err = db
            .insert_attestation(&dup, &gvr)
            .expect_err("runtime insert of same (pubkey, target) must collide on unique index");
        assert!(
            err.to_string().contains("UNIQUE constraint failed")
                || matches!(err, SlashingError::DatabaseError(_)),
            "expected unique-constraint failure, got: {err:?}"
        );
    }

    /// Export always emits canonical GVR metadata; re-import against the same Root
    /// must succeed and preserve rows.
    #[test]
    fn test_export_roundtrips_through_import() {
        let db1 = SlashingDb::open_in_memory().expect("open");
        let gvr = chain_gvr();
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        db1.seed_attestation(pubkey, 10, 11, Some("0xatt".into()), &gvr).expect("seed att");
        db1.seed_block(pubkey, 99, Some("0xblk".into()), &gvr).expect("seed block");

        let exported = db1.export(&gvr).expect("export");
        assert_eq!(
            exported.metadata.genesis_validators_root,
            SlashingDb::root_to_hex(&gvr),
            "export metadata must be canonical"
        );

        let db2 = SlashingDb::open_in_memory().expect("open db2");
        db2.import(&exported, &gvr).expect("re-import");
        assert_eq!(db2.get_attestations(pubkey).expect("atts").len(), 1);
        assert_eq!(db2.get_blocks(pubkey).expect("blocks").len(), 1);
    }

    /// No bulk row rewrite is performed: legacy bare-hex GVR rows remain readable
    /// by the stage path (which keys on pubkey, not the GVR TEXT encoding).
    #[test]
    fn test_existing_rows_with_legacy_encoding_still_readable() {
        let db = SlashingDb::open_in_memory().expect("open");
        let gvr = chain_gvr();
        let bare = "04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let pubkey = normalize_pubkey(
            "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed",
        )
        .expect("valid hex pubkey");

        // Simulate a pre-RF3-18 import that wrote the bare wire form into the row.
        {
            let conn = db.conn.lock();
            conn.execute(
                "INSERT INTO attestations \
                 (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
                 VALUES ('local-vc', ?1, 1, 5, '0xlegacy', ?2)",
                (pubkey.as_ref(), bare),
            )
            .expect("insert legacy bare-gvr row");
        }

        // Stage path must still find the row and reject a double-vote at target 5.
        let err = db
            .check_and_record_attestation(pubkey.as_ref(), 2, 5, Some("0xnew".into()), &gvr)
            .expect_err("legacy bare-gvr row must still block double vote");
        assert!(
            matches!(err, SlashingError::SlashableAttestation(_)),
            "expected double-vote rejection, got: {err:?}"
        );
    }

    #[test]
    fn test_integrity_genesis_root_persists_across_connections() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("genesis.db");
        let root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        {
            let db = SlashingDb::open(&path).expect("failed to open db");
            db.set_genesis_validators_root(&gvr_from_hex(root)).expect("set should succeed");
        }

        {
            let db = SlashingDb::open(&path).expect("failed to reopen db");
            let stored = db.genesis_validators_root().expect("query should succeed");
            assert_eq!(stored, Some(root.to_string()));
        }
    }

    #[test]
    fn test_integrity_metadata_table_created() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let conn = db.conn.lock();
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = 'metadata'",
                [],
                |row| row.get(0),
            )
            .expect("failed to query tables");
        assert_eq!(table_count, 1);
    }

    // --- Watermark and pruning tests ---

    #[test]
    fn test_import_atomic_success() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![
                ValidatorRecord {
                    pubkey: "0xaaa".to_string(),
                    signed_blocks: vec![InterchangeBlock {
                        slot: "10".to_string(),
                        signing_root: None,
                    }],
                    signed_attestations: vec![InterchangeAttestation {
                        source_epoch: "1".to_string(),
                        target_epoch: "2".to_string(),
                        signing_root: None,
                    }],
                },
                ValidatorRecord {
                    pubkey: "0xbbb".to_string(),
                    signed_blocks: vec![InterchangeBlock {
                        slot: "20".to_string(),
                        signing_root: Some("0xroot".to_string()),
                    }],
                    signed_attestations: vec![InterchangeAttestation {
                        source_epoch: "3".to_string(),
                        target_epoch: "4".to_string(),
                        signing_root: Some("0xroot2".to_string()),
                    }],
                },
            ],
        };

        db.import(&interchange, &genesis_root_bytes).expect("import should succeed");

        let att_a = db.get_attestations("0xaaa").expect("query failed");
        assert_eq!(att_a.len(), 1);
        assert_eq!(att_a[0].source_epoch, 1);

        let blocks_b = db.get_blocks("0xbbb").expect("query failed");
        assert_eq!(blocks_b.len(), 1);
        assert_eq!(blocks_b[0].slot, 20);
    }

    #[test]
    fn test_import_atomic_rollback_on_error() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();

        // Validators 1-5 are valid, validator 6 has invalid epoch
        let mut data = Vec::new();
        for i in 0..5 {
            data.push(ValidatorRecord {
                pubkey: format!("0x{:04x}", i),
                signed_blocks: vec![InterchangeBlock {
                    slot: format!("{}", i * 100),
                    signing_root: None,
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: format!("{}", i),
                    target_epoch: format!("{}", i + 1),
                    signing_root: None,
                }],
            });
        }
        // Validator 6 with invalid epoch
        data.push(ValidatorRecord {
            pubkey: "0xbad".to_string(),
            signed_blocks: vec![],
            signed_attestations: vec![InterchangeAttestation {
                source_epoch: "not_a_number".to_string(),
                target_epoch: "10".to_string(),
                signing_root: None,
            }],
        });

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data,
        };

        let result = db.import(&interchange, &genesis_root_bytes);
        assert!(result.is_err());

        // The malformed epoch is rejected before BEGIN IMMEDIATE, so the valid
        // prefix never lands.
        for i in 0..5 {
            let pubkey = format!("0x{:04x}", i);
            let attestations = db.get_attestations(&pubkey).expect("query failed");
            assert_eq!(
                attestations.len(),
                0,
                "validator {} should have no attestations after rollback",
                i
            );
            let blocks = db.get_blocks(&pubkey).expect("query failed");
            assert_eq!(blocks.len(), 0, "validator {} should have no blocks after rollback", i);
        }
    }

    #[test]
    fn test_import_atomic_large_batch() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = CHAIN_GVR_HEX;
        let genesis_root_bytes = chain_gvr();

        let mut data = Vec::new();
        for i in 0..1000 {
            data.push(ValidatorRecord {
                pubkey: format!("0x{:06x}", i),
                signed_blocks: vec![InterchangeBlock {
                    slot: format!("{}", i * 10),
                    signing_root: None,
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: format!("{}", i),
                    target_epoch: format!("{}", i + 1),
                    signing_root: None,
                }],
            });
        }

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data,
        };

        db.import(&interchange, &genesis_root_bytes).expect("large import should succeed");

        // Spot-check a few validators
        let att_0 = db.get_attestations("0x000000").expect("query failed");
        assert_eq!(att_0.len(), 1);
        let att_999 = db.get_attestations("0x0003e7").expect("query failed");
        assert_eq!(att_999.len(), 1);
        assert_eq!(att_999[0].source_epoch, 999);

        let blocks_500 = db.get_blocks("0x0001f4").expect("query failed");
        assert_eq!(blocks_500.len(), 1);
        assert_eq!(blocks_500[0].slot, 5000);
    }
}
