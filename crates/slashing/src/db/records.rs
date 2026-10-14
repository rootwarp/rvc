//! History row CRUD for [`SlashingDb`] (attestations / blocks).
//!
//! Pure code motion from the former monolithic `db` module (E2 part 2).

use rusqlite::Connection;

use super::{normalize_pubkey, SlashingDb};
use crate::error::SlashingError;
use crate::types::{SignedAttestation, SignedBlock};
use eth_types::{Epoch, Root, Slot};

impl SlashingDb {
    /// Insert a signed attestation record (test helper).
    ///
    /// Every row must carry a non-NULL `genesis_validators_root` so that the v3
    /// unique index `(pubkey, genesis_validators_root, target_epoch)` can enforce
    /// per-pubkey uniqueness.  SQLite treats NULL as DISTINCT from all values,
    /// including other NULLs, so a NULL gvr would silently bypass the index.
    #[cfg(test)]
    pub(crate) fn insert_attestation(
        &self,
        attestation: &SignedAttestation,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        let pubkey = attestation.pubkey.as_ref();
        let gvr_hex = Self::root_to_hex(gvr);
        let signing_root = attestation.signing_root.as_ref().map(|r| r.as_hex());
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO attestations \
             (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
             VALUES ('local-vc', ?1, ?2, ?3, ?4, ?5)",
            (
                pubkey,
                attestation.source_epoch as i64,
                attestation.target_epoch as i64,
                signing_root,
                &gvr_hex,
            ),
        )?;
        Ok(())
    }

    /// Seed a signed attestation for **test fixtures only**.
    ///
    /// **Bypasses all EIP-3076 slashing checks.** This is an unconditional
    /// idempotent INSERT: it never evaluates double-vote, surround, or watermark
    /// rules. Production and safety-critical paths must write history via
    /// [`Self::stage_attestation`] → `commit` or [`Self::check_and_record_attestation`].
    ///
    /// If an attestation with the same pubkey and target_epoch already exists,
    /// the operation silently succeeds without modifying the existing record.
    ///
    /// Every row carries a non-NULL `genesis_validators_root`.  The v3 unique index
    /// `(pubkey, genesis_validators_root, target_epoch)` only fires for non-NULL gvr
    /// values — SQLite treats NULL as DISTINCT, so a NULL gvr would bypass the
    /// index entirely.  Callers must supply the chain's pinned GVR.
    ///
    /// Idempotency is checked by `(pubkey, target_epoch)` — this is safe because the
    /// DB is single-chain: every row for a given pubkey has the same gvr.
    #[doc(hidden)]
    pub fn seed_attestation(
        &self,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let gvr_hex = Self::root_to_hex(gvr);
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO attestations \
             (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
             SELECT 'local-vc', ?1, ?2, ?3, ?4, ?5
             WHERE NOT EXISTS (
                 SELECT 1 FROM attestations WHERE pubkey = ?1 AND target_epoch = ?3
             )",
            (pubkey.as_ref(), source_epoch as i64, target_epoch as i64, &signing_root, &gvr_hex),
        )?;
        Ok(())
    }

    /// Get all attestations for a given public key.
    pub fn get_attestations(&self, pubkey: &str) -> Result<Vec<SignedAttestation>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let conn = self.conn.lock();
        Self::read_attestations(&conn, pubkey.as_ref())
    }

    /// Read attestations for `pubkey` using a caller-held `Connection`.
    ///
    /// Private helper used by `export` to run all reads under a single held
    /// lock (KM-1/ADR-008 consistent-snapshot guarantee).  The public
    /// `get_attestations` is a thin wrapper that acquires the lock itself.
    pub(crate) fn read_attestations(
        conn: &Connection,
        pubkey: &str,
    ) -> Result<Vec<SignedAttestation>, SlashingError> {
        let mut stmt = conn.prepare(
            "SELECT pubkey, source_epoch, target_epoch, signing_root
             FROM attestations
             WHERE pubkey = ?1
             ORDER BY target_epoch ASC",
        )?;

        let rows = stmt.query_map([pubkey], |row| {
            Ok(SignedAttestation::from_stored(
                row.get(0)?,
                row.get::<_, i64>(1)? as Epoch,
                row.get::<_, i64>(2)? as Epoch,
                row.get(3)?,
            ))
        })?;

        let mut attestations = Vec::new();
        for row in rows {
            attestations.push(row?);
        }
        Ok(attestations)
    }

    /// Insert a signed block record (test helper).
    ///
    /// Every row must carry a non-NULL `genesis_validators_root` so that the v3
    /// unique index `(pubkey, genesis_validators_root, slot)` can enforce uniqueness.
    /// SQLite treats NULL as DISTINCT from all values including other NULLs, so a
    /// NULL gvr would silently bypass the index.
    #[cfg(test)]
    pub(crate) fn insert_block(
        &self,
        block: &SignedBlock,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        let pubkey = block.pubkey.as_ref();
        let gvr_hex = Self::root_to_hex(gvr);
        let signing_root = block.signing_root.as_ref().map(|r| r.as_hex());
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
             VALUES ('local-vc', ?1, ?2, ?3, ?4)",
            (pubkey, block.slot as i64, signing_root, &gvr_hex),
        )?;
        Ok(())
    }

    /// Get all blocks for a given public key.
    pub fn get_blocks(&self, pubkey: &str) -> Result<Vec<SignedBlock>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let conn = self.conn.lock();
        Self::read_blocks(&conn, pubkey.as_ref())
    }

    /// Read blocks for `pubkey` using a caller-held `Connection`.
    ///
    /// Private helper used by `export` to run all reads under a single held
    /// lock (KM-1/ADR-008 consistent-snapshot guarantee).  The public
    /// `get_blocks` is a thin wrapper that acquires the lock itself.
    pub(crate) fn read_blocks(
        conn: &Connection,
        pubkey: &str,
    ) -> Result<Vec<SignedBlock>, SlashingError> {
        let mut stmt = conn.prepare(
            "SELECT pubkey, slot, signing_root
             FROM blocks
             WHERE pubkey = ?1
             ORDER BY slot ASC",
        )?;

        let rows = stmt.query_map([pubkey], |row| {
            Ok(SignedBlock::from_stored(row.get(0)?, row.get::<_, i64>(1)? as u64, row.get(2)?))
        })?;

        let mut blocks = Vec::new();
        for row in rows {
            blocks.push(row?);
        }
        Ok(blocks)
    }

    /// Read all distinct pubkeys from the DB using a caller-held `Connection`.
    ///
    /// Private helper for `export` so the full export runs under one lock.
    /// Attestations, blocks, and watermarks: a pruned validator has no rows
    /// left, and omitting the watermark table would drop it from the file.
    pub(crate) fn read_all_pubkeys(conn: &Connection) -> Result<Vec<String>, SlashingError> {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT pubkey FROM attestations
             UNION
             SELECT DISTINCT pubkey FROM blocks
             UNION
             SELECT DISTINCT pubkey FROM watermarks",
        )?;

        let rows = stmt.query_map([], |row| row.get(0))?;

        let mut pubkeys = Vec::new();
        for row in rows {
            pubkeys.push(row?);
        }
        Ok(pubkeys)
    }

    /// Seed a signed block for **test fixtures only**.
    ///
    /// **Bypasses all EIP-3076 slashing checks.** This is an unconditional
    /// idempotent INSERT: it never evaluates double-proposal or watermark rules.
    /// Production and safety-critical paths must write history via
    /// [`Self::stage_block`] → `commit` or [`Self::check_and_record_block`].
    ///
    /// If a block with the same pubkey and slot already exists,
    /// the operation silently succeeds without modifying the existing record.
    ///
    /// Every row carries a non-NULL `genesis_validators_root`.  The v3 unique index
    /// `(pubkey, genesis_validators_root, slot)` only fires for non-NULL gvr values —
    /// SQLite treats NULL as DISTINCT, so a NULL gvr would bypass the index entirely.
    /// Callers must supply the chain's pinned GVR.
    ///
    /// Idempotency is checked by `(pubkey, slot)` — safe because the DB is
    /// single-chain: every row for a given pubkey has the same gvr.
    #[doc(hidden)]
    pub fn seed_block(
        &self,
        pubkey: &str,
        slot: Slot,
        signing_root: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let gvr_hex = Self::root_to_hex(gvr);
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
             SELECT 'local-vc', ?1, ?2, ?3, ?4
             WHERE NOT EXISTS (
                 SELECT 1 FROM blocks WHERE pubkey = ?1 AND slot = ?2
             )",
            (pubkey.as_ref(), slot as i64, &signing_root, &gvr_hex),
        )?;
        Ok(())
    }

    /// Get the last signed attestation epoch for a given public key.
    ///
    /// Returns `None` if no attestations have been signed for this validator.
    pub fn last_signed_attestation_epoch(
        &self,
        pubkey: &str,
    ) -> Result<Option<Epoch>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let conn = self.conn.lock();
        let result: Option<i64> = conn
            .query_row(
                "SELECT MAX(target_epoch) FROM attestations WHERE pubkey = ?1",
                [pubkey.as_ref()],
                |row| row.get(0),
            )
            .map_err(SlashingError::from)?;

        Ok(result.map(|e| e as Epoch))
    }

    /// Get the last signed block slot for a given public key.
    ///
    /// Returns `None` if no blocks have been signed for this validator.
    pub fn last_signed_block_slot(&self, pubkey: &str) -> Result<Option<Slot>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let conn = self.conn.lock();
        let result: Option<i64> = conn
            .query_row("SELECT MAX(slot) FROM blocks WHERE pubkey = ?1", [pubkey.as_ref()], |row| {
                row.get(0)
            })
            .map_err(SlashingError::from)?;

        Ok(result.map(|s| s as Slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AttestationSlashingViolation;
    use crate::types::{SignedAttestation, SignedBlock};
    use tempfile::tempdir;

    /// Zero GVR used as a test sentinel.  No GVR is pinned in metadata for these
    /// unit tests, so the M-6 per-call GVR check is skipped and this value is
    /// only written into the row's `genesis_validators_root` column.
    const TEST_GVR: Root = [0u8; 32];

    #[test]
    fn test_insert_and_get_attestation() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation =
            SignedAttestation::new("0x1234", 100, 101, Some("0xabcd")).expect("valid hex pubkey");

        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0], attestation);
    }

    #[test]
    fn test_insert_attestation_without_signing_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation =
            SignedAttestation::new("0x1234", 100, 101, None).expect("valid hex pubkey");

        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].signing_root.is_none());
    }

    #[test]
    fn test_get_attestations_empty() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestations = db.get_attestations("0xnonexistent").expect("failed to get");
        assert!(attestations.is_empty());
    }

    #[test]
    fn test_get_attestations_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestations = vec![
            SignedAttestation::new("0x1234", 100, 101, None).expect("valid hex pubkey"),
            SignedAttestation::new("0x1234", 101, 102, None).expect("valid hex pubkey"),
        ];

        for a in &attestations {
            db.insert_attestation(a, &TEST_GVR).expect("failed to insert");
        }

        let result = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].target_epoch, 101);
        assert_eq!(result[1].target_epoch, 102);
    }

    #[test]
    fn test_attestation_unique_constraint() {
        // v3: uniqueness is enforced by (pubkey, gvr, target_epoch).
        // Raw inserts with NULL gvr bypass the index (SQLite treats NULLs as distinct).
        // The constraint is enforced at the slashing-check level (check_and_record_*).
        // Verify pubkey-scoped uniqueness via the staging API.
        let gvr = [0u8; 32];
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation("0x1234", 100, 101, None, &gvr)
            .expect("first attestation should succeed");

        // Same pubkey+target_epoch with a different signing_root must be rejected.
        let result = db.check_and_record_attestation(
            "0x1234",
            99,
            101,
            Some("0xdifferent".to_string()),
            &gvr,
        );
        assert!(result.is_err(), "duplicate target_epoch attestation must be rejected");
    }

    #[test]
    fn test_insert_and_get_block() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let block = SignedBlock::new("0x1234", 1000, Some("0xabcd")).expect("valid hex pubkey");

        db.insert_block(&block, &TEST_GVR).expect("failed to insert");

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], block);
    }

    #[test]
    fn test_insert_block_without_signing_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let block = SignedBlock::new("0x1234", 1000, None).expect("valid hex pubkey");

        db.insert_block(&block, &TEST_GVR).expect("failed to insert");

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].signing_root.is_none());
    }

    #[test]
    fn test_get_blocks_empty() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let blocks = db.get_blocks("0xnonexistent").expect("failed to get");
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_get_blocks_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let blocks = vec![
            SignedBlock::new("0x1234", 1000, None).expect("valid hex pubkey"),
            SignedBlock::new("0x1234", 1001, None).expect("valid hex pubkey"),
        ];

        for b in &blocks {
            db.insert_block(b, &TEST_GVR).expect("failed to insert");
        }

        let result = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].slot, 1000);
        assert_eq!(result[1].slot, 1001);
    }

    #[test]
    fn test_block_unique_constraint() {
        // v3: uniqueness is enforced by (pubkey, gvr, slot).
        // Raw inserts with NULL gvr bypass the index (SQLite treats NULLs as distinct).
        // The constraint is enforced at the slashing-check level (check_and_record_*).
        // Verify pubkey-scoped uniqueness via the staging API.
        let gvr = [0u8; 32];
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_block("0x1234", 1000, None, &gvr).expect("first block should succeed");

        // Same pubkey+slot with a different signing_root must be rejected.
        let result =
            db.check_and_record_block("0x1234", 1000, Some("0xdifferent".to_string()), &gvr);
        assert!(result.is_err(), "duplicate slot block must be rejected");
    }

    /// Verify the v3 unique index `(pubkey, genesis_validators_root, slot)` fires
    /// for non-NULL gvr rows inserted via raw SQL.
    ///
    /// SQLite treats NULL as DISTINCT from all values (including other NULLs), so a
    /// NULL gvr bypasses a unique index silently.  This test proves the index works
    /// when gvr is non-NULL — which is the guaranteed post-fix state of every insert path.
    #[test]
    fn test_v3_block_unique_index_fires_for_non_null_gvr() {
        let db = SlashingDb::open_in_memory().expect("open");
        let gvr_hex = SlashingDb::root_to_hex(&TEST_GVR);
        let conn = db.conn.lock();

        // Insert a block with non-NULL gvr directly.
        conn.execute(
            "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
             VALUES ('local-vc', '0xaaaa', 999, '0xroot_a', ?1)",
            [&gvr_hex],
        )
        .expect("first insert must succeed");

        // A second insert with the same (pubkey, gvr, slot) but different signing_root
        // must fail because the v3 UNIQUE index fires.
        let err = conn
            .execute(
                "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
                 VALUES ('cn-B', '0xaaaa', 999, '0xroot_b', ?1)",
                [&gvr_hex],
            )
            .expect_err("duplicate (pubkey, gvr, slot) must violate unique index");

        assert!(
            err.to_string().contains("UNIQUE constraint failed"),
            "expected UNIQUE constraint error, got: {err}"
        );
    }

    /// Verify the v3 unique index `(pubkey, genesis_validators_root, target_epoch)` fires
    /// for non-NULL gvr attestation rows.
    #[test]
    fn test_v3_attestation_unique_index_fires_for_non_null_gvr() {
        let db = SlashingDb::open_in_memory().expect("open");
        let gvr_hex = SlashingDb::root_to_hex(&TEST_GVR);
        let conn = db.conn.lock();

        conn.execute(
            "INSERT INTO attestations \
             (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
             VALUES ('local-vc', '0xbbbb', 10, 20, '0xatt_root_a', ?1)",
            [&gvr_hex],
        )
        .expect("first insert must succeed");

        let err = conn
            .execute(
                "INSERT INTO attestations \
                 (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
                 VALUES ('cn-B', '0xbbbb', 11, 20, '0xatt_root_b', ?1)",
                [&gvr_hex],
            )
            .expect_err("duplicate (pubkey, gvr, target_epoch) must violate unique index");

        assert!(
            err.to_string().contains("UNIQUE constraint failed"),
            "expected UNIQUE constraint error, got: {err}"
        );
    }

    #[test]
    fn test_different_pubkeys_isolated() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation1 =
            SignedAttestation::new("0x1111", 100, 101, None).expect("valid hex pubkey");

        let attestation2 =
            SignedAttestation::new("0x2222", 100, 101, None).expect("valid hex pubkey");

        db.insert_attestation(&attestation1, &TEST_GVR).expect("failed to insert");
        db.insert_attestation(&attestation2, &TEST_GVR).expect("failed to insert");

        let result1 = db.get_attestations("0x1111").expect("failed to get");
        let result2 = db.get_attestations("0x2222").expect("failed to get");

        assert_eq!(result1.len(), 1);
        assert_eq!(result2.len(), 1);
        assert_eq!(result1[0].pubkey.as_ref(), "0x1111");
        assert_eq!(result2[0].pubkey.as_ref(), "0x2222");
    }

    #[test]
    fn test_persistence_across_connections() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("test.db");

        {
            let db = SlashingDb::open(&path).expect("failed to open db");
            let attestation =
                SignedAttestation::new("0x1234", 100, 101, None).expect("valid hex pubkey");
            db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");
        }

        {
            let db = SlashingDb::open(&path).expect("failed to reopen db");
            let attestations = db.get_attestations("0x1234").expect("failed to get");
            assert_eq!(attestations.len(), 1);
            assert_eq!(attestations[0].target_epoch, 101);
        }
    }

    #[test]
    fn test_seed_helpers_bypass_eip3076_checks() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Surrounding-vote pair: (4,11) surrounds (5,10). Production
        // `check_and_record_attestation` rejects the second; seed must accept both.
        db.seed_attestation("0xseed", 5, 10, Some("0xa".into()), &TEST_GVR)
            .expect("seed first attestation");
        db.seed_attestation("0xseed", 4, 11, Some("0xb".into()), &TEST_GVR)
            .expect("seed surrounding attestation without rule check");

        let atts = db.get_attestations("0xseed").expect("read attestations");
        assert_eq!(atts.len(), 2, "both seeded rows must be present");

        // Same-slot blocks with different roots: seed returns Ok (idempotent on
        // slot; second insert is a no-op) and must not surface DoubleProposal.
        db.seed_block("0xseed", 1000, Some("0xroot1".into()), &TEST_GVR).expect("seed first block");
        db.seed_block("0xseed", 1000, Some("0xroot2".into()), &TEST_GVR)
            .expect("seed same-slot different root without rule check");

        // Contrast: the checked path rejects the surrounding vote.
        db.check_and_record_attestation("0xseed2", 5, 10, Some("0xa".into()), &TEST_GVR)
            .expect("first checked attestation");
        let rejected =
            db.check_and_record_attestation("0xseed2", 4, 11, Some("0xb".into()), &TEST_GVR);
        assert!(
            matches!(
                rejected,
                Err(SlashingError::SlashableAttestation(
                    AttestationSlashingViolation::SurroundingVote { .. }
                ))
            ),
            "production path must still reject surrounding votes: {rejected:?}"
        );
    }

    #[test]
    fn test_seed_attestation_new() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.seed_attestation("0x1234", 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("record should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].pubkey.as_ref(), "0x1234");
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[0].signing_root.as_ref().map(|r| r.as_hex()), Some("0xabcd"));
    }

    #[test]
    fn test_seed_attestation_without_signing_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.seed_attestation("0x1234", 100, 101, None, &TEST_GVR).expect("record should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].signing_root.is_none());
    }

    #[test]
    fn test_seed_attestation_idempotent_exact_duplicate() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.seed_attestation("0x1234", 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("first record should succeed");

        db.seed_attestation("0x1234", 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("duplicate record should also succeed (idempotent)");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_seed_attestation_idempotent_same_target_different_source() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.seed_attestation("0x1234", 100, 101, None, &TEST_GVR)
            .expect("first record should succeed");

        // Same pubkey and target_epoch but different source_epoch
        // Due to UNIQUE(pubkey, target_epoch), this should be ignored
        db.seed_attestation("0x1234", 99, 101, None, &TEST_GVR)
            .expect("duplicate target should succeed (idempotent)");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        // Original source_epoch should be preserved
        assert_eq!(attestations[0].source_epoch, 100);
    }

    #[test]
    fn test_seed_attestation_multiple_different_targets() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.seed_attestation("0x1234", 100, 101, None, &TEST_GVR)
            .expect("first record should succeed");
        db.seed_attestation("0x1234", 101, 102, None, &TEST_GVR)
            .expect("second record should succeed");
        db.seed_attestation("0x1234", 102, 103, None, &TEST_GVR)
            .expect("third record should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 3);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[1].target_epoch, 102);
        assert_eq!(attestations[2].target_epoch, 103);
    }

    #[test]
    fn test_seed_attestation_different_pubkeys() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.seed_attestation("0x1111", 100, 101, None, &TEST_GVR).expect("record should succeed");
        db.seed_attestation("0x2222", 100, 101, None, &TEST_GVR).expect("record should succeed");

        let att1 = db.get_attestations("0x1111").expect("failed to get");
        let att2 = db.get_attestations("0x2222").expect("failed to get");

        assert_eq!(att1.len(), 1);
        assert_eq!(att2.len(), 1);
    }

    // --- Block slashing protection tests ---

    #[test]
    fn test_seed_block_new() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_block("0x1234", 1000, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("record should succeed");
        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 1000);
        assert_eq!(blocks[0].signing_root.as_ref().map(|r| r.as_hex()), Some("0xabcd"));
    }

    #[test]
    fn test_seed_block_idempotent() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_block("0x1234", 1000, None, &TEST_GVR).expect("first record");
        db.seed_block("0x1234", 1000, None, &TEST_GVR).expect("duplicate record (idempotent)");
        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_seed_block_multiple_slots() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_block("0x1234", 1000, None, &TEST_GVR).expect("record");
        db.seed_block("0x1234", 1001, None, &TEST_GVR).expect("record");
        db.seed_block("0x1234", 1002, None, &TEST_GVR).expect("record");
        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 3);
    }

    #[test]
    fn test_block_last_signed_block_slot_empty_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let result = db.last_signed_block_slot("0x1234").expect("query should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn test_block_last_signed_block_slot_single() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_block("0x1234", 1000, None, &TEST_GVR).expect("record");
        let result = db.last_signed_block_slot("0x1234").expect("query should succeed");
        assert_eq!(result, Some(1000));
    }

    #[test]
    fn test_block_last_signed_block_slot_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_block("0x1234", 1000, None, &TEST_GVR).expect("record");
        db.seed_block("0x1234", 1002, None, &TEST_GVR).expect("record");
        db.seed_block("0x1234", 1001, None, &TEST_GVR).expect("record");
        let result = db.last_signed_block_slot("0x1234").expect("query should succeed");
        assert_eq!(result, Some(1002));
    }

    #[test]
    fn test_block_last_signed_block_slot_different_pubkeys() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_block("0x1111", 1000, None, &TEST_GVR).expect("record");
        db.seed_block("0x2222", 2000, None, &TEST_GVR).expect("record");
        assert_eq!(db.last_signed_block_slot("0x1111").unwrap(), Some(1000));
        assert_eq!(db.last_signed_block_slot("0x2222").unwrap(), Some(2000));
    }

    #[test]
    fn test_liveness_last_signed_attestation_epoch_empty_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let result = db.last_signed_attestation_epoch("0x1234").expect("query should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn test_liveness_last_signed_attestation_epoch_single() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_attestation("0x1234", 100, 101, None, &TEST_GVR).expect("record");
        let result = db.last_signed_attestation_epoch("0x1234").expect("query should succeed");
        assert_eq!(result, Some(101));
    }

    #[test]
    fn test_liveness_last_signed_attestation_epoch_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_attestation("0x1234", 100, 101, None, &TEST_GVR).expect("record");
        db.seed_attestation("0x1234", 103, 105, None, &TEST_GVR).expect("record");
        db.seed_attestation("0x1234", 101, 103, None, &TEST_GVR).expect("record");
        let result = db.last_signed_attestation_epoch("0x1234").expect("query should succeed");
        assert_eq!(result, Some(105));
    }

    #[test]
    fn test_liveness_last_signed_attestation_epoch_different_pubkeys() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_attestation("0x1111", 100, 101, None, &TEST_GVR).expect("record");
        db.seed_attestation("0x2222", 200, 201, None, &TEST_GVR).expect("record");
        assert_eq!(db.last_signed_attestation_epoch("0x1111").unwrap(), Some(101));
        assert_eq!(db.last_signed_attestation_epoch("0x2222").unwrap(), Some(201));
    }
}
