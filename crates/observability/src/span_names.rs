//! Span-name registry.
//!
//! Field keys already have a canonical list ([`crate::logging::fields`]). Span
//! names did not, and they drifted. This module is that list, plus the naming
//! rule for anything added to it.
//!
//! **Naming rule — dotted, lowercase, unprefixed.** A new span name:
//!
//! - contains a `.` (`domain.operation`, not a bare word);
//! - is ASCII lowercase, digits, `_`, and `.` only;
//! - does not start with `rvc.`.
//!
//! [`follows_naming_rule`] is that check. The const list is seeded from the
//! tracked non-test tree and keeps each name's current spelling. Four seeded
//! names predate the dotted rule and are not renamed:
//! `monitoring_push`, `proposer_config_refresh`, `sign`, `slashing_monitor`.
//! Their `.tick` siblings (`monitoring_push.tick` and the rest) are dotted.
//!
//! The architecture-test scan that diffs the tree against [`ALL`] is advisory.
//! It reports a name that is used and not listed here; it does not fail the
//! build. Follow-up **[TRC-7d-block]** flips that report to blocking once the
//! registry has settled.

/// Every span name seeded from tracked non-test source, sorted.
///
/// [`contains`] binary-searches this slice. Keep it sorted and unique.
pub const ALL: &[&str] = &[
    "aggregation.produce",
    "aggregation.submit",
    "attestation.produce",
    "beacon.get_aggregate_attestation",
    "beacon.get_attestation_data",
    "beacon.get_attester_duties",
    "beacon.get_block_root",
    "beacon.get_config_spec",
    "beacon.get_fork",
    "beacon.get_fork_schedule",
    "beacon.get_genesis",
    "beacon.get_node_syncing",
    "beacon.get_node_version",
    "beacon.get_payload_attestation_data",
    "beacon.get_proposer_duties",
    "beacon.get_sync_committee_contribution",
    "beacon.get_sync_committee_duties",
    "beacon.get_validators",
    "beacon.http",
    "beacon.post_ptc_duties",
    "beacon.post_validator_liveness",
    "beacon.prepare_beacon_proposer",
    "beacon.produce_block_v3",
    "beacon.produce_block_v4",
    "beacon.publish_blinded_block",
    "beacon.publish_block",
    "beacon.publish_block_contents",
    "beacon.publish_execution_payload_envelope",
    "beacon.register_validators",
    "beacon.submit_aggregate_and_proofs",
    "beacon.submit_attestation",
    "beacon.submit_attestations",
    "beacon.submit_beacon_committee_subscriptions",
    "beacon.submit_builder_preferences",
    "beacon.submit_contribution_and_proofs",
    "beacon.submit_payload_attestations",
    "beacon.submit_proposer_preferences",
    "beacon.submit_sync_committee_messages",
    "beacon.submit_voluntary_exit",
    "block.propose",
    "bn.attempt",
    "bn.strategy.best",
    "bn.strategy.broadcast",
    "bn.strategy.failover",
    "bn.strategy.first",
    "bn_manager.check_sync_status",
    "bn_manager.health_scores",
    "bn_manager.synced_indices",
    "builder.broadcast_builder_preferences",
    "builder.broadcast_proposer_preferences",
    "builder.prepare_proposers",
    "builder.register",
    "crypto.sign_voluntary_exit",
    "duty_tracker.check_attester_reorg",
    "duty_tracker.check_proposer_reorg",
    "duty_tracker.check_ptc_reorg",
    "duty_tracker.evict_old_caches",
    "duty_tracker.fetch_attester_duties",
    "duty_tracker.fetch_proposer_duties",
    "duty_tracker.fetch_ptc_duties",
    "duty_tracker.fetch_sync_committee_duties",
    "duty_tracker.get_duties_for_slot",
    "duty_tracker.get_duty",
    "duty_tracker.get_proposer_duty",
    "duty_tracker.get_sync_committee_duties",
    "epoch.boundary",
    "grpc.sign",
    "grpc_signer.connect",
    "index.resolve",
    "index.resolve.tick",
    "keymanager.delete_keystores",
    "keymanager.delete_remote_keys",
    "keymanager.import_keystores",
    "keymanager.import_remote_keys",
    "monitoring_push",
    "monitoring_push.tick",
    "orchestrator.check_reorg",
    "orchestrator.fetch_epoch_duties",
    "orchestrator.maybe_propose_block",
    "orchestrator.on_epoch_boundary",
    "orchestrator.prepare_proposers",
    "orchestrator.process_slot",
    "orchestrator.produce_aggregations",
    "orchestrator.produce_payload_attestations",
    "orchestrator.produce_sync_contributions",
    "orchestrator.produce_sync_messages",
    "orchestrator.submit_committee_subscriptions",
    "propagator.propagate",
    "proposer_config_refresh",
    "proposer_config_refresh.tick",
    "secret_provider.fetch_key",
    "secret_provider.gcp.fetch",
    "secret_provider.gcp.list",
    "secret_provider.list_keys",
    "secret_provider.load_all",
    "sign",
    "sign.aggregate_and_proof",
    "sign.aggregate_and_proof_root",
    "sign.attestation",
    "sign.block",
    "sign.builder_registration",
    "sign.builder_request_auth",
    "sign.contribution_and_proof",
    "sign.electra_aggregate_and_proof",
    "sign.envelope",
    "sign.execution_payload_envelope",
    "sign.grpc_remote_typed",
    "sign.payload_attestation",
    "sign.proposer_preferences",
    "sign.randao",
    "sign.remote",
    "sign.selection_proof",
    "sign.sync_committee_message",
    "sign.sync_committee_selection_proof",
    "sign.voluntary_exit",
    "signer.dvt.coordinate",
    "signer.dvt.partial_sign_attestation_data",
    "signer.dvt.partial_sign_beacon_block",
    "signer.dvt.partial_sign_block_header",
    "signer.dvt.partial_sign_payload_attestation",
    "signer.dvt.partial_sign_root",
    "signer.dvt.partial_sign_sync_committee",
    "slashing.check",
    "slashing.db.attestation",
    "slashing.db.block",
    "slashing.db.export",
    "slashing.db.import",
    "slashing.db.prune",
    "slashing_monitor",
    "slashing_monitor.tick",
    "slot.phase.aggregation",
    "slot.phase.attestation",
    "slot.phase.block",
    "slot.phase.payload_attestation",
    "slot.phase.sync_message",
    "slot.process",
    "validator_store.list_enabled_pubkeys",
    "validator_store.load_from_config",
    "validator_store.reload_config",
    "validator_store.save_config",
];

/// Returns whether `name` is in the span-name registry.
///
/// ```
/// use rvc_observability::span_names::contains;
///
/// assert!(contains("grpc.sign"));
/// assert!(!contains("not.a.registered.span"));
/// ```
#[must_use]
pub fn contains(name: &str) -> bool {
    ALL.binary_search(&name).is_ok()
}

/// Normative shape for a new span name: dotted, ASCII-lowercase, unprefixed.
///
/// - dotted: contains at least one `.`
/// - lowercase: every byte is `a-z`, `0-9`, `_`, or `.`
/// - unprefixed: does not start with `rvc.`
///
/// ```
/// use rvc_observability::span_names::follows_naming_rule;
///
/// assert!(follows_naming_rule("grpc.sign"));
/// assert!(!follows_naming_rule("sign"));
/// assert!(!follows_naming_rule(concat!("rvc", ".slot")));
/// ```
#[must_use]
pub fn follows_naming_rule(name: &str) -> bool {
    let dotted = name.contains('.');
    let lowercase = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.');
    // Split so this source file has no quoted `rvc.` span literal for the prefix gate.
    let unprefixed = !name.starts_with(concat!("rvc", "."));
    dotted && lowercase && unprefixed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_sorted_and_unique() {
        let mut sorted = ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ALL, sorted.as_slice(), "span_names::ALL must be sorted and unique");
    }

    #[test]
    fn naming_rule_matches_the_documented_shape() {
        assert!(follows_naming_rule("grpc.sign"));
        assert!(follows_naming_rule("duty_tracker.get_duty"));
        assert!(follows_naming_rule("slot.phase.block"));
        assert!(follows_naming_rule("monitoring_push.tick"));
        assert!(!follows_naming_rule("sign"));
        assert!(!follows_naming_rule("monitoring_push"));
        assert!(!follows_naming_rule("proposer_config_refresh"));
        assert!(!follows_naming_rule("slashing_monitor"));
        assert!(!follows_naming_rule(concat!("rvc", ".slot")));
        assert!(!follows_naming_rule("Grpc.sign"));
        assert!(!follows_naming_rule(""));
    }

    /// Spellings already in the tree that predate the dotted rule. Do not rename them.
    const SEEDED_UNDOTTED: &[&str] =
        &["monitoring_push", "proposer_config_refresh", "sign", "slashing_monitor"];

    #[test]
    fn seeded_names_follow_the_rule_except_historical_undotted() {
        let mut undotted: Vec<&str> =
            ALL.iter().copied().filter(|name| !name.contains('.')).collect();
        undotted.sort_unstable();
        assert_eq!(undotted, SEEDED_UNDOTTED);
        for name in ALL {
            assert!(!name.starts_with(concat!("rvc", ".")), "{name} carries the legacy prefix");
            assert!(
                name.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.'
                }),
                "{name} is not lowercase"
            );
            assert!(
                follows_naming_rule(name) || SEEDED_UNDOTTED.contains(name),
                "{name} breaks the naming rule"
            );
        }
    }

    #[test]
    fn tracing_initiative_names_are_registered_and_unprefixed() {
        for name in [
            "grpc.sign",
            "duty_tracker.get_duty",
            "duty_tracker.get_duties_for_slot",
            "duty_tracker.get_proposer_duty",
            "duty_tracker.get_sync_committee_duties",
            "index.resolve",
            "index.resolve.tick",
            "monitoring_push",
            "monitoring_push.tick",
            "proposer_config_refresh",
            "proposer_config_refresh.tick",
            "slashing_monitor",
            "slashing_monitor.tick",
        ] {
            assert!(contains(name), "{name} missing from the span-name registry");
            assert!(!name.starts_with(concat!("rvc", ".")), "{name}");
        }
    }
}
