//! ARCH-5d / ARCH-5l: one production `reserve_then_sign` consumer; gate and
//! service pass data.
//!
//! `SigningGate` and `SignerService` must not each own a slashable `body`
//! closure. After the switchover there is exactly one production
//! `.reserve_then_sign(` and zero production `.stage_then_sign(`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crypto::{signing_root_for, DutyRef, SecretKey, SigningCtx};
use eth_types::{AttestationData, Checkpoint, ForkSchedule, Root};
use rvc_signer::{SignerService, SigningGate, ValidatorLockMap, ValidatorSigner};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

fn signer_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn production_text(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

fn count_lines_containing(source: &str, needle: &str) -> Vec<String> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(needle))
        .map(|(idx, line)| format!("{}: {}", idx + 1, line.trim()))
        .collect()
}

/// After ARCH-5l: exactly one production `.reserve_then_sign(` and zero
/// production `.stage_then_sign(`. `spawn_blocking` + `fail_closed_max` stay.
#[test]
fn test_single_production_reserve_then_sign_call_site() {
    let src = signer_src_dir();
    let gate = std::fs::read_to_string(src.join("gate.rs")).expect("read gate.rs");
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("read lib.rs");
    let core = std::fs::read_to_string(src.join("core.rs")).expect("read core.rs");

    for (name, text) in [("gate.rs", gate.as_str()), ("lib.rs", lib.as_str())] {
        let stage_hits = count_lines_containing(text, ".stage_then_sign(");
        let reserve_hits = count_lines_containing(text, ".reserve_then_sign(");
        assert!(
            stage_hits.is_empty(),
            "ARCH-5l: {name} must not call .stage_then_sign(; found:\n{}",
            stage_hits.join("\n")
        );
        assert!(
            reserve_hits.is_empty(),
            "ARCH-5l: {name} must not call .reserve_then_sign(; found:\n{}",
            reserve_hits.join("\n")
        );
    }

    let core_prod = production_text(&core);
    let core_stage = count_lines_containing(core_prod, ".stage_then_sign(");
    assert!(
        core_stage.is_empty(),
        "ARCH-5l: expected zero production .stage_then_sign( in core.rs; found:\n{}",
        core_stage.join("\n")
    );

    assert!(
        core_prod.contains("tokio::task::spawn_blocking"),
        "C9 anchor 7: spawn_blocking must still wrap the slashable sequence"
    );
    assert!(
        core_prod.contains("fail_closed_max"),
        "SEC-1: TimeoutPolicySource::fail_closed_max must stay on the slashable path"
    );

    let mut saw_decl = false;
    let mut reserve_calls = Vec::new();
    let mut staged_row_impls = Vec::new();
    for path in rust_files(&src) {
        let text = std::fs::read_to_string(&path).expect("read signer src");
        let prod = production_text(&text);
        let rel = path.strip_prefix(&src).unwrap_or(&path);
        if prod.contains("fn reserve_then_sign") {
            saw_decl = true;
        }
        for (idx, line) in prod.lines().enumerate() {
            if line.contains(".reserve_then_sign(") {
                reserve_calls.push(format!("{}:{}: {}", rel.display(), idx + 1, line.trim()));
            }
            if line.contains("impl StagedRow for CommittedReservation") {
                staged_row_impls.push(format!("{}:{}", rel.display(), idx + 1));
            }
        }
    }
    assert!(saw_decl, "ARCH-5i: fn reserve_then_sign must exist in crates/signer/src");
    assert_eq!(
        reserve_calls.len(),
        1,
        "ARCH-5l: expected exactly one production .reserve_then_sign(; found:\n{}",
        reserve_calls.join("\n")
    );
    assert!(
        staged_row_impls.is_empty(),
        "VD-5.4: reserve_then_sign must not be a StagedRow impl; found:\n{}",
        staged_row_impls.join("\n")
    );
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read signer src dir") {
        let path = entry.expect("dirent").path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out
}

fn make_fork_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
        altair_fork_epoch: 50,
        altair_fork_version: [0x00, 0x00, 0x00, 0x02],
        bellatrix_fork_epoch: u64::MAX,
        bellatrix_fork_version: [0x00, 0x00, 0x00, 0x03],
        capella_fork_epoch: u64::MAX,
        capella_fork_version: [0x00, 0x00, 0x00, 0x04],
        deneb_fork_epoch: u64::MAX,
        deneb_fork_version: [0x00, 0x00, 0x00, 0x05],
        electra_fork_epoch: u64::MAX,
        electra_fork_version: [0x00, 0x00, 0x00, 0x06],
        fulu_fork_epoch: u64::MAX,
        fulu_fork_version: [0x00, 0x00, 0x00, 0x07],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [0x00, 0x00, 0x00, 0x08],
    }
}

/// Collects `client_cn` from `slashing.audit` events (the only place the
/// scoped CN is observable — history rows always store `local-vc`).
struct AuditCnLayer {
    cns: Arc<Mutex<Vec<String>>>,
}

impl<S> Layer<S> for AuditCnLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "slashing.audit" {
            return;
        }
        struct CnVisitor(Option<String>);
        impl Visit for CnVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "client_cn" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                if field.name() == "client_cn" {
                    self.0 = Some(value.to_string());
                }
            }
        }
        let mut visitor = CnVisitor(None);
        event.record(&mut visitor);
        if let Some(cn) = visitor.0 {
            self.cns.lock().expect("audit cn mutex").push(cn);
        }
    }
}

/// Same attestation through `SigningGate` and `SignerService` must write
/// identical history rows. Audit CN stays per-caller on the gate and
/// `"local-vc"` on the VC path (RED if the fold unifies the CN).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gate_and_service_produce_identical_slashing_rows_for_the_same_duty() {
    let audit_cns = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(AuditCnLayer { cns: Arc::clone(&audit_cns) });
    // spawn_blocking threads do not inherit a thread-local dispatcher.
    let _ = tracing::subscriber::set_global_default(subscriber);

    let sk = SecretKey::generate();
    let (pubkey, signer) = common::composite_with_key(sk);
    let db_gate = common::open_db();
    let db_svc = common::open_db();
    let gate = SigningGate::new(
        Arc::clone(&db_gate),
        common::always_allowed(),
        Arc::clone(&signer),
        Arc::new(ValidatorLockMap::new()),
    );
    let service =
        SignerService::new(signer, Arc::clone(&db_svc)).with_enablement(common::always_allowed());

    const GVR: Root = [0x5d; 32];
    const GATE_CN: &str = "mtls-client-alpha";
    let data = AttestationData {
        slot: 11 * 8,
        index: 0,
        beacon_block_root: [0xbb; 32],
        source: Checkpoint { epoch: 10, root: [0x11; 32] },
        target: Checkpoint { epoch: 11, root: [0x22; 32] },
    };
    let fork_schedule = make_fork_schedule();
    let ctx = SigningCtx { fork_schedule: &fork_schedule, genesis_validators_root: GVR };
    let signing_root = signing_root_for(&DutyRef::Attestation(&data), &ctx);

    gate.sign_attestation(&pubkey, 10, 11, signing_root, GVR, GATE_CN)
        .await
        .expect("gate attestation must succeed");
    service
        .sign_attestation(&data, &pubkey, &fork_schedule, &GVR)
        .await
        .expect("service attestation must succeed");

    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let gate_rows = db_gate.get_attestations(&pubkey_hex).expect("gate rows");
    let svc_rows = db_svc.get_attestations(&pubkey_hex).expect("service rows");
    assert_eq!(gate_rows.len(), 1, "gate must commit one attestation row: {gate_rows:?}");
    assert_eq!(svc_rows.len(), 1, "service must commit one attestation row: {svc_rows:?}");
    assert_eq!(
        gate_rows, svc_rows,
        "committed slashing rows must match (history client_cn is AUDIT_ORIGIN on both paths)"
    );

    let cns = audit_cns.lock().expect("audit cn mutex").clone();
    assert!(
        cns.iter().any(|cn| cn == GATE_CN),
        "gate path must audit with the caller CN {GATE_CN:?}; captured {cns:?}"
    );
    assert!(
        cns.iter().any(|cn| cn == "local-vc"),
        "VC path must audit with local-vc; captured {cns:?}"
    );
    assert_ne!(GATE_CN, "local-vc", "test fixture CNs must differ so unification is observable");
}
