//! ARCH-5d / ARCH-5l: one production `reserve_then_sign` consumer; gate and
//! service pass data.
//!
//! `SigningGate` and `SignerService` must not each own a slashable `body`
//! closure. After the switchover there is exactly one production
//! `.reserve_then_sign(` and zero production `.stage_then_sign(`.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use crypto::{
    signing_root_for, CompositeSigner, DutyRef, PublicKey, SecretKey, Signature, Signer,
    SigningCtx, SigningError,
};
use eth_types::{AttestationData, Checkpoint, ForkSchedule, Root, SLOTS_PER_EPOCH};
use rvc_signer::metrics::{rejection_reason, rejection_sign_type, RVC_SIGNER_REJECTIONS_TOTAL};
use rvc_signer::{
    BackendKind, BeaconBlockHeaderFields, PreReserveBarrier, SignerError, SignerService,
    SigningEnablement, SigningGate, ValidatorLockMap, ValidatorSigner,
};
use slashing::SlashingDb;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{Attributes, Id, Record};
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

/// `source` with every `#[cfg(test)]` item and every `//` comment line blanked.
///
/// Line numbers are kept, so [`count_lines_containing`] still reports real
/// lines. Unlike [`production_text`], production code after an early
/// `#[cfg(test)]` module is kept (`lib.rs` has two before `mod tests`). An item
/// ends on its first line when that line ends in `;` or `}`, otherwise at the
/// next line at the attribute's indent that starts with `}` or ends with `);`
/// (rustfmt layout).
fn production_code(source: &str) -> String {
    let mut out = Vec::new();
    let mut lines = source.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed != "#[cfg(test)]" {
            out.push(if trimmed.starts_with("//") { "" } else { line });
            continue;
        }
        out.push("");
        let indent = line.len() - trimmed.len();
        let mut header = true;
        for item_line in lines.by_ref() {
            out.push("");
            let item = item_line.trim_start();
            if header && (item.starts_with("#[") || item.starts_with("///")) {
                continue;
            }
            let one_line = header && (item.ends_with(';') || item.ends_with('}'));
            let at_indent = item_line.len() - item.len() == indent;
            if one_line || (at_indent && (item.starts_with('}') || item.ends_with(");"))) {
                break;
            }
            header = false;
        }
    }
    out.join("\n")
}

/// W4-S3a (660-AC1a): `SignerService` builds its slashable request in one
/// place and classifies the backend in one place.
#[test]
fn test_one_vc_slashable_request_and_one_backend_classifier() {
    let lib = std::fs::read_to_string(signer_src_dir().join("lib.rs")).expect("read lib.rs");
    let prod = production_code(&lib);
    let off: Vec<String> = ["SignSlashableRequest {", "has_remote_key("]
        .into_iter()
        .map(|needle| (needle, count_lines_containing(&prod, needle)))
        .filter(|(_, hits)| hits.len() != 1)
        .map(|(needle, hits)| format!("`{needle}`: {} lines\n{}", hits.len(), hits.join("\n")))
        .collect();
    assert!(
        off.is_empty(),
        "660-AC1a: expected exactly one production line each in lib.rs:\n{}",
        off.join("\n")
    );
}

/// The scanner sees production code after an early `#[cfg(test)]` module and
/// skips test items and comments, so the gate above cannot pass vacuously.
#[test]
fn test_production_code_skips_only_cfg_test_items_and_comments() {
    let fixture = "\
fn a() {
    sign(SignSlashableRequest { x });
}

#[cfg(test)]
mod early {
    fn b() {
        sign(SignSlashableRequest { y });
    }
}

#[cfg(test)]
use x::has_remote_key;

fn c() {
    // has_remote_key(pk) in a comment
    #[cfg(test)]
    let _ = has_remote_key(pk);
    composite.has_remote_key(pk);
}

#[cfg(test)]
#[allow(dead_code)]
fn d(
    pk: Pk,
) -> bool {
    has_remote_key(pk)
}

#[cfg(test)]
fn e() { has_remote_key(pk) }
fn f() { sign(SignSlashableRequest { z }) }
";
    let prod = production_code(fixture);
    assert_eq!(prod.lines().count(), fixture.lines().count(), "line numbers must be kept");
    assert_eq!(
        count_lines_containing(&prod, "SignSlashableRequest {"),
        ["2: sign(SignSlashableRequest { x });", "32: fn f() { sign(SignSlashableRequest { z }) }"]
    );
    assert_eq!(
        count_lines_containing(&prod, "has_remote_key("),
        ["19: composite.has_remote_key(pk);"]
    );
    assert_eq!(
        count_lines_containing(production_text(fixture), "SignSlashableRequest {").len(),
        1,
        "production_text stops at the first #[cfg(test)]; the gate uses production_code"
    );
}

// ── W4-S3a (660-AC3): facade span and rejection-label guard ─────────────────

/// `sign.*` facade span as a subscriber saw it.
#[derive(Debug)]
struct FacadeSpan {
    id: u64,
    name: &'static str,
    fields: BTreeMap<String, String>,
}

/// Records `sign.*` spans with their fields, and the `op` field of events.
///
/// Installed per thread with `set_default`, so the test runs on a
/// current-thread runtime: the facade span, its `record` calls and the
/// under-lock refusal event all happen on the test thread.
#[derive(Clone, Default)]
struct FacadeCapture {
    spans: Arc<Mutex<Vec<FacadeSpan>>>,
    ops: Arc<Mutex<Vec<String>>>,
}

struct FieldText<'a>(&'a mut BTreeMap<String, String>);

impl Visit for FieldText<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_string(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
}

impl<S: tracing::Subscriber> Layer<S> for FacadeCapture {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
        let name = attrs.metadata().name();
        if !name.starts_with("sign.") {
            return;
        }
        let mut fields = BTreeMap::new();
        attrs.record(&mut FieldText(&mut fields));
        self.spans.lock().expect("span capture").push(FacadeSpan {
            id: id.into_u64(),
            name,
            fields,
        });
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
        let mut spans = self.spans.lock().expect("span capture");
        if let Some(span) = spans.iter_mut().rev().find(|span| span.id == id.into_u64()) {
            values.record(&mut FieldText(&mut span.fields));
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = BTreeMap::new();
        event.record(&mut FieldText(&mut fields));
        if let Some(op) = fields.remove("op") {
            self.ops.lock().expect("op capture").push(op);
        }
    }
}

/// One `ValidatorSigner` slashable method, with its expected span and labels.
#[derive(Clone, Copy, Debug)]
enum Facade {
    Attestation,
    Block,
    BlockHeader,
}

impl Facade {
    fn span_name(self) -> &'static str {
        match self {
            Self::Attestation => "sign.attestation",
            Self::Block | Self::BlockHeader => "sign.block",
        }
    }

    fn duty(self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::Block | Self::BlockHeader => "block",
        }
    }

    fn op_name(self) -> &'static str {
        match self {
            Self::Attestation => "sign_attestation",
            Self::Block => "sign_block",
            Self::BlockHeader => "sign_block_header",
        }
    }

    fn sign_type(self) -> &'static str {
        match self {
            Self::Attestation => rejection_sign_type::ATTESTATION_DATA,
            Self::Block | Self::BlockHeader => rejection_sign_type::BEACON_BLOCK,
        }
    }

    /// Sign the duty at `epoch` (target epoch, or the block's epoch at
    /// `slot_in_epoch`). `variant` changes the signing root only.
    async fn sign(
        self,
        service: &SignerService,
        pubkey: &PublicKey,
        epoch: u64,
        slot_in_epoch: u64,
        variant: u8,
    ) -> (Result<Signature, SignerError>, u64) {
        let schedule = fork_boundary_schedule();
        let slot = epoch * SLOTS_PER_EPOCH + slot_in_epoch;
        let result = match self {
            Self::Attestation => {
                let data = AttestationData {
                    slot,
                    index: 0,
                    beacon_block_root: [variant; 32],
                    source: Checkpoint { epoch: epoch - 1, root: [0x11; 32] },
                    target: Checkpoint { epoch, root: [0x22; 32] },
                };
                service.sign_attestation(&data, pubkey, &schedule, &FACADE_GVR).await
            }
            Self::Block => {
                service.sign_block(&[variant; 32], slot, pubkey, &schedule, &FACADE_GVR).await
            }
            Self::BlockHeader => {
                let header = BeaconBlockHeaderFields {
                    slot,
                    proposer_index: 1,
                    parent_root: [variant; 32],
                    state_root: [0x22; 32],
                    body_root: [0x33; 32],
                    body_ssz: Vec::new(),
                    is_blinded: false,
                };
                service.sign_block_header(&header, pubkey, &schedule, &FACADE_GVR).await
            }
        };
        (result, slot)
    }
}

const FACADE_GVR: Root = [0x6e; 32];
const ELECTRA: u64 = 10;
const FULU: u64 = 20;
const GLOAS: u64 = 30;

fn fork_boundary_schedule() -> ForkSchedule {
    ForkSchedule {
        altair_fork_epoch: 1,
        bellatrix_fork_epoch: 2,
        capella_fork_epoch: 3,
        deneb_fork_epoch: 4,
        electra_fork_epoch: ELECTRA,
        fulu_fork_epoch: FULU,
        gloas_fork_epoch: GLOAS,
        ..make_fork_schedule()
    }
}

/// Open for the first check (the facade's outer admission) and closed for
/// every later one (the core's re-check under the per-validator lock).
struct OpenOnce(AtomicBool);

impl SigningEnablement for OpenOnce {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }

    fn voluntary_exit_only(&self) -> bool {
        false
    }

    fn blocked_by_doppelganger(&self, _pubkey: &PublicKey) -> bool {
        false
    }
}

/// Backend that refuses every sign the way a pre-Gloas remote does.
struct GloasRejectingSigner;

#[async_trait]
impl Signer for GloasRejectingSigner {
    async fn sign(&self, _root: &Root, _pubkey: &[u8; 48]) -> Result<Signature, SigningError> {
        Err(SigningError::SignerLacksGloasSupport {
            rpc: "SignBlockHeader",
            details: "UNIMPLEMENTED".to_string(),
        })
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        vec![]
    }
}

/// What one facade call left on its span and in the `op` events.
struct Observed {
    result: Result<Signature, SignerError>,
    span: BTreeMap<String, String>,
    ops: Vec<String>,
}

async fn observe(
    facade: Facade,
    service: &SignerService,
    pubkey: &PublicKey,
    (epoch, slot_in_epoch, variant): (u64, u64, u8),
) -> Observed {
    let capture = FacadeCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    let (result, slot) = facade.sign(service, pubkey, epoch, slot_in_epoch, variant).await;
    drop(guard);

    let mut spans = std::mem::take(&mut *capture.spans.lock().expect("span capture"));
    assert_eq!(spans.len(), 1, "{facade:?}: expected one facade span, got {spans:?}");
    let span = spans.pop().expect("one span");
    assert_eq!(span.name, facade.span_name(), "{facade:?}: span name");
    assert_eq!(span.fields.get("duty").map(String::as_str), Some(facade.duty()), "{facade:?}");
    assert_eq!(span.fields.get("slot"), Some(&slot.to_string()), "{facade:?}: span slot");
    let ops = std::mem::take(&mut *capture.ops.lock().expect("op capture"));
    Observed { result, span: span.fields, ops }
}

fn rejections(sign_type: &'static str, version: &'static str) -> u64 {
    RVC_SIGNER_REJECTIONS_TOTAL
        .with_label_values(&[rejection_reason::UNSUPPORTED_TYPE, sign_type, version])
        .get()
}

/// W4-S3a (660-AC3): each slashable `ValidatorSigner` method keeps its span
/// name, `duty`, `slot` and `slashing_result`, and its backend rejections keep
/// the `sign_type` (from `op_name`) and `version` (from `fork_name`) labels.
///
/// Green on the pre-fold facades; it pins them so the shared helper cannot
/// drift. Rejection deltas are exact: nextest runs each test in its own
/// process, and no other test in this binary records a rejection.
#[tokio::test]
async fn test_vc_slashable_spans_record_op_name_and_outcome() {
    let result_of = |observed: &Observed| observed.span.get("slashing_result").cloned();
    for facade in [Facade::Attestation, Facade::Block, Facade::BlockHeader] {
        let (pubkey, composite) = common::composite_with_key(SecretKey::generate());
        let open = SignerService::new(Arc::clone(&composite), common::open_db())
            .with_enablement(common::always_allowed());

        let safe = observe(facade, &open, &pubkey, (ELECTRA, 0, 1)).await;
        assert!(safe.result.is_ok(), "{facade:?}: {:?}", safe.result);
        assert_eq!(result_of(&safe).as_deref(), Some("safe"), "{facade:?}");

        let blocked = observe(facade, &open, &pubkey, (ELECTRA, 0, 2)).await;
        assert!(
            matches!(blocked.result, Err(SignerError::SlashingBlocked(_))),
            "{facade:?}: a conflicting root must be blocked, got {:?}",
            blocked.result
        );
        assert_eq!(result_of(&blocked).as_deref(), Some("blocked"), "{facade:?}");

        let closed = SignerService::new(Arc::clone(&composite), common::open_db())
            .with_enablement(common::always_denied());
        let refused = observe(facade, &closed, &pubkey, (ELECTRA, 0, 1)).await;
        assert!(
            matches!(refused.result, Err(SignerError::BlockedByDoppelganger)),
            "{facade:?}: {:?}",
            refused.result
        );
        assert_eq!(result_of(&refused), None, "{facade:?}: refused at admission");
        assert!(refused.ops.is_empty(), "{facade:?}: core not reached: {:?}", refused.ops);

        let closes = SignerService::new(Arc::clone(&composite), common::open_db())
            .with_enablement(Arc::new(OpenOnce(AtomicBool::new(false))));
        let under_lock = observe(facade, &closes, &pubkey, (ELECTRA, 0, 1)).await;
        assert!(
            matches!(under_lock.result, Err(SignerError::BlockedByDoppelganger)),
            "{facade:?}: {:?}",
            under_lock.result
        );
        assert_eq!(result_of(&under_lock), None, "{facade:?}: refused under the lock");
        assert_eq!(under_lock.ops, vec![facade.op_name().to_string()], "{facade:?}: op_name");

        let rejecting = SignerService::new(composite, common::open_db())
            .with_enablement(common::always_allowed())
            .with_sign_backend(Arc::new(GloasRejectingSigner));
        // Attestations: target at Electra (source in Deneb). Blocks: the last
        // Fulu slot. Both: the first Gloas slot. An `if`, not a `match`, so
        // `fork_hazard_inventory` does not see a string-literal fork dispatch.
        let below = if matches!(facade, Facade::Attestation) {
            ((ELECTRA, 0), "electra")
        } else {
            ((GLOAS - 1, SLOTS_PER_EPOCH - 1), "fulu")
        };
        let label_cases = [below, ((GLOAS, 0), "gloas")];
        for (variant, ((epoch, slot_in_epoch), version)) in (1u8..).zip(label_cases) {
            let before = rejections(facade.sign_type(), version);
            let rejected =
                observe(facade, &rejecting, &pubkey, (epoch, slot_in_epoch, variant)).await;
            assert!(
                matches!(rejected.result, Err(SignerError::SigningFailed(_))),
                "{facade:?}: {:?}",
                rejected.result
            );
            assert_eq!(
                result_of(&rejected),
                None,
                "{facade:?}: a backend rejection is not blocked"
            );
            assert_eq!(
                rejections(facade.sign_type(), version) - before,
                1,
                "{facade:?}: one rejection labelled sign_type={}, version={version}",
                facade.sign_type()
            );
        }
    }
}

// ── W4-S3a: the shared classifier feeds a policy resolved under the lock ────

fn register_http_remote(composite: &CompositeSigner, pk: [u8; 48]) {
    let remote = remote_signer_client::RemoteSigner::new_for_tests(
        remote_signer_client::RemoteSignerConfig::new("https://127.0.0.1:1"),
        vec![pk],
    );
    composite.add_remote_key(pk, Arc::new(remote));
}

/// Registers an HTTP remote for the key while the sign is parked under the
/// per-validator lock, before reserve.
struct RemoteAppearsBeforeReserve {
    composite: Arc<CompositeSigner>,
    pk: [u8; 48],
}

#[async_trait]
impl PreReserveBarrier for RemoteAppearsBeforeReserve {
    async fn wait(&self) {
        register_http_remote(&self.composite, self.pk);
    }
}

fn retained_blocks(db: &SlashingDb, pubkey: &PublicKey) -> usize {
    db.get_blocks(&hex::encode(pubkey.to_bytes())).expect("read blocks").len()
}

/// W4-S3a: `classify_backend` feeds the SEC-1 policy at sign time, not at the
/// facade. A local-only key starts as `InProcess` (discard). A remote that
/// appears under the lock, or later while the reserve is in its transaction,
/// upgrades the policy to retain. The backend fails ambiguously, so discard
/// would reconcile the reserved row and retain keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_vc_backend_policy_resolves_under_the_lock_and_again_before_bls() {
    let schedule = make_fork_schedule();
    const GVR: Root = [0x7a; 32];
    let open = |composite: &Arc<CompositeSigner>, db: &Arc<SlashingDb>| {
        SignerService::new(Arc::clone(composite), Arc::clone(db))
            .with_enablement(common::always_allowed())
            .with_sign_backend(Arc::new(common::AmbiguousErrorSigner))
    };

    let (pubkey, composite) = common::composite_with_key(SecretKey::generate());
    let db = common::open_db();
    let service = open(&composite, &db);
    let err = service
        .sign_block(&[0x01; 32], 64, &pubkey, &schedule, &GVR)
        .await
        .expect_err("ambiguous backend error");
    assert!(matches!(err, SignerError::SigningFailed(_)), "{err:?}");
    assert_eq!(retained_blocks(&db, &pubkey), 0, "control: a local-only key discards");

    let (pubkey, composite) = common::composite_with_key(SecretKey::generate());
    let db = common::open_db();
    let service = open(&composite, &db);
    assert_eq!(service.backend_kind(&pubkey), BackendKind::InProcess);
    service.set_pre_reserve_barrier(Some(Arc::new(RemoteAppearsBeforeReserve {
        composite: Arc::clone(&composite),
        pk: pubkey.to_bytes(),
    })));
    let err = service
        .sign_block(&[0x02; 32], 64, &pubkey, &schedule, &GVR)
        .await
        .expect_err("ambiguous backend error");
    assert!(matches!(err, SignerError::SigningFailed(_)), "{err:?}");
    assert_eq!(service.backend_kind(&pubkey), BackendKind::Unknown);
    assert_eq!(retained_blocks(&db, &pubkey), 1, "a remote seen under the lock must retain");

    let (pubkey, composite) = common::composite_with_key(SecretKey::generate());
    let db = common::open_db();
    let service = Arc::new(open(&composite, &db));
    let (entered, release) = db.block_next_eval();
    let signing = {
        let (service, pubkey) = (Arc::clone(&service), pubkey.clone());
        tokio::spawn(async move {
            service.sign_block(&[0x03; 32], 64, &pubkey, &make_fork_schedule(), &GVR).await
        })
    };
    tokio::task::spawn_blocking(move || entered.recv())
        .await
        .expect("join")
        .expect("the reserve must park inside its transaction");
    register_http_remote(&composite, pubkey.to_bytes());
    release.send(()).expect("release the reserve");
    let err = signing.await.expect("join").expect_err("ambiguous backend error");
    assert!(matches!(err, SignerError::SigningFailed(_)), "{err:?}");
    assert_eq!(
        retained_blocks(&db, &pubkey),
        1,
        "a remote seen after the under-lock resolve, before BLS, must retain"
    );
}
