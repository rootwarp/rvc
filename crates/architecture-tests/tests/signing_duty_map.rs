//! Signing-duty source pin (741-3).
//!
//! Every `.rs` file under `crates/signer/src` is parsed with `syn`. Each
//! `SigningDuty` variant site is recorded against its enclosing fn, whatever
//! its visibility, qualifiers or header layout: plain, raw (`r#`) and
//! type-relative (`<SigningDuty>::`) paths, `use` imports of a variant, and the
//! same tokens inside macros and attributes. A second fn with the same key in
//! one file is kept apart (`#2`). Any other `VoluntaryExit` ident, for example
//! through an aliased `SigningDuty`, is recorded as a backstop. Only exact
//! `#[cfg(test)]`, `#[test]` and `#[tokio::test]` skip code; `#[cfg(any(test,
//! feature = "test-utils"))]` items are production. Exactly one production fn
//! per signer surface (`SignerService`, `SigningGate`) names
//! `SigningDuty::VoluntaryExit`, and it is `sign_voluntary_exit`: the exit-only
//! enablement depends on it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use syn::buffer::{Cursor, TokenBuffer};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{Attribute, Ident, UseTree};

/// Enclosing fn (`Type::method`, or a free fn's name) → variants it names.
type DutyMap = BTreeMap<String, BTreeSet<String>>;

const OUTSIDE_FN: &str = "<outside fn>";
const DUTY_ENUM: &str = "SigningDuty";
const EXIT: &str = "VoluntaryExit";
const EXIT_FN: &str = "sign_voluntary_exit";

/// Production sites of one source file.
#[derive(Default)]
struct FileScan {
    duties: DutyMap,
    /// Enclosing fns with a `VoluntaryExit` ident anywhere (the backstop).
    exit_idents: BTreeSet<String>,
}

fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let path = attr.path();
        let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let test_fn = names == ["test"] || names == ["tokio", "test"];
        let cfg_test =
            path.is_ident("cfg") && attr.parse_args::<Ident>().is_ok_and(|ident| ident == "test");
        test_fn || cfg_test
    })
}

/// The ident after `SigningDuty ::` (or `SigningDuty > ::`) in unparsed tokens.
fn variant_after(cursor: Cursor<'_>) -> Option<Ident> {
    let cursor = match cursor.punct() {
        Some((gt, next)) if gt.as_char() == '>' => next,
        _ => cursor,
    };
    let (first, cursor) = cursor.punct()?;
    let (second, cursor) = cursor.punct()?;
    if first.as_char() != ':' || second.as_char() != ':' {
        return None;
    }
    cursor.ident().map(|(ident, _)| ident)
}

#[derive(Default)]
struct DutyVisitor {
    owners: Vec<String>,
    fns: Vec<String>,
    seen: BTreeMap<String, usize>,
    /// Set by a `<SigningDuty>` qualified self; syn visits its path next.
    qself_position: Option<usize>,
    scan: FileScan,
}

impl DutyVisitor {
    fn current_fn(&self) -> String {
        self.fns.last().map_or(OUTSIDE_FN, String::as_str).to_string()
    }

    fn record(&mut self, variant: String) {
        let function = self.current_fn();
        self.scan.duties.entry(function).or_default().insert(variant);
    }

    fn record_ident(&mut self, ident: &Ident) {
        if ident.unraw() == EXIT {
            let function = self.current_fn();
            self.scan.exit_idents.insert(function);
        }
    }

    fn scan_tokens(&mut self, mut cursor: Cursor<'_>) {
        while !cursor.eof() {
            if let Some((inner, _, _, next)) = cursor.any_group() {
                self.scan_tokens(inner);
                cursor = next;
            } else if let Some((ident, next)) = cursor.ident() {
                self.record_ident(&ident);
                if ident.unraw() == DUTY_ENUM {
                    if let Some(variant) = variant_after(next) {
                        self.record(variant.unraw().to_string());
                    }
                }
                cursor = next;
            } else if let Some((_, next)) = cursor.token_tree() {
                cursor = next;
            } else {
                break;
            }
        }
    }

    fn record_tokens(&mut self, buffer: &TokenBuffer) {
        self.scan_tokens(buffer.begin());
    }

    /// `use …SigningDuty::{A, B as C, *}` names `A`, `B` and `*`.
    fn record_use(&mut self, tree: &UseTree, after_duty: bool) {
        match tree {
            UseTree::Path(path) => {
                if after_duty {
                    self.record(path.ident.unraw().to_string());
                }
                self.record_use(&path.tree, path.ident.unraw() == DUTY_ENUM);
            }
            UseTree::Name(name) if after_duty => self.record(name.ident.unraw().to_string()),
            UseTree::Rename(rename) if after_duty => self.record(rename.ident.unraw().to_string()),
            UseTree::Glob(_) if after_duty => self.record("*".to_string()),
            UseTree::Group(group) => {
                for item in &group.items {
                    self.record_use(item, after_duty);
                }
            }
            _ => {}
        }
    }

    fn method(&self, name: &Ident) -> String {
        match self.owners.last() {
            Some(owner) => format!("{owner}::{name}"),
            None => name.to_string(),
        }
    }

    fn in_owner(&mut self, owner: String, walk: impl FnOnce(&mut Self)) {
        self.owners.push(owner);
        walk(self);
        self.owners.pop();
    }

    fn in_fn(&mut self, function: String, walk: impl FnOnce(&mut Self)) {
        let count = {
            let count = self.seen.entry(function.clone()).or_default();
            *count += 1;
            *count
        };
        self.fns.push(if count == 1 { function } else { format!("{function}#{count}") });
        walk(self);
        self.fns.pop();
    }
}

impl<'ast> Visit<'ast> for DutyVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if is_test_only(&node.attrs) {
            return;
        }
        let owner = match node.self_ty.as_ref() {
            syn::Type::Path(ty) => ty.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        };
        self.in_owner(owner.unwrap_or_else(|| "<impl>".to_string()), |v| {
            visit::visit_item_impl(v, node);
        });
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if !is_test_only(&node.attrs) {
            self.in_owner(node.ident.to_string(), |v| visit::visit_item_trait(v, node));
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !is_test_only(&node.attrs) {
            self.in_fn(node.sig.ident.to_string(), |v| visit::visit_item_fn(v, node));
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !is_test_only(&node.attrs) {
            let function = self.method(&node.sig.ident);
            self.in_fn(function, |v| visit::visit_impl_item_fn(v, node));
        }
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if !is_test_only(&node.attrs) {
            let function = self.method(&node.sig.ident);
            self.in_fn(function, |v| visit::visit_trait_item_fn(v, node));
        }
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.record_use(&node.tree, false);
        visit::visit_item_use(self, node);
    }

    /// An import under its own name is not a site; each use of that name is.
    fn visit_use_name(&mut self, _node: &'ast syn::UseName) {}

    fn visit_ident(&mut self, node: &'ast Ident) {
        self.record_ident(node);
    }

    fn visit_qself(&mut self, node: &'ast syn::QSelf) {
        visit::visit_qself(self, node);
        if let syn::Type::Path(ty) = node.ty.as_ref() {
            if ty.path.segments.last().is_some_and(|s| s.ident.unraw() == DUTY_ENUM) {
                self.qself_position = Some(node.position);
            }
        }
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if let Some(position) = self.qself_position.take() {
            if let Some(segment) = node.segments.iter().nth(position) {
                self.record(segment.ident.unraw().to_string());
            }
        }
        let segments: Vec<&syn::PathSegment> = node.segments.iter().collect();
        for pair in segments.windows(2) {
            if pair[0].ident.unraw() == DUTY_ENUM {
                self.record(pair[1].ident.unraw().to_string());
            }
        }
        visit::visit_path(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.record_tokens(&TokenBuffer::new2(node.tokens.clone()));
        visit::visit_macro(self, node);
    }

    fn visit_meta_list(&mut self, node: &'ast syn::MetaList) {
        self.record_tokens(&TokenBuffer::new2(node.tokens.clone()));
        visit::visit_meta_list(self, node);
    }
}

/// Production sites of one source file.
fn scan_source(src: &str) -> FileScan {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("parse: {e}"));
    let mut visitor = DutyVisitor::default();
    visitor.visit_file(&file);
    visitor.scan
}

/// Production `SigningDuty` variant sites of one source file, by enclosing fn.
fn duty_map_of(src: &str) -> DutyMap {
    scan_source(src).duties
}

/// Every fn, in any file, that names `VoluntaryExit` but is not `sign_voluntary_exit`.
fn voluntary_exit_violations(files: &BTreeMap<String, FileScan>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for (file, scan) in files {
        let variant_sites =
            scan.duties.iter().filter(|(_, duties)| duties.contains(EXIT)).map(|(f, _)| f);
        for function in variant_sites.chain(&scan.exit_idents) {
            let name = function.rsplit("::").next().unwrap_or(function);
            if name != EXIT_FN {
                out.insert(format!("{file}: {function}"));
            }
        }
    }
    out.into_iter().collect()
}

fn signer_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../signer/src")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Duty map of every `.rs` file under `root`, keyed by `/`-separated relative path.
fn scan_tree(root: &Path) -> BTreeMap<String, FileScan> {
    let mut paths = Vec::new();
    collect_rs(root, &mut paths);
    paths
        .into_iter()
        .map(|path| {
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let relative = path.strip_prefix(root).expect("under root");
            let key =
                relative.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>();
            (key.join("/"), scan_source(&src))
        })
        .collect()
}

fn files_of(sources: &[(&str, &str)]) -> BTreeMap<String, FileScan> {
    sources.iter().map(|(file, src)| ((*file).to_string(), scan_source(src))).collect()
}

fn expect_duties(owner: &str, pairs: &[(&str, &str)]) -> DutyMap {
    let mut map = DutyMap::new();
    for (function, duty) in pairs {
        map.entry(format!("{owner}::{function}")).or_default().insert((*duty).to_string());
    }
    map
}

fn map_of(pairs: &[(&str, &[&str])]) -> DutyMap {
    pairs
        .iter()
        .map(|(function, duties)| {
            ((*function).to_string(), duties.iter().map(|d| (*d).to_string()).collect())
        })
        .collect()
}

#[test]
fn test_only_sign_voluntary_exit_names_the_voluntary_exit_duty() {
    let files = scan_tree(&signer_src());
    for required in ["lib.rs", "gate.rs", "core.rs"] {
        assert!(files.contains_key(required), "scan must read {required}: {:?}", files.keys());
    }
    assert!(
        files.keys().any(|file| file.contains('/')),
        "scan must recurse into subdirectories: {:?}",
        files.keys()
    );

    let signer_expected = expect_duties(
        "SignerService",
        &[
            ("sign_attestation", "Attestation"),
            ("sign_block", "Block"),
            ("sign_block_header", "Block"),
            ("sign_randao_reveal", "RandaoReveal"),
            ("sign_sync_committee_message", "SyncCommitteeMessage"),
            ("sign_payload_attestation", "PayloadAttestation"),
            ("sign_proposer_preferences", "ProposerPreferences"),
            ("sign_builder_request_auth", "BuilderRequestAuth"),
            ("sign_execution_payload_envelope_root", "ExecutionPayloadEnvelope"),
            ("sign_selection_proof", "SelectionProof"),
            ("sign_aggregate_and_proof", "AggregateAndProof"),
            ("sign_aggregate_and_proof_root", "AggregateAndProofRoot"),
            ("sign_electra_aggregate_and_proof", "ElectraAggregateAndProof"),
            ("sign_voluntary_exit", "VoluntaryExit"),
            ("sign_builder_registration", "BuilderRegistration"),
            ("sign_sync_committee_selection_proof", "SyncCommitteeSelectionProof"),
            ("sign_contribution_and_proof", "ContributionAndProof"),
        ],
    );
    assert_eq!(
        files["lib.rs"].duties, signer_expected,
        "SignerService method-to-duty map (lib.rs)"
    );

    let gate_expected = expect_duties(
        "SigningGate",
        &[
            ("sign_block", "Block"),
            ("sign_attestation", "Attestation"),
            ("sign_sync_committee_message", "SyncCommitteeMessage"),
            ("sign_aggregate_and_proof", "AggregateAndProof"),
            ("sign_payload_attestation", "PayloadAttestation"),
            ("sign_proposer_preferences", "ProposerPreferences"),
            ("sign_contribution_and_proof", "ContributionAndProof"),
            ("sign_selection_proof", "SelectionProof"),
            ("sign_sync_committee_selection_proof", "SyncCommitteeSelectionProof"),
            ("sign_randao_reveal", "RandaoReveal"),
            ("sign_voluntary_exit", "VoluntaryExit"),
            ("sign_builder_registration", "BuilderRegistration"),
            ("sign_builder_request_auth", "BuilderRequestAuth"),
            ("sign_execution_payload_envelope", "ExecutionPayloadEnvelope"),
        ],
    );
    assert_eq!(files["gate.rs"].duties, gate_expected, "SigningGate method-to-duty map (gate.rs)");

    assert_eq!(
        voluntary_exit_violations(&files),
        Vec::<String>::new(),
        "only sign_voluntary_exit may name SigningDuty::VoluntaryExit"
    );
    let exit_sites: Vec<String> = files
        .iter()
        .flat_map(|(file, scan)| {
            scan.duties
                .iter()
                .filter(|(_, duties)| duties.contains(EXIT))
                .map(move |(function, _)| format!("{file}: {function}"))
        })
        .collect();
    assert_eq!(
        exit_sites,
        ["gate.rs: SigningGate::sign_voluntary_exit", "lib.rs: SignerService::sign_voluntary_exit"],
        "exactly one production fn per signer surface names VoluntaryExit"
    );
    let ident_sites: Vec<String> = files
        .iter()
        .flat_map(|(file, scan)| scan.exit_idents.iter().map(move |f| format!("{file}: {f}")))
        .collect();
    assert_eq!(
        ident_sites,
        [
            "gate.rs: SigningGate::sign_voluntary_exit",
            "lib.rs: SignerService::sign_voluntary_exit",
            "test_utils.rs: StubValidatorSigner::sign_voluntary_exit",
            "traits.rs: ValidatorSigner::sign_voluntary_exit",
        ],
        "every VoluntaryExit ident sits in one of these fns"
    );
}

#[test]
fn fixture_pub_crate_multiline_fn_is_attributed() {
    let src = "fn sign_block() { SigningDuty::Block } pub(crate) fn sneaky(\n) -> SigningDuty { SigningDuty::VoluntaryExit }";
    assert_eq!(
        duty_map_of(src),
        map_of(&[("sign_block", &["Block"]), ("sneaky", &["VoluntaryExit"])])
    );
    assert_eq!(voluntary_exit_violations(&files_of(&[("lib.rs", src)])), ["lib.rs: sneaky"]);
}

#[test]
fn fixture_const_and_unsafe_fns_are_attributed() {
    let src = r#"
fn sign_block() { let _ = SigningDuty::Block; }
const fn exit_duty() -> SigningDuty { SigningDuty::VoluntaryExit }
unsafe fn raw_exit() { let _ = doppelganger::SigningDuty::VoluntaryExit; }
pub(crate) async unsafe fn wrapped<T>(
    _value: T,
) where
    T: Send,
{
    let _ = SigningDuty::RandaoReveal;
}
impl SigningGate {
    pub(super) const unsafe fn hidden(&self) -> SigningDuty { SigningDuty::VoluntaryExit }
}
const EXIT: SigningDuty = SigningDuty::VoluntaryExit;
"#;
    assert_eq!(
        duty_map_of(src),
        map_of(&[
            ("<outside fn>", &["VoluntaryExit"]),
            ("SigningGate::hidden", &["VoluntaryExit"]),
            ("exit_duty", &["VoluntaryExit"]),
            ("raw_exit", &["VoluntaryExit"]),
            ("sign_block", &["Block"]),
            ("wrapped", &["RandaoReveal"]),
        ])
    );
    assert_eq!(
        voluntary_exit_violations(&files_of(&[("gate.rs", src)])),
        [
            "gate.rs: <outside fn>",
            "gate.rs: SigningGate::hidden",
            "gate.rs: exit_duty",
            "gate.rs: raw_exit",
        ]
    );
}

#[test]
fn fixture_other_file_naming_voluntary_exit_is_reported() {
    let lib = r#"
impl ValidatorSigner for SignerService {
    async fn sign_voluntary_exit(&self) { self.admit(SigningDuty::VoluntaryExit).await }
}
"#;
    let core = r#"
impl SlashableKind {
    fn signing_duty(self) -> doppelganger::SigningDuty {
        match self {
            Self::Block { .. } => doppelganger::SigningDuty::Block,
            Self::Attestation { .. } => doppelganger::SigningDuty::VoluntaryExit,
        }
    }
}
"#;
    let files = files_of(&[("lib.rs", lib), ("service_util/core.rs", core)]);
    assert_eq!(
        files["service_util/core.rs"].duties,
        map_of(&[("SlashableKind::signing_duty", &["Block", "VoluntaryExit"])])
    );
    assert_eq!(
        voluntary_exit_violations(&files),
        ["service_util/core.rs: SlashableKind::signing_duty"]
    );
}

#[test]
fn fixture_test_module_is_ignored() {
    let src = r#"
#[cfg(test)]
mod tests {
    fn helper() -> SigningDuty { SigningDuty::VoluntaryExit }

    #[test]
    fn exit_is_allowed() { assert!(allowed(SigningDuty::VoluntaryExit)); }
}

#[test]
fn top_level_test() { let _ = SigningDuty::VoluntaryExit; }

#[tokio::test(flavor = "multi_thread")]
async fn top_level_async_test() { let _ = SigningDuty::VoluntaryExit; }

#[cfg(any(test, feature = "test-utils"))]
fn test_utils_helper() -> SigningDuty { SigningDuty::VoluntaryExit }
"#;
    assert_eq!(duty_map_of(src), map_of(&[("test_utils_helper", &["VoluntaryExit"])]));
}

#[test]
fn fixture_macro_and_trait_default_bodies_are_attributed() {
    let src = r#"
fn sign_randao_reveal(duty: SigningDuty) -> bool {
    matches!(duty, doppelganger::SigningDuty::VoluntaryExit)
}

#[tracing::instrument(fields(duty = ?SigningDuty::Block))]
fn traced() {}

fn logs() { warn!("SigningDuty::VoluntaryExit is only text here"); }

trait Sneaky {
    fn sign_exit(&self) -> SigningDuty { SigningDuty::VoluntaryExit }
}
"#;
    assert_eq!(
        duty_map_of(src),
        map_of(&[
            ("Sneaky::sign_exit", &["VoluntaryExit"]),
            ("sign_randao_reveal", &["VoluntaryExit"]),
            ("traced", &["Block"]),
        ])
    );
}

#[test]
fn fixture_tool_attribute_ending_in_test_is_scanned() {
    let src = r#"
#[rustfmt::test]
#[allow(dead_code)]
fn sneaky() -> SigningDuty { SigningDuty::VoluntaryExit }

#[test]
fn real_test() { let _ = SigningDuty::VoluntaryExit; }
"#;
    assert_eq!(duty_map_of(src), map_of(&[("sneaky", &["VoluntaryExit"])]));
    assert_eq!(voluntary_exit_violations(&files_of(&[("core.rs", src)])), ["core.rs: sneaky"]);
}

#[test]
fn fixture_raw_and_type_relative_paths_are_reported() {
    let src = r#"
pub(crate) const fn raw() -> SigningDuty { doppelganger::SigningDuty::r#VoluntaryExit }
pub(crate) const fn type_relative() -> SigningDuty { <doppelganger::SigningDuty>::VoluntaryExit }
fn in_pattern(duty: SigningDuty) -> bool {
    if let <SigningDuty>::VoluntaryExit = duty { true } else { false }
}
fn in_macro(duty: SigningDuty) -> bool {
    matches!(duty, <SigningDuty>::VoluntaryExit | r#SigningDuty::r#Block)
}
"#;
    assert_eq!(
        duty_map_of(src),
        map_of(&[
            ("in_macro", &["Block", "VoluntaryExit"]),
            ("in_pattern", &["VoluntaryExit"]),
            ("raw", &["VoluntaryExit"]),
            ("type_relative", &["VoluntaryExit"]),
        ])
    );
    assert_eq!(
        voluntary_exit_violations(&files_of(&[("service_util/sneaky.rs", src)])),
        [
            "service_util/sneaky.rs: in_macro",
            "service_util/sneaky.rs: in_pattern",
            "service_util/sneaky.rs: raw",
            "service_util/sneaky.rs: type_relative",
        ]
    );
}

#[test]
fn fixture_voluntary_exit_ident_outside_sign_voluntary_exit_is_reported() {
    let src = r#"
use doppelganger::SigningDuty as Duty;
use eth_types::VoluntaryExit;

const ALIASED: Duty = Duty::VoluntaryExit;
fn aliased() -> Duty { Duty::VoluntaryExit }
fn aliased_in_macro(duty: Duty) -> bool { matches!(duty, Duty::VoluntaryExit) }
fn sign_voluntary_exit(_exit: &VoluntaryExit) -> Duty { Duty::VoluntaryExit }
"#;
    assert_eq!(duty_map_of(src), DutyMap::new());
    assert_eq!(
        voluntary_exit_violations(&files_of(&[("service_util/alias.rs", src)])),
        [
            "service_util/alias.rs: <outside fn>",
            "service_util/alias.rs: aliased",
            "service_util/alias.rs: aliased_in_macro",
        ]
    );
}

#[test]
fn fixture_variant_imports_are_attributed() {
    let src = r#"
use doppelganger::SigningDuty::VoluntaryExit as TopLevelExit;

fn sign_randao_reveal() -> SigningDuty {
    use doppelganger::SigningDuty::VoluntaryExit as Ve;
    let _ = Ve;
    SigningDuty::RandaoReveal
}
fn grouped() { use doppelganger::{SigningDuty::{Block, VoluntaryExit as Exit}, SigningEnablement}; }
fn globbed() { use doppelganger::SigningDuty::*; }
"#;
    assert_eq!(
        duty_map_of(src),
        map_of(&[
            ("<outside fn>", &["VoluntaryExit"]),
            ("globbed", &["*"]),
            ("grouped", &["Block", "VoluntaryExit"]),
            ("sign_randao_reveal", &["RandaoReveal", "VoluntaryExit"]),
        ])
    );
    assert_eq!(
        voluntary_exit_violations(&files_of(&[("core.rs", src)])),
        ["core.rs: <outside fn>", "core.rs: grouped", "core.rs: sign_randao_reveal"]
    );
}

#[test]
fn fixture_second_exit_fn_on_a_surface_type_is_reported() {
    let lib = r#"
impl ValidatorSigner for SignerService {
    async fn sign_voluntary_exit(&self) { self.admit(SigningDuty::VoluntaryExit).await }
}
trait ExitAlt { fn sign_voluntary_exit(&self) -> SigningDuty; }
impl ExitAlt for SignerService {
    fn sign_voluntary_exit(&self) -> SigningDuty { SigningDuty::VoluntaryExit }
}
"#;
    let gate = r#"
impl SigningGate {
    pub async fn sign_voluntary_exit(&self) { self.sign(SigningDuty::VoluntaryExit).await }
}
mod alt {
    struct SigningGate;
    impl SigningGate {
        fn sign_voluntary_exit(&self) -> SigningDuty { SigningDuty::VoluntaryExit }
    }
}
"#;
    assert_eq!(
        duty_map_of(lib),
        map_of(&[
            ("SignerService::sign_voluntary_exit", &["VoluntaryExit"]),
            ("SignerService::sign_voluntary_exit#2", &["VoluntaryExit"]),
        ])
    );
    assert_eq!(
        voluntary_exit_violations(&files_of(&[("lib.rs", lib), ("gate.rs", gate)])),
        [
            "gate.rs: SigningGate::sign_voluntary_exit#2",
            "lib.rs: SignerService::sign_voluntary_exit#2"
        ]
    );
}
