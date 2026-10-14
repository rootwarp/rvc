//! Issue 6.14 deadline harness: Gloas attestation due-ms via the production
//! resolver (`DeadlineSchedule::for_fork` + `due_ms`), never a config-key read.
//!
//! ```text
//! cargo bench -p rvc --bench deadline_rebenchmark -- --output PATH.json
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use eth_types::{ForkName, ForkSchedule, Slot};
use rvc::config::{Config, ServiceBuilder};
use rvc::orchestrator::OrchestratorConfig;
use timing::{SLOTS_PER_EPOCH, SLOT_DURATION_MS};

fn gloas_epoch_fork_schedule(gloas_epoch: u64) -> Arc<ForkSchedule> {
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.gloas_fork_epoch = gloas_epoch;
    Arc::new(schedule)
}

/// Production path: config → `DeadlineSchedule` the coordinator holds →
/// `from_epoch` on a Gloas-epoch slot → `for_fork` → `due_ms`.
fn resolve_attestation_deadline(
    config: &OrchestratorConfig,
    slot: Slot,
    slot_duration_ms: u64,
) -> (ForkName, u64) {
    let epoch = slot / SLOTS_PER_EPOCH;
    let fork = ForkName::from_epoch(epoch, &config.fork_schedule);
    (fork, config.attestation_deadline_ms(slot, slot_duration_ms))
}

fn output_path_from_cli() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(path) = arg.strip_prefix("--output=") {
            return Some(PathBuf::from(path));
        }
        if arg == "--output" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

fn emit(json: &str) {
    print!("{json}");
    let _ = std::io::stdout().flush();
    if let Some(path) = output_path_from_cli() {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| panic!("create parent dir {}: {e}", parent.display()));
            }
        }
        std::fs::write(&path, json.as_bytes())
            .unwrap_or_else(|e| panic!("write summary {}: {e}", path.display()));
    }
}

fn main() {
    // Epoch 1 is Gloas; slot 0 stays pre-Gloas so inherit-intentionally is
    // exercised only through `for_fork`, not a hardcoded Gloas bps set.
    let gloas_epoch = 1;
    let fork_schedule = gloas_epoch_fork_schedule(gloas_epoch);
    let slot = gloas_epoch * SLOTS_PER_EPOCH;
    let config = Config::default();
    let slot_duration_ms = config.network.slot_duration_ms();
    assert_eq!(slot_duration_ms, SLOT_DURATION_MS);

    let orch = ServiceBuilder::new(config).build_orchestrator_config([0u8; 32], fork_schedule);
    let (fork, deadline_ms) = resolve_attestation_deadline(&orch, slot, slot_duration_ms);
    assert!(fork >= ForkName::Gloas, "6.14 must resolve a Gloas-epoch slot; got {}", fork.as_ref());

    let json = format!(
        "{{\n  \"issue\": \"6.14\",\n  \"resolver\": \"OrchestratorConfig::attestation_deadline_ms\",\n  \
         \"slot\": {slot},\n  \"epoch\": {epoch},\n  \"fork\": \"{fork}\",\n  \
         \"slot_duration_ms\": {slot_duration_ms},\n  \"attestation_deadline_ms\": {deadline_ms}\n}}\n",
        epoch = slot / SLOTS_PER_EPOCH,
        fork = fork.as_ref(),
    );
    emit(&json);
}
