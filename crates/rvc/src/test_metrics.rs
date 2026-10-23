//! Per-thread copies of samples that are also on process-global Prometheus series.
//!
//! `cargo test` runs every test in one process. A `current_thread` test reads
//! its own deltas from these cells. The Prometheus series is still updated.

use std::cell::Cell;

thread_local! {
    static PARENT_FALLBACK: Cell<u64> = const { Cell::new(0) };
    static AGG_FAILED: Cell<u64> = const { Cell::new(0) };
    static BLOCK_START_COLD_N: Cell<u64> = const { Cell::new(0) };
    static BLOCK_START_COLD_SUM: Cell<f64> = const { Cell::new(0.0) };
    static PHASE_BLOCK_N: Cell<u64> = const { Cell::new(0) };
    static PHASE_BLOCK_SUM: Cell<f64> = const { Cell::new(0.0) };
    static IMPORT_DEFERRED_N: Cell<u64> = const { Cell::new(0) };
    static IMPORT_DEFERRED_SUM: Cell<f64> = const { Cell::new(0.0) };
}

fn add(cell: &Cell<u64>, by: u64) {
    cell.set(cell.get().saturating_add(by));
}

fn add_sum(cell: &Cell<f64>, sample: f64) {
    cell.set(cell.get() + sample);
}

pub fn add_parent_fallback() {
    PARENT_FALLBACK.with(|cell| add(cell, 1));
}

pub fn parent_fallback() -> u64 {
    PARENT_FALLBACK.with(Cell::get)
}

pub fn add_agg_failed(by: u64) {
    AGG_FAILED.with(|cell| add(cell, by));
}

pub fn agg_failed() -> u64 {
    AGG_FAILED.with(Cell::get)
}

pub fn add_block_start_cold(offset_ms: f64) {
    BLOCK_START_COLD_N.with(|cell| add(cell, 1));
    BLOCK_START_COLD_SUM.with(|cell| add_sum(cell, offset_ms));
}

pub fn block_start_cold() -> (u64, f64) {
    (BLOCK_START_COLD_N.with(Cell::get), BLOCK_START_COLD_SUM.with(Cell::get))
}

pub fn add_phase_block(offset_ms: f64) {
    PHASE_BLOCK_N.with(|cell| add(cell, 1));
    PHASE_BLOCK_SUM.with(|cell| add_sum(cell, offset_ms));
}

pub fn phase_block() -> (u64, f64) {
    (PHASE_BLOCK_N.with(Cell::get), PHASE_BLOCK_SUM.with(Cell::get))
}

pub fn add_import_deferred(wait_ms: f64) {
    IMPORT_DEFERRED_N.with(|cell| add(cell, 1));
    IMPORT_DEFERRED_SUM.with(|cell| add_sum(cell, wait_ms));
}

pub fn import_deferred() -> (u64, f64) {
    (IMPORT_DEFERRED_N.with(Cell::get), IMPORT_DEFERRED_SUM.with(Cell::get))
}
