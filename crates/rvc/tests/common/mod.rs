//! Shared integration-test helpers for `crates/rvc/tests/`.
//!
//! Each top-level `tests/*.rs` file is a separate crate; common fixtures live
//! here so RF1-02 and RF1-08 share one pipeline harness.
//!
//! `dead_code` is allowed: each integration-test binary only exercises a
//! subset of the shared knobs/handles.

#![allow(dead_code)]

pub mod import_during_duties;
pub mod pipeline_fixture;
