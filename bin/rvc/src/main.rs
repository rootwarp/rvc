//! rvc - Rust Validator Client
//!
//! Main entry point for the validator client binary: CLI parse, logging init,
//! and one call into [`rvc::bootstrap::run`].
//!
//! This `main` is intentionally **synchronous** so named startup exit codes
//! (NFR-3) can use `process::exit` only after the Tokio runtime has been
//! dropped — never mid-async (ARCH-2i).

mod cli;
mod commands;
mod logging;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(cli::dispatch(cli::Cli::parse()));

    // Runtime dropped. Named startup codes (NFR-3) map here — never mid-async (ARCH-2i).
    if let Err(ref e) = result {
        if let Some(be) = e.downcast_ref::<rvc::bootstrap::BootstrapError>() {
            let code = be.exit_code();
            if be.is_keystore_locked() || code != 1 {
                std::process::exit(code);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    /// RF5-10: keep the binary entry point under the line-count budget.
    #[test]
    fn test_main_rs_under_600_lines() {
        let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let lines = src.lines().count();
        assert!(
            lines < 600,
            "bin/rvc/src/main.rs must stay under 600 lines after RF5-10 (found {lines})"
        );
    }
}
