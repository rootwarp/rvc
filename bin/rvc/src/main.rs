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

/// Named bootstrap exit status, applied only after the Tokio runtime has dropped.
///
/// `None` means the error is not a named code; `main` returns it through anyhow.
fn named_process_exit_code(err: &anyhow::Error) -> Option<i32> {
    let be = err.downcast_ref::<rvc::bootstrap::BootstrapError>()?;
    let code = be.exit_code();
    if be.is_keystore_locked() || code != 1 {
        Some(code)
    } else {
        None
    }
}

fn main() -> anyhow::Result<()> {
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(cli::dispatch(cli::Cli::parse()));

    // Runtime dropped. Named startup codes (NFR-3) map here — never mid-async (ARCH-2i).
    if let Err(ref e) = result {
        if let Some(code) = named_process_exit_code(e) {
            std::process::exit(code);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::named_process_exit_code;
    use rvc::bootstrap::BootstrapError;
    use rvc::startup::EXIT_CRITICAL_TASK_FAILED;

    /// RR1-06: a panicking registered task exits 16 after the runtime drops.
    #[test]
    fn critical_task_failed_maps_to_exit_16() {
        let err =
            anyhow::Error::from(BootstrapError::CriticalTaskFailed { task: "duty_orchestrator" });
        assert_eq!(named_process_exit_code(&err), Some(EXIT_CRITICAL_TASK_FAILED));
        assert_eq!(EXIT_CRITICAL_TASK_FAILED, 16);
    }

    /// RR1-08: a listener bind failure exits 15 after the runtime drops.
    #[test]
    fn listener_bind_maps_to_exit_15() {
        use std::net::SocketAddr;

        use rvc::startup::EXIT_LISTENER_BIND;

        let err = anyhow::Error::from(BootstrapError::ListenerBind {
            listener: "metrics",
            addr: "127.0.0.1:9".parse::<SocketAddr>().expect("addr"),
            source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"),
        });
        assert_eq!(named_process_exit_code(&err), Some(EXIT_LISTENER_BIND));
        assert_eq!(EXIT_LISTENER_BIND, 15);
    }

    /// Unnamed bootstrap failures stay on anyhow's default status.
    #[test]
    fn generic_bootstrap_error_is_not_a_named_exit() {
        let err = anyhow::Error::from(BootstrapError::InvalidConfig("x".into()));
        assert_eq!(named_process_exit_code(&err), None);
    }

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
