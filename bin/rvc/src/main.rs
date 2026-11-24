//! rvc - Rust Validator Client
//!
//! Main entry point for the validator client binary: CLI parse, logging init,
//! and one call into [`rvc::bootstrap::run`].
//!
//! This `main` is intentionally **synchronous** so named startup exit codes
//! (NFR-3) can use `process::exit` only after the Tokio runtime has been
//! shut down and dropped — never mid-async (ARCH-2i).
//! [`rvc::startup::block_on_then_shutdown`] bounds the wait for blocking work
//! that is still running by `rvc::startup::RUNTIME_SHUTDOWN_GRACE`.

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
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let result = rvc::startup::block_on_then_shutdown(runtime, cli::dispatch(cli::Cli::parse()));

    // The runtime is shut down (blocking work bounded by `RUNTIME_SHUTDOWN_GRACE`) and dropped.
    // Named startup codes (NFR-3) map here — never mid-async (ARCH-2i).
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

    /// W4-D3d1: exit 12 keeps its named code after the bounded runtime shutdown.
    #[test]
    fn doppelganger_detected_maps_to_exit_12() {
        use rvc::startup::EXIT_DOPPELGANGER_DETECTED;

        let err = anyhow::Error::from(BootstrapError::DoppelgangerDetected);
        assert_eq!(named_process_exit_code(&err), Some(EXIT_DOPPELGANGER_DETECTED));
        assert_eq!(EXIT_DOPPELGANGER_DETECTED, 12);
    }

    /// W4-D3d1: `main` shuts the runtime down through the bounded helper, so a
    /// blocking task that is still stuck cannot hold the named exit code.
    #[test]
    fn main_shuts_the_runtime_down_through_the_bounded_helper() {
        let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let production = src.split("#[cfg(test)]").next().unwrap_or_default();
        assert!(
            !production.contains(".block_on("),
            "main must not call .block_on( on a runtime whose drop waits for blocking work"
        );
        let file = syn::parse_file(src).expect("main.rs must be valid Rust.");
        let mut paths = PathNames::default();
        let production = file
            .items
            .iter()
            .filter(|item| !matches!(item, syn::Item::Mod(m) if m.ident == "tests"));
        production.for_each(|item| syn::visit::Visit::visit_item(&mut paths, item));
        let process_exits = paths.0.iter().filter(|path| path.ends_with("process::exit")).count();
        let main = file.items.iter().find_map(|item| match item {
            syn::Item::Fn(main) if main.sig.ident == "main" => Some(main),
            _ => None,
        });
        let stmts = &main.expect("main.rs must have fn main.").block.stmts;
        let find = |name: &str| -> Vec<usize> {
            let named = |stmt: &syn::Stmt| {
                let mut paths = PathNames::default();
                syn::visit::Visit::visit_stmt(&mut paths, stmt);
                paths.0.iter().any(|path| path.rsplit("::").next() == Some(name))
            };
            (0..stmts.len()).filter(|i| named(&stmts[*i])).collect()
        };
        let (helper, exits) = (find("block_on_then_shutdown"), find("exit"));
        assert!(
            helper.len() == 1 && exits.len() == 1 && process_exits == 1 && exits[0] > helper[0],
            "main must call rvc::startup::block_on_then_shutdown in one statement with no exit \
             in it, and the one process::exit of the file must be in a later statement of main \
             (helper statements {helper:?}, exit statements {exits:?}, process::exit calls \
             {process_exits})."
        );
    }

    /// Each path, with its segments joined by `::`.
    #[derive(Default)]
    struct PathNames(Vec<String>);

    impl<'ast> syn::visit::Visit<'ast> for PathNames {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
            self.0.push(names.join("::"));
            syn::visit::visit_path(self, path);
        }
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
