//! The image and compose health checks probe a route that the server serves.
//!
//! The rvc `HEALTHCHECK` ran `curl -f http://localhost:8080/healthz`. rvc does
//! not serve `/healthz`, so the probe got a 404 and the container was always
//! unhealthy. The probes now run the `health` subcommand of each binary, and
//! the runtime images do not install `curl`.

use rvc_architecture_tests::workspace_root;

struct Probe {
    stage: &'static str,
    binary: &'static str,
    url: &'static str,
    path: &'static str,
    /// Source file that serves `path`, and the text that registers it there.
    route_source: &'static str,
    route_text: &'static str,
    /// Source file of the `health` subcommand default, and its definition.
    default_source: &'static str,
    default_text: &'static str,
}

/// Grace time before a failed probe counts. Both binaries serve the probed
/// route only after the keystores are decrypted (rvc also connects to the
/// beacon node first), and that can take minutes.
const START_PERIOD: &str = "300s";

const PROBES: [Probe; 2] = [
    Probe {
        stage: "rvc",
        binary: "rvc",
        url: "http://127.0.0.1:8080/livez",
        path: "/livez",
        route_source: "crates/metrics/src/server.rs",
        route_text: ".route(\"/livez\", get(livez_handler))",
        default_source: "bin/rvc/src/commands/health.rs",
        default_text: "pub const DEFAULT_URL: &str = \"http://127.0.0.1:8080/livez\";",
    },
    Probe {
        stage: "rvc-signer",
        binary: "rvc-signer",
        url: "http://127.0.0.1:9101/metrics",
        path: "/metrics",
        route_source: "crates/signer-server/src/metrics.rs",
        route_text: "(\"GET\", \"/metrics\") => MetricsRoute::Metrics,",
        default_source: "bin/rvc-signer/src/main.rs",
        default_text: "const DEFAULT_HEALTH_URL: &str = \"http://127.0.0.1:9101/metrics\";",
    },
];

const RUNTIME_STAGES: [&str; 3] = ["rvc", "rvc-signer", "rvc-keygen"];

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Dockerfile instructions with `\` continuations joined, grouped by stage name.
fn dockerfile_stages(text: &str) -> Vec<(String, Vec<String>)> {
    let mut stages: Vec<(String, Vec<String>)> = Vec::new();
    let mut pending = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if pending.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        if let Some(head) = trimmed.strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
            continue;
        }
        pending.push_str(trimmed);
        let instruction = std::mem::take(&mut pending);
        let words: Vec<&str> = instruction.split_whitespace().collect();
        if words.first().is_some_and(|w| w.eq_ignore_ascii_case("FROM")) {
            let name = match words.as_slice() {
                [_, _, as_kw, name] if as_kw.eq_ignore_ascii_case("AS") => (*name).to_string(),
                _ => String::new(),
            };
            stages.push((name, Vec::new()));
        } else if let Some((_, instructions)) = stages.last_mut() {
            instructions.push(instruction);
        }
    }
    stages
}

fn stage<'a>(stages: &'a [(String, Vec<String>)], name: &str) -> &'a [String] {
    stages
        .iter()
        .find(|(stage, _)| stage == name)
        .map(|(_, instructions)| instructions.as_slice())
        .unwrap_or_else(|| panic!("Dockerfile has no stage `{name}`"))
}

fn exec_form(json: &str, context: &str) -> Vec<String> {
    serde_json::from_str(json.trim())
        .unwrap_or_else(|e| panic!("{context}: not an exec-form JSON array ({e}): {json}"))
}

/// The options and the exec-form command of the one HEALTHCHECK in a stage.
fn healthcheck(instructions: &[String], stage_name: &str) -> (Vec<String>, Vec<String>) {
    let checks: Vec<&String> =
        instructions.iter().filter(|i| i.starts_with("HEALTHCHECK ")).collect();
    assert_eq!(checks.len(), 1, "stage `{stage_name}` must have one HEALTHCHECK: {checks:?}");
    let (options, cmd) = checks[0]
        .split_once(" CMD ")
        .unwrap_or_else(|| panic!("stage `{stage_name}` HEALTHCHECK has no CMD: {}", checks[0]));
    let options = options.split_whitespace().skip(1).map(String::from).collect();
    (options, exec_form(cmd, stage_name))
}

fn healthcheck_argv(instructions: &[String], stage_name: &str) -> Vec<String> {
    healthcheck(instructions, stage_name).1
}

/// The value of `key:` inside one top-level service of `docker-compose.yml`.
fn compose_service_value(text: &str, service: &str, key: &str) -> String {
    let header = format!("  {service}:");
    let prefix = format!("{key}:");
    let mut in_service = false;
    for line in text.lines() {
        if line.starts_with("  ") && !line.starts_with("   ") && !line.trim().is_empty() {
            in_service = line.trim_end() == header;
            continue;
        }
        if in_service {
            if let Some(value) = line.trim().strip_prefix(&prefix) {
                return value.trim().to_string();
            }
        }
        if !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
            in_service = false;
        }
    }
    panic!("docker-compose.yml service `{service}` has no `{key}`")
}

/// The `test:` array of one top-level service in `docker-compose.yml`.
fn compose_healthcheck_argv(text: &str, service: &str) -> Vec<String> {
    exec_form(&compose_service_value(text, service, "test"), service)
}

fn expected_argv(probe: &Probe) -> Vec<String> {
    [probe.binary, "health", "--url", probe.url].map(String::from).to_vec()
}

#[test]
fn test_image_healthchecks_run_the_health_subcommand_on_a_served_route() {
    let stages = dockerfile_stages(&read("Dockerfile"));
    for probe in &PROBES {
        assert!(probe.url.ends_with(probe.path), "{} url/path mismatch", probe.stage);
        assert_eq!(
            healthcheck_argv(stage(&stages, probe.stage), probe.stage),
            expected_argv(probe),
            "Dockerfile stage `{}` HEALTHCHECK",
            probe.stage
        );
        assert!(
            read(probe.route_source).contains(probe.route_text),
            "{} must serve {} (`{}`)",
            probe.route_source,
            probe.path,
            probe.route_text
        );
        assert!(
            read(probe.default_source).contains(probe.default_text),
            "the `{} health` default must stay {}",
            probe.binary,
            probe.url
        );
    }
}

#[test]
fn test_compose_healthchecks_match_the_image_healthchecks() {
    let compose = read("docker-compose.yml");
    for probe in &PROBES {
        let mut expected = vec!["CMD".to_string()];
        expected.extend(expected_argv(probe));
        assert_eq!(
            compose_healthcheck_argv(&compose, probe.stage),
            expected,
            "docker-compose.yml service `{}` healthcheck",
            probe.stage
        );
    }
}

#[test]
fn test_healthchecks_give_a_slow_start_enough_grace() {
    let stages = dockerfile_stages(&read("Dockerfile"));
    let compose = read("docker-compose.yml");
    for probe in &PROBES {
        let (options, _) = healthcheck(stage(&stages, probe.stage), probe.stage);
        let expected = format!("--start-period={START_PERIOD}");
        assert!(
            options.contains(&expected),
            "Dockerfile stage `{}` HEALTHCHECK needs {expected}: {options:?}",
            probe.stage
        );
        assert_eq!(
            compose_service_value(&compose, probe.stage, "start_period"),
            START_PERIOD,
            "docker-compose.yml service `{}` start_period",
            probe.stage
        );
    }
}

#[test]
fn test_runtime_images_do_not_install_curl() {
    let stages = dockerfile_stages(&read("Dockerfile"));
    for name in RUNTIME_STAGES {
        let hits: Vec<&String> = stage(&stages, name)
            .iter()
            .filter(|i| i.split_whitespace().any(|w| w == "curl" || w.starts_with("libcurl")))
            .collect();
        assert!(hits.is_empty(), "runtime stage `{name}` must not use curl: {hits:?}");
    }
}

#[test]
fn test_parsers_see_continuations_and_service_blocks() {
    let dockerfile = "FROM a AS one\nHEALTHCHECK --interval=1s \\\n    CMD [\"x\", \"health\"]\n\
                      FROM b AS two\nRUN apt-get install -y \\\n    curl \\\n    && true\n";
    let stages = dockerfile_stages(dockerfile);
    assert_eq!(healthcheck_argv(stage(&stages, "one"), "one"), ["x", "health"]);
    assert_eq!(healthcheck(stage(&stages, "one"), "one").0, ["--interval=1s"]);
    assert!(stage(&stages, "two")[0].split_whitespace().any(|w| w == "curl"));

    let compose = "services:\n  a:\n    healthcheck:\n      test: [\"CMD\", \"a\"]\n  \
                   b:\n    healthcheck:\n      test: [\"CMD\", \"b\"]\nvolumes:\n  c:\n";
    assert_eq!(compose_healthcheck_argv(compose, "a"), ["CMD", "a"]);
    assert_eq!(compose_healthcheck_argv(compose, "b"), ["CMD", "b"]);
}
