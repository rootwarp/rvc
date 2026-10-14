#!/usr/bin/env bash
# trace-e2e.sh — part 1 (TRC-5a / #432) and part 2 (TRC-5b / #433).
#
# Part 1 stands up a MockBn-based fixture beacon node and runs bin/rvc until
# it reaches at least one attestation duty. Evidence is a `slot.process` span
# in the fmt log plus the duty-path line "Found attestation duties". Part 1
# does not start the signer or a collector. TRC-5c, TRC-5d, and TRC-5e are
# not started.
#
# Part 2 drives host bin/rvc and bin/rvc-signer against the Phase-1 compose
# stack (docker-compose.yml, profile tracing / Jaeger v2). The beacon is the
# part-1 fixture, on the host, so both binaries reach it and the published
# OTLP sink. This script assigns OTEL_TRACES_SAMPLER_ARG=1.0 (do not rely on
# the SDK default). It waits until one slot.process span has closed, waits a
# bounded flush while both processes are still alive, then SIGTERM. SIGKILL
# is not the success path. Jaeger traces are written for TRC-5c to:
#   target/trace-e2e/spans.json
# Override with TRACE_E2E_SPANS_FILE. This file is not the TRC-5c assert.
#
# Requires Docker and a repo checkout for part 1's default runtime. A local
# `target/{debug,release}/rvc` (or $RVC_BIN) is used when present; otherwise
# part 1 builds the `rvc` image from the repo Dockerfile. Part 2 needs host
# `rvc` and `rvc-signer` binaries (RVC_BIN / RVC_SIGNER_BIN or target/).
#
#   TRACE_E2E_RUNTIME=python   part 1: run the fixture server with host python3
#                              (same program Docker runs). Default is docker.
#   TRACE_E2E_GENESIS_DELAY    seconds from now until genesis (default 20)
#   TRACE_E2E_KEEP=1           keep the work directory after success
#   TRACE_E2E_OTLP_ENDPOINT    part 2 OTLP sink (default http://127.0.0.1:4318)
#   TRACE_E2E_FLUSH_WAIT       part 2 seconds both processes stay up after the
#                              slot span closes (default 8)
#   TRACE_E2E_SLOT_CLOSE_TIMEOUT
#                              part 2 override for the slot-close wait, seconds.
#                              Default is genesis delay + one epoch + 30s.
#   TRACE_E2E_TEARDOWN=sigkill part 2 diagnostic only. Always exits non-zero.
#
# shellcheck disable=SC2317
# fail() exits, and wait_until/trap invoke callbacks by name. Shellcheck
# reports those bodies as unreachable. They run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="${ROOT}/scripts/tests/fixtures"
FIXTURE_PY="${ROOT}/scripts/trace_e2e_fixture_bn.py"
GVR="0x1111111111111111111111111111111111111111111111111111111111111111"
FEE_RECIPIENT="0x1111111111111111111111111111111111111111"
IMAGE="${TRACE_E2E_PY_IMAGE:-python:3.12-alpine}"
RUNTIME="${TRACE_E2E_RUNTIME:-docker}"

part="1"
up_only=0
ok=0
workdir=""
bn_cid=""
bn_pid=""
bn_net=""
bn_alias="trace-e2e-bn"
rvc_pid=""
rvc_cid=""
rvc_log=""
signer_pid=""
signer_log=""
compose_started=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [--part 1|2] [--up-only]

Part 1 (default): start the fixture beacon node, run bin/rvc, and exit 0
when a slot.process span and an attestation duty-path log are both present.

Part 2: Jaeger from \`docker compose --profile tracing\`, host bin/rvc and
bin/rvc-signer, one closed slot, bounded flush, SIGTERM. Writes
target/trace-e2e/spans.json for TRC-5c.

  --part N     Part 1 or 2. Any other part exits 1 (part-not-in-scope).
  --up-only    Part 1 only: start the fixture, wait until ready, then exit.
  -h, --help   Show this help.

Every wait has a timeout and a named failure (trace-e2e: FAIL <name>).
EOF
}

fail() {
    local name="$1"
    shift
    echo "trace-e2e: FAIL ${name}: $*" >&2
    exit 1
}

dump_debug() {
    if [[ "${ok}" -eq 1 ]]; then
        return 0
    fi
    if [[ -n "${rvc_log}" && -f "${rvc_log}" ]]; then
        echo "----- rvc log (tail) -----" >&2
        tail -n 160 "${rvc_log}" >&2 || true
    fi
    if [[ -n "${signer_log}" && -f "${signer_log}" ]]; then
        echo "----- rvc-signer log (tail) -----" >&2
        tail -n 160 "${signer_log}" >&2 || true
    fi
    if [[ -n "${bn_cid}" ]]; then
        echo "----- fixture container log -----" >&2
        docker logs "${bn_cid}" >&2 || true
    fi
    if [[ -n "${workdir}" ]]; then
        echo "trace-e2e: logs kept at ${workdir}" >&2
    fi
}

# Bounded TERM, then KILL. Used only from the EXIT trap so a failed part-2
# run cannot leak host processes. The success path is stop_pid_clean, which
# never sends KILL.
terminate_host() {
    local pid="${1:-}"
    local deadline st
    if [[ -z "${pid}" ]]; then
        return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" >/dev/null 2>&1 || true
        return 0
    fi
    kill -TERM "${pid}" >/dev/null 2>&1 || true
    deadline=$((SECONDS + 5))
    while kill -0 "${pid}" 2>/dev/null; do
        st="$(ps -p "${pid}" -o stat= 2>/dev/null || true)"
        st="${st//[[:space:]]/}"
        case "${st}" in
            Z*) break ;;
        esac
        if (( SECONDS >= deadline )); then
            kill -KILL "${pid}" >/dev/null 2>&1 || true
            break
        fi
        sleep 0.2
    done
    wait "${pid}" >/dev/null 2>&1 || true
}

cleanup() {
    dump_debug
    if [[ "${compose_started}" -eq 1 ]]; then
        terminate_host "${rvc_pid}"
        terminate_host "${signer_pid}"
        terminate_host "${bn_pid}"
        rvc_pid=""
        signer_pid=""
        bn_pid=""
        # Profile is required: Jaeger is not in the default service set.
        timeout 60 docker compose --profile tracing down -v >/dev/null 2>&1 || true
        compose_started=0
    fi
    if [[ -n "${rvc_pid}" ]]; then
        kill "${rvc_pid}" >/dev/null 2>&1 || true
        wait "${rvc_pid}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${rvc_cid}" ]]; then
        docker rm -f "${rvc_cid}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${bn_pid}" ]]; then
        kill "${bn_pid}" >/dev/null 2>&1 || true
        wait "${bn_pid}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${bn_cid}" ]]; then
        docker rm -f "${bn_cid}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${bn_net}" ]]; then
        docker network rm "${bn_net}" >/dev/null 2>&1 || true
    fi
    if [[ "${ok}" -eq 1 && "${TRACE_E2E_KEEP:-0}" != "1" && -n "${workdir}" ]]; then
        rm -rf "${workdir}"
    fi
}
trap cleanup EXIT

wait_until() {
    local name="$1"
    local timeout_s="$2"
    shift 2
    local deadline=$((SECONDS + timeout_s))
    while (( SECONDS < deadline )); do
        if "$@"; then
            return 0
        fi
        sleep 0.2
    done
    fail "${name}" "timed out after ${timeout_s}s"
}

# Optional args are ports already chosen but not yet bound. /dev/tcp only sees
# listeners, so two calls in a row would otherwise return the same port.
pick_port() {
    local port used skip
    for ((port = 19000; port <= 19250; port++)); do
        skip=0
        for used in "$@"; do
            if [[ "${port}" == "${used}" ]]; then
                skip=1
                break
            fi
        done
        if [[ "${skip}" -eq 1 ]]; then
            continue
        fi
        if ! (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1; then
            printf '%s\n' "${port}"
            return 0
        fi
    done
    return 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --part)
            if [[ $# -lt 2 ]]; then
                fail usage "--part requires a value"
            fi
            part="$2"
            shift 2
            ;;
        --part=*)
            part="${1#--part=}"
            shift
            ;;
        --up-only)
            up_only=1
            shift
            ;;
        -h|--help)
            usage
            ok=1
            exit 0
            ;;
        *)
            fail usage "unknown argument: $1"
            ;;
    esac
done

# SIGTERM and wait. Still alive after the timeout is a failed run: this does
# not SIGKILL (that would drop BatchSpanProcessor's queue and look like success).
stop_pid_clean() {
    local name="$1"
    local pid="$2"
    local timeout_s="$3"
    local deadline st
    if [[ -z "${pid}" ]]; then
        return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" >/dev/null 2>&1 || true
        return 0
    fi
    kill -TERM "${pid}" >/dev/null 2>&1 || true
    deadline=$((SECONDS + timeout_s))
    while kill -0 "${pid}" 2>/dev/null; do
        st="$(ps -p "${pid}" -o stat= 2>/dev/null || true)"
        st="${st//[[:space:]]/}"
        case "${st}" in
            Z*)
                wait "${pid}" >/dev/null 2>&1 || true
                return 0
                ;;
        esac
        if (( SECONDS >= deadline )); then
            fail "${name}" \
                "pid ${pid} still alive ${timeout_s}s after SIGTERM; refusing SIGKILL as success"
        fi
        sleep 0.2
    done
    wait "${pid}" >/dev/null 2>&1 || true
}

resolve_host_bin() {
    local env_name="$1"
    local bin_name="$2"
    local override="${3:-}"
    local candidate=""
    if [[ -n "${override}" ]]; then
        if [[ ! -x "${override}" ]]; then
            fail "${bin_name}-bin" "${env_name} is not executable: ${override}"
        fi
        printf '%s\n' "${override}"
        return 0
    fi
    if [[ -x "${ROOT}/target/debug/${bin_name}" ]]; then
        candidate="${ROOT}/target/debug/${bin_name}"
    elif [[ -x "${ROOT}/target/release/${bin_name}" ]]; then
        candidate="${ROOT}/target/release/${bin_name}"
    else
        fail "${bin_name}-bin" \
            "no ${bin_name} binary (build target/debug/${bin_name} or set ${env_name})"
    fi
    printf '%s\n' "${candidate}"
}

# Part 2. Exits. Does not return.
run_part2() {
    local spans_file otlp_endpoint flush_wait teardown spe delay now genesis_time
    local bn_port signer_port signer_metrics rvc_metrics pubkey signer_pw
    local evidence_timeout slot_close_margin shutdown_timeout

    if [[ "${up_only}" -eq 1 ]]; then
        fail usage "--up-only applies to part 1 only"
    fi

    teardown="${TRACE_E2E_TEARDOWN:-term}"
    case "${teardown}" in
        term|sigkill) ;;
        *) fail usage "TRACE_E2E_TEARDOWN must be term or sigkill (got ${teardown})" ;;
    esac

    flush_wait="${TRACE_E2E_FLUSH_WAIT:-8}"
    case "${flush_wait}" in
        ''|*[!0-9]*) fail usage "TRACE_E2E_FLUSH_WAIT must be a non-negative integer" ;;
    esac

    if ! command -v python3 >/dev/null 2>&1; then
        fail python-missing "python3 is required for part 2 (fixture beacon node)"
    fi
    if ! command -v curl >/dev/null 2>&1; then
        fail curl-missing "curl is required for part 2"
    fi
    if ! command -v docker >/dev/null 2>&1; then
        fail docker-missing "docker is required for part 2 (compose tracing profile)"
    fi
    if ! docker compose version >/dev/null 2>&1; then
        fail docker-compose-missing "docker compose is required for part 2"
    fi

    shopt -s nullglob
    fixture_files=("${FIXTURE_DIR}"/trace_e2e_bn__*.json)
    shopt -u nullglob
    if ((${#fixture_files[@]} == 0)); then
        fail fixture-glob "no fixtures matched ${FIXTURE_DIR}/trace_e2e_bn__*.json"
    fi
    if [[ ! -f "${FIXTURE_DIR}/trace_e2e_validator_keystore.json" ]]; then
        fail fixture-keystore "missing trace_e2e_validator_keystore.json"
    fi
    if [[ ! -f "${FIXTURE_DIR}/trace_e2e_validator_pubkey.txt" ]]; then
        fail fixture-pubkey "missing trace_e2e_validator_pubkey.txt"
    fi
    if [[ ! -f "${FIXTURE_DIR}/trace_e2e_validator_password.txt" ]]; then
        fail fixture-password "missing trace_e2e_validator_password.txt"
    fi
    pubkey="$(tr -d '[:space:]' < "${FIXTURE_DIR}/trace_e2e_validator_pubkey.txt")"
    if [[ -z "${pubkey}" ]]; then
        fail fixture-pubkey "pubkey file is empty"
    fi
    signer_pw="$(sed -n 's/^\*=//p' "${FIXTURE_DIR}/trace_e2e_validator_password.txt" | head -n 1 | tr -d '\r' || true)"
    if [[ -z "${signer_pw}" ]]; then
        fail fixture-password "password file has no *= entry for the signer"
    fi

    spe="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["data"]["SECONDS_PER_SLOT"])' \
        "${FIXTURE_DIR}/trace_e2e_bn__spec.json")" || fail fixture-spec "cannot read SECONDS_PER_SLOT"
    case "${spe}" in
        ''|*[!0-9]*|0) fail fixture-spec "SECONDS_PER_SLOT must be a positive integer (got ${spe:-empty})" ;;
    esac

    delay="${TRACE_E2E_GENESIS_DELAY:-20}"
    case "${delay}" in
        ''|*[!0-9]*) fail usage "TRACE_E2E_GENESIS_DELAY must be a non-negative integer" ;;
    esac
    now="$(date +%s)"
    genesis_time="$((now + delay))"
    slot_close_margin=1
    shutdown_timeout=20
    evidence_timeout="$((delay + spe * 32 + 30))"
    if [[ -n "${TRACE_E2E_SLOT_CLOSE_TIMEOUT:-}" ]]; then
        evidence_timeout="${TRACE_E2E_SLOT_CLOSE_TIMEOUT}"
        case "${evidence_timeout}" in
            ''|*[!0-9]*|0)
                fail usage "TRACE_E2E_SLOT_CLOSE_TIMEOUT must be a positive integer"
                ;;
        esac
    fi

    spans_file="${TRACE_E2E_SPANS_FILE:-${ROOT}/target/trace-e2e/spans.json}"
    mkdir -p -- "$(dirname -- "${spans_file}")"

    # Published by docker-compose.yml (jaeger, profile tracing): OTLP/HTTP 4318.
    otlp_endpoint="${TRACE_E2E_OTLP_ENDPOINT:-http://127.0.0.1:4318}"
    # Greppable assignment. ADR-005: the SDK default is 0.01; do not rely on it.
    OTEL_TRACES_SAMPLER_ARG=1.0
    export OTEL_TRACES_SAMPLER_ARG
    export OTEL_EXPORTER_OTLP_ENDPOINT="${otlp_endpoint}"

    export COMPOSE_FILE="${ROOT}/docker-compose.yml"
    export COMPOSE_PROJECT_NAME="${TRACE_E2E_COMPOSE_PROJECT:-rvc-trace-e2e}"
    case "${COMPOSE_PROJECT_NAME}" in
        ''|*[!A-Za-z0-9_-]*)
            fail usage "TRACE_E2E_COMPOSE_PROJECT must be a compose project name"
            ;;
    esac

    rvc_bin="$(resolve_host_bin RVC_BIN rvc "${RVC_BIN:-}")"
    signer_bin="$(resolve_host_bin RVC_SIGNER_BIN rvc-signer "${RVC_SIGNER_BIN:-}")"

    bn_port="$(pick_port)" || fail port-bind "no free TCP port in 19000-19250 for the fixture"
    signer_port="$(pick_port "${bn_port}")" || fail port-bind "no free TCP port for rvc-signer"
    signer_metrics="$(pick_port "${bn_port}" "${signer_port}")" || fail port-bind "no free TCP port for signer metrics"
    rvc_metrics="$(pick_port "${bn_port}" "${signer_port}" "${signer_metrics}")" || fail port-bind "no free TCP port for rvc metrics"

    workdir="$(mktemp -d "${TMPDIR:-/tmp}/trace-e2e.XXXXXX")"
    mkdir -p "${workdir}/keystores" "${workdir}/signer-data"
    cp "${FIXTURE_DIR}/trace_e2e_validator_keystore.json" "${workdir}/keystores/keystore-0.json"
    chmod 600 "${workdir}/keystores/keystore-0.json"
    cp "${FIXTURE_DIR}/trace_e2e_validator_password.txt" "${workdir}/passwords.txt"
    printf '%s\n' "${signer_pw}" > "${workdir}/signer-password.txt"
    chmod 600 "${workdir}/signer-password.txt" "${workdir}/passwords.txt"
    cat > "${workdir}/validators.toml" <<EOF
[defaults]
fee_recipient = "${FEE_RECIPIENT}"
EOF
    cat > "${workdir}/config.toml" <<EOF
beacon_url = "http://127.0.0.1:${bn_port}"
keystore_path = "${workdir}/keystores"
grpc_signer.url = "http://127.0.0.1:${signer_port}"
slashing_db_path = "${workdir}/slashing.db"
validators_config = "${workdir}/validators.toml"
password_file = "${workdir}/passwords.txt"
metrics_address = "127.0.0.1"
metrics_port = ${rvc_metrics}
network = "custom"
genesis_time = ${genesis_time}
genesis_validators_root = "${GVR}"
log_level = "info"
keymanager_enabled = false
disable_keystore_locking = true
allow_fresh_db = true
doppelganger_detection = false
EOF

    # Set before `up` so a failed start still runs compose down from the trap.
    compose_started=1
    echo "trace-e2e: part 2 starting Phase-1 compose tracing profile (jaeger)"
    if ! timeout 180 docker compose --profile tracing up -d jaeger; then
        fail jaeger-start "docker compose --profile tracing up -d jaeger failed or timed out after 180s"
    fi

    jaeger_otlp_ready() {
        local code
        code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 -X POST \
            "http://127.0.0.1:4318/v1/traces" \
            -H 'Content-Type: application/json' -d '{}' 2>/dev/null || true)"
        [[ "${code}" == "200" ]]
    }
    wait_until jaeger-otlp 90 jaeger_otlp_ready
    echo "trace-e2e: jaeger OTLP sink ready at http://127.0.0.1:4318"

    TRACE_E2E_GENESIS_TIME="${genesis_time}" \
        TRACE_E2E_GENESIS_VALIDATORS_ROOT="${GVR}" \
        TRACE_E2E_VALIDATOR_PUBKEY="${pubkey}" \
        TRACE_E2E_VALIDATOR_INDEX="0" \
        python3 "${FIXTURE_PY}" \
            --fixtures "${FIXTURE_DIR}" \
            --bind 127.0.0.1 \
            --port "${bn_port}" \
        >"${workdir}/fixture.log" 2>&1 &
    bn_pid=$!

    genesis_ok() {
        curl -fsS --max-time 2 "http://127.0.0.1:${bn_port}/eth/v1/beacon/genesis" >/dev/null 2>&1
    }
    wait_until fixture-bn-ready 60 genesis_ok
    echo "trace-e2e: fixture beacon node ready at http://127.0.0.1:${bn_port}"

    signer_log="${workdir}/signer.log"
    : > "${signer_log}"
    # Same sampler and endpoint as bin/rvc. No --tracing-sample-rate flag:
    # the explicit env assignment above is what the process resolves.
    # Loopback fixture only. --insecure also requires this opt-in, and the
    # signer gate still demands a loopback bind (predicate_ok).
    OTEL_TRACES_SAMPLER_ARG=1.0 \
        OTEL_EXPORTER_OTLP_ENDPOINT="${otlp_endpoint}" \
        RVC_SIGNER_ALLOW_INSECURE=true \
        RUST_LOG=info \
        "${signer_bin}" serve \
            --insecure \
            --init-slashing-db \
            --keystore-dir "${workdir}/keystores" \
            --password-file "${workdir}/signer-password.txt" \
            --data-dir "${workdir}/signer-data" \
            --listen-address "127.0.0.1:${signer_port}" \
            --metrics-address "127.0.0.1:${signer_metrics}" \
        >"${signer_log}" 2>&1 &
    signer_pid=$!

    signer_ready() {
        if ! kill -0 "${signer_pid}" 2>/dev/null; then
            fail signer-exited "bin/rvc-signer (pid ${signer_pid}) exited before it was ready"
        fi
        curl -fsS --max-time 2 "http://127.0.0.1:${signer_metrics}/metrics" >/dev/null 2>&1
    }
    wait_until signer-ready 30 signer_ready
    echo "trace-e2e: rvc-signer ready at 127.0.0.1:${signer_port}"

    rvc_log="${workdir}/rvc.log"
    : > "${rvc_log}"
    # Loopback http is refused unless this is set. The signer process keeps
    # its own --insecure / RVC_SIGNER_ALLOW_INSECURE pair.
    OTEL_TRACES_SAMPLER_ARG=1.0 \
        OTEL_EXPORTER_OTLP_ENDPOINT="${otlp_endpoint}" \
        RVC_REMOTE_SIGNER_ALLOW_INSECURE=true \
        RUST_LOG=info \
        "${rvc_bin}" start \
            --config "${workdir}/config.toml" \
            --init-slashing-db \
            --no-doppelganger-detection \
            --log-level info \
            --log-format pretty \
            --metrics-address 127.0.0.1 \
            --metrics-port "${rvc_metrics}" \
        >"${rvc_log}" 2>&1 &
    rvc_pid=$!

    # A failed connect is non-fatal inside bin/rvc: it logs and keeps the
    # local keystore. That still closes slot.process and then fails the
    # continuity assert as missing-span. Name it here instead.
    grpc_signer_connected() {
        if ! kill -0 "${rvc_pid}" 2>/dev/null; then
            fail rvc-exited "bin/rvc (pid ${rvc_pid}) exited before the gRPC signer connect settled"
        fi
        if grep -F -q 'Failed to connect to gRPC remote signer' "${rvc_log}"; then
            fail grpc-connect \
                "bin/rvc logged a failed gRPC connect and would keep signing on the local keystore"
        fi
        grep -F -q 'gRPC remote signer connected' "${rvc_log}"
    }
    wait_until grpc-connect 30 grpc_signer_connected
    echo "trace-e2e: gRPC remote signer connected from bin/rvc"

    # slot.process stays open until the next slot boundary (post-duty window).
    # "Slot processing complete" is inside the span; the span drops after
    # genesis + (slot+1)*SECONDS_PER_SLOT.
    slot_span_closed() {
        local line slot slot_end now
        if ! kill -0 "${rvc_pid}" 2>/dev/null; then
            fail rvc-exited "bin/rvc (pid ${rvc_pid}) exited before slot.process closed"
        fi
        if ! grep -F -q 'slot.process' "${rvc_log}"; then
            return 1
        fi
        line="$(grep -E 'Slot processing complete slot=[0-9]+' "${rvc_log}" | head -n 1 || true)"
        if [[ -z "${line}" ]]; then
            return 1
        fi
        slot="${line##*slot=}"
        slot="${slot%%[^0-9]*}"
        case "${slot}" in
            ''|*[!0-9]*) return 1 ;;
        esac
        slot_end=$((genesis_time + (slot + 1) * spe + slot_close_margin))
        now="$(date +%s)"
        (( now >= slot_end ))
    }
    wait_until slot-close "${evidence_timeout}" slot_span_closed
    echo "trace-e2e: slot.process closed (full slot elapsed after Slot processing complete)"

    if [[ "${teardown}" == "sigkill" ]]; then
        # Diagnostic red: the span has ended but the batch worker has not been
        # given the flush window, and SIGKILL skips shutdown. Always non-zero.
        kill -KILL "${rvc_pid}" >/dev/null 2>&1 || true
        kill -KILL "${signer_pid}" >/dev/null 2>&1 || true
        wait "${rvc_pid}" >/dev/null 2>&1 || true
        wait "${signer_pid}" >/dev/null 2>&1 || true
        rvc_pid=""
        signer_pid=""
        fetch_jaeger_spans "${spans_file}"
        if span_file_has_closed_slot "${spans_file}"; then
            fail sigkill-exported \
                "SIGKILL still left a closed slot.process in ${spans_file}; red path is invalid"
        fi
        fail sigkill-no-export \
            "SIGKILL dropped the unflushed slot.process span (${spans_file})"
    fi

    # BatchSpanProcessor exports on its schedule while the process is alive.
    # bin/rvc does not call shutdown_tracing on Drop, so this window is the flush.
    span_flush_done() {
        local elapsed
        if ! kill -0 "${rvc_pid}" 2>/dev/null; then
            fail rvc-exited "bin/rvc exited during span-flush"
        fi
        if ! kill -0 "${signer_pid}" 2>/dev/null; then
            fail signer-exited "bin/rvc-signer exited during span-flush"
        fi
        elapsed=$((SECONDS - flush_mark))
        (( elapsed >= flush_wait ))
    }
    flush_mark="${SECONDS}"
    wait_until span-flush "$((flush_wait + 15))" span_flush_done
    echo "trace-e2e: span-flush waited ${flush_wait}s with both processes alive"

    stop_pid_clean rvc-shutdown "${rvc_pid}" "${shutdown_timeout}"
    rvc_pid=""
    stop_pid_clean signer-shutdown "${signer_pid}" "${shutdown_timeout}"
    signer_pid=""
    # Fixture is not a span exporter. TERM it so the trap does not have to.
    stop_pid_clean fixture-shutdown "${bn_pid}" 10
    bn_pid=""

    fetch_jaeger_spans "${spans_file}"
    if ! span_file_has_closed_slot "${spans_file}"; then
        fail slot-span \
            "no closed slot.process (startTime + duration) in ${spans_file}"
    fi

    echo "trace-e2e: part 2 ok — closed slot.process written to ${spans_file}"
    ok=1
    exit 0
}

fetch_jaeger_spans() {
    local dest="$1"
    local tmp
    mkdir -p -- "$(dirname -- "${dest}")"
    tmp="${dest}.partial"
    if ! curl -fsS --max-time 10 \
        "http://127.0.0.1:16686/api/traces?service=rvc&limit=50" \
        -o "${tmp}"; then
        rm -f -- "${tmp}"
        fail jaeger-query "GET /api/traces?service=rvc timed out or failed (waited for Jaeger query)"
    fi
    mv -- "${tmp}" "${dest}"
}

span_file_has_closed_slot() {
    python3 - "$1" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)
for trace in doc.get("data") or []:
    for span in trace.get("spans") or []:
        if span.get("operationName") != "slot.process":
            continue
        if "startTime" not in span or "duration" not in span:
            continue
        duration = span["duration"]
        if isinstance(duration, bool) or not isinstance(duration, (int, float)):
            continue
        if duration < 0:
            continue
        print(
            "trace-e2e: closed slot.process"
            f" duration={duration} startTime={span['startTime']}"
        )
        raise SystemExit(0)
raise SystemExit(1)
PY
}

if [[ "${part}" != "1" && "${part}" != "2" ]]; then
    fail part-not-in-scope \
        "only part 1 and part 2 are implemented; part ${part} is a later ticket (5c-5e are not started)"
fi

if [[ "${part}" == "2" ]]; then
    run_part2
fi

# Shellcheck-friendly glob: nullglob + array, quoted directory prefix.
shopt -s nullglob
fixture_files=("${FIXTURE_DIR}"/trace_e2e_bn__*.json)
shopt -u nullglob
if ((${#fixture_files[@]} == 0)); then
    fail fixture-glob "no fixtures matched ${FIXTURE_DIR}/trace_e2e_bn__*.json"
fi

if [[ ! -f "${FIXTURE_DIR}/trace_e2e_validator_keystore.json" ]]; then
    fail fixture-keystore "missing trace_e2e_validator_keystore.json"
fi
if [[ ! -f "${FIXTURE_DIR}/trace_e2e_validator_pubkey.txt" ]]; then
    fail fixture-pubkey "missing trace_e2e_validator_pubkey.txt"
fi
if [[ ! -f "${FIXTURE_DIR}/trace_e2e_validator_password.txt" ]]; then
    fail fixture-password "missing trace_e2e_validator_password.txt"
fi

pubkey="$(tr -d '[:space:]' < "${FIXTURE_DIR}/trace_e2e_validator_pubkey.txt")"
if [[ -z "${pubkey}" ]]; then
    fail fixture-pubkey "pubkey file is empty"
fi

if [[ "${RUNTIME}" == "docker" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        fail docker-missing "docker is required (or set TRACE_E2E_RUNTIME=python)"
    fi
elif [[ "${RUNTIME}" == "python" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        fail python-missing "python3 is required when TRACE_E2E_RUNTIME=python"
    fi
else
    fail usage "TRACE_E2E_RUNTIME must be docker or python (got ${RUNTIME})"
fi

bn_port="$(pick_port)" || fail port-bind "no free TCP port in 19000-19250"
metrics_port="$(pick_port)" || fail port-bind "no free TCP port for metrics"
if [[ "${metrics_port}" == "${bn_port}" ]]; then
    metrics_port="$((bn_port + 1))"
fi

delay="${TRACE_E2E_GENESIS_DELAY:-20}"
case "${delay}" in
    ''|*[!0-9]*) fail usage "TRACE_E2E_GENESIS_DELAY must be a non-negative integer" ;;
esac
now="$(date +%s)"
genesis_time="$((now + delay))"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/trace-e2e.XXXXXX")"
mkdir -p "${workdir}/keystores"
cp "${FIXTURE_DIR}/trace_e2e_validator_keystore.json" "${workdir}/keystores/keystore-0.json"
cp "${FIXTURE_DIR}/trace_e2e_validator_password.txt" "${workdir}/passwords.txt"
cat > "${workdir}/validators.toml" <<EOF
[defaults]
fee_recipient = "${FEE_RECIPIENT}"
EOF

rvc_bin=""
use_docker_rvc=0
if [[ -n "${RVC_BIN:-}" ]]; then
    if [[ ! -x "${RVC_BIN}" ]]; then
        fail rvc-bin "RVC_BIN is not executable: ${RVC_BIN}"
    fi
    rvc_bin="${RVC_BIN}"
elif [[ -x "${ROOT}/target/debug/rvc" ]]; then
    rvc_bin="${ROOT}/target/debug/rvc"
elif [[ -x "${ROOT}/target/release/rvc" ]]; then
    rvc_bin="${ROOT}/target/release/rvc"
else
    if [[ "${RUNTIME}" != "docker" ]]; then
        fail rvc-bin "no rvc binary and TRACE_E2E_RUNTIME is not docker"
    fi
    echo "trace-e2e: building rvc image (Dockerfile target rvc)" >&2
    if ! docker build --target rvc -t rvc-trace-e2e:rvc "${ROOT}"; then
        fail rvc-image "docker build --target rvc failed"
    fi
    use_docker_rvc=1
fi

# Readiness is always the host loopback publish. Containerized bin/rvc does
# not use that publish: on Linux, host-gateway is the bridge address and cannot
# reach 127.0.0.1. Both containers share a private network and rvc uses the
# fixture alias on port 5052.
host_beacon_url="http://127.0.0.1:${bn_port}"
if [[ "${use_docker_rvc}" -eq 1 ]]; then
    bn_net="rvc-trace-e2e-net-$$"
    docker network rm "${bn_net}" >/dev/null 2>&1 || true
    if ! docker network create "${bn_net}" >/dev/null; then
        fail fixture-bn-network "docker network create ${bn_net} failed"
    fi
    beacon_url="http://${bn_alias}:5052"
    ks_path="/data/keystores"
    slash_path="/data/slashing.db"
    validators_path="/data/validators.toml"
    password_path="/data/passwords.txt"
else
    beacon_url="${host_beacon_url}"
    ks_path="${workdir}/keystores"
    slash_path="${workdir}/slashing.db"
    validators_path="${workdir}/validators.toml"
    password_path="${workdir}/passwords.txt"
fi

cat > "${workdir}/config.toml" <<EOF
beacon_url = "${beacon_url}"
keystore_path = "${ks_path}"
slashing_db_path = "${slash_path}"
validators_config = "${validators_path}"
password_file = "${password_path}"
metrics_address = "127.0.0.1"
metrics_port = ${metrics_port}
network = "custom"
genesis_time = ${genesis_time}
genesis_validators_root = "${GVR}"
log_level = "info"
keymanager_enabled = false
disable_keystore_locking = true
allow_fresh_db = true
doppelganger_detection = false
EOF

echo "trace-e2e: ${#fixture_files[@]} fixture files; genesis_time=${genesis_time} (delay ${delay}s)"

if [[ "${RUNTIME}" == "docker" ]]; then
    bn_cid="rvc-trace-e2e-bn-$$"
    docker rm -f "${bn_cid}" >/dev/null 2>&1 || true
    bn_run=(docker run -d --name "${bn_cid}" -p "127.0.0.1:${bn_port}:5052")
    if [[ -n "${bn_net}" ]]; then
        bn_run+=(--network "${bn_net}" --network-alias "${bn_alias}")
    fi
    if ! "${bn_run[@]}" \
        -e TRACE_E2E_GENESIS_TIME="${genesis_time}" \
        -e TRACE_E2E_GENESIS_VALIDATORS_ROOT="${GVR}" \
        -e TRACE_E2E_VALIDATOR_PUBKEY="${pubkey}" \
        -e TRACE_E2E_VALIDATOR_INDEX="0" \
        -v "${FIXTURE_PY}:/srv/fixture_bn.py:ro" \
        -v "${FIXTURE_DIR}:/fixtures:ro" \
        "${IMAGE}" \
        python3 /srv/fixture_bn.py --fixtures /fixtures --bind 0.0.0.0 --port 5052 \
        >/dev/null; then
        fail fixture-bn-start "docker run of the fixture beacon node failed"
    fi
else
    TRACE_E2E_GENESIS_TIME="${genesis_time}" \
        TRACE_E2E_GENESIS_VALIDATORS_ROOT="${GVR}" \
        TRACE_E2E_VALIDATOR_PUBKEY="${pubkey}" \
        TRACE_E2E_VALIDATOR_INDEX="0" \
        python3 "${FIXTURE_PY}" \
            --fixtures "${FIXTURE_DIR}" \
            --bind 127.0.0.1 \
            --port "${bn_port}" \
        >"${workdir}/fixture.log" 2>&1 &
    bn_pid=$!
fi

genesis_ok() {
    curl -fsS --max-time 2 "${host_beacon_url}/eth/v1/beacon/genesis" >/dev/null
}
wait_until fixture-bn-ready 60 genesis_ok
echo "trace-e2e: fixture beacon node ready at ${host_beacon_url}"

if [[ "${up_only}" -eq 1 ]]; then
    echo "trace-e2e: --up-only; part 1 stops after fixture readiness"
    ok=1
    exit 0
fi

rvc_log="${workdir}/rvc.log"
: > "${rvc_log}"

if [[ "${use_docker_rvc}" -eq 1 ]]; then
    rvc_cid="rvc-trace-e2e-vc-$$"
    docker rm -f "${rvc_cid}" >/dev/null 2>&1 || true
    if ! docker run -d --name "${rvc_cid}" \
        --network "${bn_net}" \
        --user "$(id -u):$(id -g)" \
        -e RUST_LOG=info \
        -v "${workdir}:/data" \
        rvc-trace-e2e:rvc \
        start \
            --config /data/config.toml \
            --init-slashing-db \
            --no-doppelganger-detection \
            --log-level info \
            --log-format pretty \
            --metrics-address 127.0.0.1 \
            --metrics-port "${metrics_port}" \
        >/dev/null; then
        fail rvc-start "docker run of bin/rvc failed"
    fi
    # Follow container logs into the evidence file.
    docker logs -f "${rvc_cid}" >"${rvc_log}" 2>&1 &
    rvc_pid=$!
else
    # RUST_LOG=info so an ambient filter cannot hide the duty-path line.
    # OTEL exporter env is cleared: part 1 asserts the fmt span, not a collector.
    env -u OTEL_EXPORTER_OTLP_ENDPOINT \
        -u OTEL_EXPORTER_OTLP_PROTOCOL \
        -u OTEL_TRACES_EXPORTER \
        -u OTEL_METRICS_EXPORTER \
        RUST_LOG=info \
        "${rvc_bin}" start \
            --config "${workdir}/config.toml" \
            --init-slashing-db \
            --no-doppelganger-detection \
            --log-level info \
            --log-format pretty \
            --metrics-address 127.0.0.1 \
            --metrics-port "${metrics_port}" \
        >"${rvc_log}" 2>&1 &
    rvc_pid=$!
fi

evidence_ready() {
    if [[ "${use_docker_rvc}" -eq 1 ]]; then
        local running
        running="$(docker inspect -f '{{.State.Running}}' "${rvc_cid}" 2>/dev/null || echo false)"
        if [[ "${running}" != "true" ]]; then
            fail rvc-exited "bin/rvc container exited before attestation-duty evidence"
        fi
    elif ! kill -0 "${rvc_pid}" >/dev/null 2>&1; then
        fail rvc-exited "bin/rvc (pid ${rvc_pid}) exited before attestation-duty evidence"
    fi
    grep -F -q 'slot.process' "${rvc_log}" \
        && grep -F -q 'Found attestation duties' "${rvc_log}"
}

# Genesis delay plus one epoch of slack (32*12s) so a slow start still
# catches a slot inside epoch 0.
evidence_timeout="$((delay + 32 * 12 + 30))"
wait_until attestation-duty "${evidence_timeout}" evidence_ready

echo "trace-e2e: part 1 ok — bin/rvc reached an attestation duty"
echo "----- evidence (slot.process + duty path) -----"
grep -F -e 'slot.process' -e 'Found attestation duties' -e 'Processing attestation duty' \
    -e 'Batch attestation summary' -e 'Processing attestation duties for slot' \
    "${rvc_log}" | head -n 40

# Part 1 stops here. Do not start the signer, the collector, or CI assertions.
ok=1
exit 0
