#!/usr/bin/env bash
# trace-e2e.sh — part 1 (TRC-5a / #432).
#
# Stands up a MockBn-based fixture beacon node and runs bin/rvc until it
# reaches at least one attestation duty. Evidence is a `slot.process` span
# plus the duty-path log line "Found attestation duties".
#
# Part 1 exits when that evidence is present. TRC-5b (signer), TRC-5c, TRC-5d
# (trace assert), and TRC-5e are not started.
#
# Requires Docker and a repo checkout. A local `target/{debug,release}/rvc`
# (or $RVC_BIN) is used when present; otherwise the script builds the `rvc`
# image from the repo Dockerfile.
#
#   TRACE_E2E_RUNTIME=python   run the fixture server with host python3
#                              (same program Docker runs; for hosts without a
#                              daemon). Default is docker.
#   TRACE_E2E_GENESIS_DELAY    seconds from now until genesis (default 20)
#   TRACE_E2E_KEEP=1           keep the work directory after success
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

usage() {
    cat <<EOF
Usage: $(basename "$0") [--part 1] [--up-only]

Part 1 (default): start the fixture beacon node, run bin/rvc, and exit 0
when a slot.process span and an attestation duty-path log are both present.

  --part N     Only part 1 is implemented. Any other part exits 1.
  --up-only    Start the fixture, wait until it is ready, then exit.
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
    if [[ -n "${bn_cid}" ]]; then
        echo "----- fixture container log -----" >&2
        docker logs "${bn_cid}" >&2 || true
    fi
    if [[ -n "${workdir}" ]]; then
        echo "trace-e2e: logs kept at ${workdir}" >&2
    fi
}

cleanup() {
    dump_debug
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

pick_port() {
    local port
    for ((port = 19000; port <= 19250; port++)); do
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

if [[ "${part}" != "1" ]]; then
    fail part-not-in-scope \
        "TRC-5a implements part 1 only; part ${part} is a later ticket (5b–5e are not started)"
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
