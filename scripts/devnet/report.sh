#!/usr/bin/env bash
# Chain + client report: validator_perf.py, devnet_report.py, verdict.json.

set -euo pipefail

_REPORT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_REPORT_DIR}/lib/common.sh"

STRICT="${STRICT:-0}"
FAIL_UNDER_ARGS=()
ANNOTATIONS=()
PERF_MAPPED_EXIT=0
CHAIN_THRESHOLDS="pass"
S5A_PRESENCE="pass"
S5B_LIVENESS="pass"
S7_BLOCKED="pass"
MISSING_FAMILIES=""
MISSING_LIVENESS=""

# Scrape/PRD family names, not Rust declaration sites.
_K_ROWS=(
    "K1 rvc_orchestrator_slots_processed_total"
    "K2 rvc_orchestrator_missed_slots_total"
    "K3 rvc_orchestrator_slot_processing_duration_seconds"
    "K4 rvc_attestations_total"
    "K5 rvc_aggregations_total"
    "K6 rvc_proposals_total"
    "K7 rvc_signing_duration_seconds"
    "K8 rvc_slashing_protection_checks_total"
    "K9 rvc_slashing_reserve_tx_hold_duration_ms"
    "K10 rvc_slot_phase_block_start_offset_ms"
    "K11 rvc_duties_fetched_total"
    "K11 rvc_duty_reorg_detected_total"
    "K12 rvc_bn_health_tier"
    "K12 rvc_proposer_bn_latency_ms"
    "K13 rvc_tasks_running"
    "K13 rvc_task_exits_total"
    "K13 rvc_sse_events_dropped_total"
)

# 5.2 owns bn_url() in common.sh; keep a local fallback so 5.3 stays out of it.
if ! declare -F bn_url >/dev/null 2>&1; then
    bn_url() {
        local port="${CL_HTTP_PORT:-}"
        if [[ -z "$port" ]]; then
            die_usage "CL_HTTP_PORT is not set"
        fi
        case "$port" in
            *[!0-9]*)
                die_usage "CL_HTTP_PORT must be a port number"
                ;;
        esac
        printf 'http://127.0.0.1:%s\n' "$port"
    }
fi

parse_report_flags() {
    local -a rest
    rest=()
    STRICT=0
    DRY_RUN=0
    FAIL_UNDER_ARGS=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --strict)
                STRICT=1
                shift
                ;;
            --fail-under)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--fail-under requires METRIC=VALUE"
                fi
                FAIL_UNDER_ARGS+=("$2")
                shift 2
                ;;
            --fail-under=*)
                if [[ -z "${1#--fail-under=}" ]]; then
                    die_usage "--fail-under requires METRIC=VALUE"
                fi
                FAIL_UNDER_ARGS+=("${1#--fail-under=}")
                shift
                ;;
            *)
                rest+=("$1")
                shift
                ;;
        esac
    done
    export STRICT DRY_RUN
    if [[ ${#rest[@]} -eq 0 ]]; then
        parse_common_flags
    else
        parse_common_flags "${rest[@]}"
    fi
}

_epochs_from_run_json() {
    local path="${RUN_DIR}/run.json"
    local epochs
    epochs="$(jq -r '.epochs // empty' "$path" 2>/dev/null || true)"
    case "$epochs" in
        '' | *[!0-9]*)
            die_usage "run.json missing epochs (produced by run.sh)"
            ;;
    esac
    if [[ "$epochs" -le 0 ]]; then
        die_usage "run.json missing epochs (produced by run.sh)"
    fi
    printf '%s\n' "$epochs"
}

# stdin → DEST. O_NOFOLLOW + O_EXCL random tmp; empty allowed. 2 = symlink.
_atomic_replace_stdin() {
    local dest="${1:-}"
    if [[ -z "$dest" ]]; then
        return 1
    fi
    python3 -c '
import os, sys

dest = sys.argv[1]
data = sys.stdin.buffer.read()
directory = os.path.dirname(os.path.abspath(dest))
if os.path.islink(directory):
    sys.exit(2)
if not os.path.isdir(directory):
    sys.exit(1)
if os.path.lexists(dest) and os.path.islink(dest):
    sys.exit(2)

tmp = dest + ".tmp." + os.urandom(16).hex()
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
fd = -1
try:
    fd = os.open(tmp, flags, 0o600)
    if data:
        os.write(fd, data)
    os.fchmod(fd, 0o600)
    os.close(fd)
    fd = -1
    if os.path.islink(tmp) or os.path.islink(dest):
        os.unlink(tmp)
        sys.exit(2)
    os.replace(tmp, dest)
    tmp = ""
except OSError:
    sys.exit(1)
finally:
    if fd >= 0:
        os.close(fd)
    if tmp:
        try:
            os.unlink(tmp)
        except OSError:
            pass
' "$dest"
}

# rvc.json pubkey set → bare-hex rvc-pubkeys.txt (A3-10 strip). 2=symlink, 3=empty/invalid.
_write_rvc_pubkeys_from_json() {
    local src="${1:-}"
    local dest="${2:-}"
    python3 -c '
import json, os, sys

src, dest = sys.argv[1], sys.argv[2]
directory = os.path.dirname(os.path.abspath(dest))
if os.path.islink(src) or os.path.islink(os.path.dirname(os.path.abspath(src))):
    sys.exit(2)
if os.path.islink(directory):
    sys.exit(2)
if not os.path.isdir(directory):
    sys.exit(1)
if os.path.lexists(dest) and os.path.islink(dest):
    sys.exit(2)

try:
    with open(src, encoding="utf-8") as fh:
        doc = json.load(fh)
except (OSError, json.JSONDecodeError):
    sys.exit(1)

keys = doc.get("pubkeys") if isinstance(doc, dict) else None
if not isinstance(keys, list) or not keys:
    sys.exit(3)

lines = []
for raw in keys:
    if not isinstance(raw, str):
        sys.exit(3)
    item = raw.strip()
    if item.lower().startswith("0x"):
        item = item[2:]
    item = item.lower()
    if len(item) != 96 or any(c not in "0123456789abcdef" for c in item):
        sys.exit(3)
    lines.append(item)
data = ("\n".join(lines) + "\n").encode("ascii")

tmp = dest + ".tmp." + os.urandom(16).hex()
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
fd = -1
try:
    fd = os.open(tmp, flags, 0o600)
    os.write(fd, data)
    os.fchmod(fd, 0o600)
    os.close(fd)
    fd = -1
    if os.path.islink(tmp) or os.path.islink(dest):
        os.unlink(tmp)
        sys.exit(2)
    os.replace(tmp, dest)
    tmp = ""
except OSError:
    sys.exit(1)
finally:
    if fd >= 0:
        os.close(fd)
    if tmp:
        try:
            os.unlink(tmp)
        except OSError:
            pass
' "$src" "$dest"
}

write_rvc_pubkeys() {
    local dest="${RUN_DIR}/rvc-pubkeys.txt"
    local rvc_json="${RUN_DIR}/rvc.json"
    local rc=0

    _write_rvc_pubkeys_from_json "$rvc_json" "$dest" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
        die_usage "refusing symlink rvc-pubkeys.txt: ${dest}"
    fi
    if [[ "$rc" -eq 3 ]]; then
        die_usage "rvc.json pubkey set is empty (produced by attach-rvc.sh)"
    fi
    if [[ "$rc" -ne 0 ]]; then
        die_infra "failed to write ${dest}"
    fi
    chmod 600 "$dest" || die_infra "failed to chmod ${dest}"
}

translate_perf_exit() {
    local rc="${1:-0}"
    case "$rc" in
        0)
            CHAIN_THRESHOLDS="pass"
            return 0
            ;;
        4)
            CHAIN_THRESHOLDS="fail"
            PERF_MAPPED_EXIT=4
            return 0
            ;;
        3)
            ANNOTATIONS+=("degraded")
            CHAIN_THRESHOLDS="pass"
            if [[ "$STRICT" == "1" ]]; then
                PERF_MAPPED_EXIT=3
            else
                log_warn "validator_perf.py degraded; annotating degraded"
            fi
            return 0
            ;;
        *)
            die_infra "validator_perf.py failed (exit ${rc})"
            ;;
    esac
}

run_chain_report() {
    local out="${RUN_DIR}/chain.json"
    local epochs child_rc=0 write_rc=0 item
    local -a cmd _pipe

    epochs="$(_epochs_from_run_json)"
    cmd=(
        "$VALIDATOR_PERF"
        --beacon-url "$(bn_url)"
        --pubkeys-file "${RUN_DIR}/rvc-pubkeys.txt"
        --epochs "$epochs"
        --allow-unfinalized
        --json
    )
    if [[ ${#FAIL_UNDER_ARGS[@]} -gt 0 ]]; then
        for item in "${FAIL_UNDER_ARGS[@]}"; do
            cmd+=(--fail-under "$item")
        done
    fi

    set +e
    "${cmd[@]}" | _atomic_replace_stdin "$out"
    _pipe=("${PIPESTATUS[@]}" 1)
    set -e
    child_rc="${_pipe[0]}"
    write_rc="${_pipe[1]}"

    if [[ "$write_rc" -eq 2 ]]; then
        die_usage "refusing symlink chain.json: ${out}"
    fi
    if [[ "$write_rc" -ne 0 ]]; then
        die_infra "failed to write ${out}"
    fi
    chmod 600 "$out" || die_infra "failed to chmod ${out}"
    translate_perf_exit "$child_rc"
}

run_client_report() {
    local rc=0
    validate_data_exists "metrics-start.txt" "${RUN_DIR}/metrics-start.txt" "soak.sh"
    validate_data_exists "metrics-end.txt" "${RUN_DIR}/metrics-end.txt" "soak.sh"
    validate_data_exists "samples.jsonl" "${RUN_DIR}/samples.jsonl" "soak.sh"

    set +e
    "$DEVNET_REPORT" report --run-dir "$RUN_DIR" >/dev/null
    rc=$?
    set -e
    case "$rc" in
        0) ;;
        2)
            die_usage "devnet_report.py report failed (exit 2)"
            ;;
        *)
            die_infra "devnet_report.py report failed (exit ${rc})"
            ;;
    esac
    if [[ ! -f "${RUN_DIR}/client.json" ]]; then
        die_infra "client.json missing after devnet_report.py report"
    fi
    if [[ ! -f "${RUN_DIR}/report.txt" ]]; then
        die_infra "report.txt missing after devnet_report.py report"
    fi
}

# Presence of K8 result="blocked" in metrics-end.txt. lstat + O_NOFOLLOW;
# does not follow a leaf symlink. 0 = present, 1 = missing/unreadable.
_end_scrape_has_k8_blocked() {
    python3 -c '
import os, re, stat, sys

path = sys.argv[1]
nofollow = getattr(os, "O_NOFOLLOW", 0)
try:
    st = os.lstat(path)
except OSError:
    sys.exit(1)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
    sys.exit(1)
fd = -1
try:
    fd = os.open(path, os.O_RDONLY | nofollow)
    data = b""
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        data += chunk
        if len(data) > 64 * 1024 * 1024:
            sys.exit(1)
except OSError:
    sys.exit(1)
finally:
    if fd >= 0:
        os.close(fd)
try:
    text = data.decode("utf-8")
except UnicodeDecodeError:
    sys.exit(1)
pat = re.compile(
    r"^rvc_slashing_protection_checks_total\{[^}]*result=\"blocked\"",
    re.M,
)
sys.exit(0 if pat.search(text) else 1)
' "${RUN_DIR}/metrics-end.txt"
}

assert_no_blocked() {
    # End-scrape presence (not a synthesized client.json end=0.0), then
    # client.json numeric check. Fail closed on missing child, null /
    # non-number end, end != 0, or monotonic_violation.
    if ! _end_scrape_has_k8_blocked; then
        S7_BLOCKED="fail"
        log_warn "K8 blocked missing or unreadable in metrics-end.txt"
        return 0
    fi
    if jq -e '
        (.counters.rvc_slashing_protection_checks_total) as $rows
        | ($rows | type) == "array"
          and (
              [$rows[] | select(.labels.result == "blocked")] as $blocked
              | ($blocked | length) > 0
                and ($blocked | all(
                    (.end | type == "number")
                    and (.end == 0)
                    and (.monotonic_violation != true)
                ))
          )
    ' "${RUN_DIR}/client.json" >/dev/null; then
        S7_BLOCKED="pass"
    else
        S7_BLOCKED="fail"
        log_warn "K8 blocked > 0 or unreadable in client.json"
    fi
}

_client_has_family() {
    local name="${1:-}"
    jq -e --arg n "$name" '
        (.counters | has($n))
        or (.histograms | has($n))
        or (.gauges | has($n))
    ' "${RUN_DIR}/client.json" >/dev/null
}

assert_s5a_presence() {
    local row kid name missing=""
    S5A_PRESENCE="pass"
    MISSING_FAMILIES=""
    for row in "${_K_ROWS[@]}"; do
        kid="${row%% *}"
        name="${row#* }"
        if _client_has_family "$name"; then
            continue
        fi
        S5A_PRESENCE="fail"
        if [[ -z "$missing" ]]; then
            missing="${kid} ${name}"
        else
            missing="${missing}, ${kid} ${name}"
        fi
    done
    MISSING_FAMILIES="$missing"
}

_jq_nonzero() {
    local kind="${1:-}"
    local name="${2:-}"
    case "$kind" in
        counter)
            jq -e --arg n "$name" '
                ((.counters[$n] // []) | map(.delta // 0) | add) > 0
            ' "${RUN_DIR}/client.json" >/dev/null
            ;;
        histogram)
            jq -e --arg n "$name" '
                ((.histograms[$n] // []) | map(.samples // 0) | add) > 0
            ' "${RUN_DIR}/client.json" >/dev/null
            ;;
        gauge)
            jq -e --arg n "$name" '
                ((.gauges[$n] // [])
                 | map([(.last // 0), (.max // 0)] | max)
                 | map(select(. != null))
                 | any(. != 0))
            ' "${RUN_DIR}/client.json" >/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

assert_s5b_liveness() {
    local missing=""
    S5B_LIVENESS="pass"
    MISSING_LIVENESS=""
    if ! _jq_nonzero counter rvc_orchestrator_slots_processed_total; then
        missing="K1 rvc_orchestrator_slots_processed_total"
    fi
    if ! _jq_nonzero histogram rvc_orchestrator_slot_processing_duration_seconds; then
        if [[ -n "$missing" ]]; then
            missing="${missing}, K3 rvc_orchestrator_slot_processing_duration_seconds"
        else
            missing="K3 rvc_orchestrator_slot_processing_duration_seconds"
        fi
    fi
    if ! _jq_nonzero counter rvc_attestations_total; then
        if [[ -n "$missing" ]]; then
            missing="${missing}, K4 rvc_attestations_total"
        else
            missing="K4 rvc_attestations_total"
        fi
    fi
    if ! _jq_nonzero counter rvc_aggregations_total; then
        if [[ -n "$missing" ]]; then
            missing="${missing}, K5 rvc_aggregations_total"
        else
            missing="K5 rvc_aggregations_total"
        fi
    fi
    if ! _jq_nonzero histogram rvc_signing_duration_seconds; then
        if [[ -n "$missing" ]]; then
            missing="${missing}, K7 rvc_signing_duration_seconds"
        else
            missing="K7 rvc_signing_duration_seconds"
        fi
    fi
    if ! _jq_nonzero counter rvc_duties_fetched_total; then
        if [[ -n "$missing" ]]; then
            missing="${missing}, K11 rvc_duties_fetched_total"
        else
            missing="K11 rvc_duties_fetched_total"
        fi
    fi
    if ! _jq_nonzero gauge rvc_bn_health_tier; then
        if [[ -n "$missing" ]]; then
            missing="${missing}, K12 rvc_bn_health_tier"
        else
            missing="K12 rvc_bn_health_tier"
        fi
    fi
    if [[ -n "$missing" ]]; then
        S5B_LIVENESS="fail"
        MISSING_LIVENESS="$missing"
    fi
}

_merged_annotations() {
    local extra='[]'
    if [[ ${#ANNOTATIONS[@]} -gt 0 ]]; then
        extra="$(printf '%s\n' "${ANNOTATIONS[@]}" | jq -R . | jq -s -c 'map(select(. != ""))')"
    fi
    jq -c -n \
        --argjson extra "$extra" \
        --argjson client "$(jq -c '.annotations // []' "${RUN_DIR}/client.json")" \
        '($client + $extra) | unique'
}

_report_exit_code() {
    if [[ "$S7_BLOCKED" != "pass" || "$S5A_PRESENCE" != "pass" || "$S5B_LIVENESS" != "pass" ]]; then
        printf '3\n'
        return 0
    fi
    if [[ "$PERF_MAPPED_EXIT" -eq 4 ]]; then
        printf '4\n'
        return 0
    fi
    if [[ "$PERF_MAPPED_EXIT" -eq 3 ]]; then
        printf '3\n'
        return 0
    fi
    printf '0\n'
}

write_verdict() {
    local dest="${RUN_DIR}/verdict.json"
    local generated_at run_id verdict exit_code annotations
    local -a _pipe
    local jq_rc=0 write_rc=0

    generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    run_id="$(jq -r '.run_id // empty' "${RUN_DIR}/run.json" 2>/dev/null || true)"
    if [[ -z "$run_id" || "$run_id" == "null" ]]; then
        die_usage "run.json missing run_id (produced by run.sh)"
    fi
    exit_code="$(_report_exit_code)"
    if [[ "$exit_code" -eq 0 ]]; then
        verdict="pass"
    else
        verdict="fail"
    fi
    annotations="$(_merged_annotations)"

    set +e
    jq -S -n \
        --arg generated_at "$generated_at" \
        --arg run_id "$run_id" \
        --arg verdict "$verdict" \
        --argjson exit_code "$exit_code" \
        --arg s5a "$S5A_PRESENCE" \
        --arg s5b "$S5B_LIVENESS" \
        --arg s7 "$S7_BLOCKED" \
        --arg chain "$CHAIN_THRESHOLDS" \
        --argjson annotations "$annotations" \
        '{
            annotations: $annotations,
            exit_code: $exit_code,
            gates: {
                chain_thresholds: $chain,
                s5a_presence: $s5a,
                s5b_liveness: $s5b,
                s7_blocked: $s7
            },
            generated_at: $generated_at,
            run_id: $run_id,
            schema_version: 1,
            verdict: $verdict
        }' | _atomic_replace_stdin "$dest"
    _pipe=("${PIPESTATUS[@]}" 1)
    set -e
    jq_rc="${_pipe[0]}"
    write_rc="${_pipe[1]}"
    if [[ "$write_rc" -eq 2 ]]; then
        die_usage "refusing symlink verdict.json: ${dest}"
    fi
    if [[ "$jq_rc" -ne 0 || "$write_rc" -ne 0 ]]; then
        die_infra "failed to write ${dest}"
    fi
    chmod 600 "$dest" || die_infra "failed to chmod ${dest}"
}

_render_chain_half() {
    jq -s -r '
        def scrub:
            tostring | gsub("[\u0000-\u001f\u007f-\u009f]"; "?");
        def dash: if . == null then "—" else scrub end;
        def pct:
            if . == null then "—"
            else ((. * 10000 | round) / 100 | tostring)
            end;
        def abbr:
            if . == null then "—"
            else
                (tostring | if startswith("0x") then .[2:] else . end) as $b
                | ("0x" + $b[0:4] + "…" + $b[-4:] | scrub)
            end;
        def incl:
            if . == null then "—/—"
            else ((.included | dash) + "/" + (.scheduled | dash))
            end;
        .[0] as $client | .[1] as $chain
        | ($client.window // {}) as $w
        | ($client.run // {}) as $run
        | (
            [
                "--- chain ---",
                (
                    "soak window: slots "
                    + (($w.start_slot | dash)) + "–" + (($w.end_slot | dash))
                    + " (" + (($w.slots | dash)) + " slots, "
                    + (($w.epochs | dash)) + " epochs)"
                    + "  key_range: " + (($run.key_range // []) | tostring)
                ),
                "",
                "pubkey  index  status  active epochs  part%  src%  tgt%  head%  missed  incl/sched  sync%  Δbal ETH  eff%  APR%"
            ]
            + [
                ($chain.validators // [])[]
                | (
                    (.pubkey | abbr) + "  " + (.index | dash) + "  "
                    + (.status | dash) + "  " + (.active_epochs | dash) + "  "
                    + (.participation_rate | pct) + "  " + (.source_rate | pct) + "  "
                    + (.target_rate | pct) + "  " + (.head_rate | pct) + "  "
                    + (.missed_attestations | dash) + "  " + ((.proposals) | incl) + "  "
                    + ((.sync.participation_rate // null) | pct) + "  "
                    + (if .balance.delta_gwei == null then "—"
                       else ((.balance.delta_gwei / 1000000000) | tostring) end)
                    + "  " + (.attester_effectiveness | pct) + "  "
                    + (.estimated_apr | pct)
                )
            ]
            + [
                "",
                (
                    "validators: " + (($chain.aggregate.validators // 0) | tostring)
                    + "  ("
                    + (
                        ($chain.aggregate.by_status // {})
                        | to_entries
                        | map((.key | scrub) + ": " + (.value | dash))
                        | join(", ")
                    )
                    + ")"
                ),
                (
                    "window: epochs "
                    + (($chain.window.from_epoch | dash)) + "–"
                    + (($chain.window.to_epoch | dash))
                ),
                (
                    "part% " + (($chain.aggregate.participation_rate) | pct)
                    + "  src% " + (($chain.aggregate.source_rate) | pct)
                    + "  tgt% " + (($chain.aggregate.target_rate) | pct)
                    + "  head% " + (($chain.aggregate.head_rate) | pct)
                    + "  eff% " + (($chain.aggregate.attester_effectiveness) | pct)
                ),
                (
                    "missed " + (($chain.aggregate.missed_attestations | dash))
                    + "  incl/sched " + (($chain.aggregate.proposals) | incl)
                    + "  consensus_reward_gwei "
                    + (($chain.aggregate.consensus_reward_gwei | dash))
                    + "  APR% " + (($chain.aggregate.estimated_apr) | pct)
                ),
                "",
                "DEGRADED:"
            ]
            + [
                ($chain.degradations // [])[]
                | ((.metric | dash) + "  " + (.reason | dash) + "  " + (.scope | dash))
            ]
            | join("\n")
        ) + "\n"
    ' "${RUN_DIR}/client.json" "${RUN_DIR}/chain.json"
}

append_chain_half() {
    local dest="${RUN_DIR}/report.txt"
    local -a _pipe
    local jq_rc=0 write_rc=0
    if [[ ! -f "$dest" ]]; then
        die_infra "report.txt missing before chain-half append"
    fi
    set +e
    {
        cat -- "$dest"
        printf '\n'
        _render_chain_half
    } | _atomic_replace_stdin "$dest"
    _pipe=("${PIPESTATUS[@]}" 1)
    set -e
    jq_rc="${_pipe[0]}"
    write_rc="${_pipe[1]}"
    if [[ "$write_rc" -eq 2 ]]; then
        die_usage "refusing symlink report.txt: ${dest}"
    fi
    if [[ "$jq_rc" -ne 0 || "$write_rc" -ne 0 ]]; then
        die_infra "failed to append chain half to ${dest}"
    fi
    chmod 600 "$dest" || die_infra "failed to chmod ${dest}"
}

apply_report_exit() {
    if [[ "$S7_BLOCKED" != "pass" ]]; then
        die_health "K8 blocked > 0 or unreadable"
    fi
    if [[ "$S5A_PRESENCE" != "pass" ]]; then
        die_health "K family missing: ${MISSING_FAMILIES}"
    fi
    if [[ "$S5B_LIVENESS" != "pass" ]]; then
        die_health "S5b liveness failed: ${MISSING_LIVENESS}"
    fi
    if [[ "$PERF_MAPPED_EXIT" -eq 4 ]]; then
        die_kpi "validator_perf.py KPI threshold breach (exit 4)"
    fi
    if [[ "$PERF_MAPPED_EXIT" -eq 3 ]]; then
        die_health "validator_perf.py degraded (exit 3) under --strict"
    fi
}

print_report_plan() {
    log_info "report plan:"
    log_info "  run dir: ${RUN_DIR}"
    log_info "  validator_perf: ${VALIDATOR_PERF}"
    log_info "  devnet_report: ${DEVNET_REPORT}"
    if [[ ${#FAIL_UNDER_ARGS[@]} -gt 0 ]]; then
        log_info "  fail-under: ${FAIL_UNDER_ARGS[*]}"
    fi
    if [[ "$STRICT" == "1" ]]; then
        log_info "  strict: on"
    fi
}

main() {
    parse_report_flags "$@"
    require_chain_1337
    if [[ -z "${RUN_DIR:-}" ]]; then
        die_usage "--run-dir is required"
    fi
    resolve_run_dir >/dev/null
    require_cmd jq
    require_cmd python3
    unset MNEMONIC || true

    if [[ "$DRY_RUN" == "1" ]]; then
        print_report_plan
        log_success "dry-run complete"
        return 0
    fi

    validate_data_exists "rvc.json" "${RUN_DIR}/rvc.json" "attach-rvc.sh"
    validate_data_exists "run.json" "${RUN_DIR}/run.json" "run.sh"

    write_rvc_pubkeys
    run_chain_report
    run_client_report
    assert_no_blocked
    assert_s5a_presence
    assert_s5b_liveness
    append_chain_half
    write_verdict
    apply_report_exit

    if [[ ${#ANNOTATIONS[@]} -gt 0 ]]; then
        log_info "annotations: ${ANNOTATIONS[*]}"
    fi
    log_success "report ok"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
