#!/usr/bin/env bash
# Hold the run N epochs behind per-slot health gates; capture the metric window.

set -euo pipefail

_SOAK_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_SOAK_DIR}/lib/common.sh"

SOAK_EPOCHS="${SOAK_EPOCHS:-}"
GATE_INTERVAL="${GATE_INTERVAL_SLOTS:-1}"
# validator_perf.py to_epoch ≤ head−2 (P6-A2); hold after sampling when offset > 0
_SOAK_END_CLAMP_EPOCHS=2
_SOAK_TRIPPED=0
_SOAK_TRIP_MSG=""
_K8_BASE=""

_require_nnint() {
    local name="$1"
    local val="$2"
    case "$val" in
        '' | *[!0-9]*)
            die_usage "${name} must be a non-negative integer (got ${val:-empty})"
            ;;
    esac
}

_slots_per_epoch() {
    local n="${SLOTS_PER_EPOCH:-32}"
    case "$n" in
        '' | *[!0-9]* | 0)
            die_usage "SLOTS_PER_EPOCH must be a positive integer (got ${n:-<empty>})"
            ;;
    esac
    printf '%s' "$n"
}

parse_soak_flags() {
    local -a rest
    rest=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --epochs)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--epochs requires a non-negative integer"
                fi
                SOAK_EPOCHS="$2"
                shift 2
                ;;
            --epochs=*)
                SOAK_EPOCHS="${1#--epochs=}"
                if [[ -z "$SOAK_EPOCHS" ]]; then
                    die_usage "--epochs requires a non-negative integer"
                fi
                shift
                ;;
            --gate-interval)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--gate-interval requires a non-negative integer"
                fi
                GATE_INTERVAL="$2"
                shift 2
                ;;
            --gate-interval=*)
                GATE_INTERVAL="${1#--gate-interval=}"
                if [[ -z "$GATE_INTERVAL" ]]; then
                    die_usage "--gate-interval requires a non-negative integer"
                fi
                shift
                ;;
            *)
                rest+=("$1")
                shift
                ;;
        esac
    done
    if [[ ${#rest[@]} -eq 0 ]]; then
        parse_common_flags
    else
        parse_common_flags "${rest[@]}"
    fi
}

_metrics_url() {
    printf '%s/metrics' "$(rvc_url)"
}

_soak_http_status() {
    local url="${1:-}"
    local timeout code
    timeout="${SCRAPE_TIMEOUT_S:-5}"
    code="$(_curl_hardened "$timeout" -o /dev/null -w '%{http_code}' -- "$url" 2>/dev/null || true)"
    case "$code" in
        '' | *[!0-9]*)
            code="000"
            ;;
    esac
    printf '%s' "$code"
}

_soak_truncate() {
    local path="${1:-}"
    local parent rc=0
    if [[ -z "$path" ]]; then
        die_usage "_soak_truncate requires a path"
    fi
    parent="$(dirname -- "$path")"
    if [[ -L "$parent" ]]; then
        die_usage "refusing symlink: ${parent}"
    fi
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink: ${path}"
    fi
    python3 -c '
import os, stat, sys

path = sys.argv[1]
nofollow = getattr(os, "O_NOFOLLOW", 0)
try:
    st = os.lstat(path)
except OSError:
    st = None
if st is not None and stat.S_ISLNK(st.st_mode):
    raise SystemExit(2)
if st is not None and not stat.S_ISREG(st.st_mode):
    raise SystemExit(1)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | nofollow, 0o600)
try:
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)
' "$path" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
        die_usage "refusing symlink: ${path}"
    fi
    if [[ "$rc" -ne 0 ]]; then
        die_infra "cannot create ${path}"
    fi
}

_require_rvc_json() {
    local path
    if [[ -z "${RUN_DIR:-}" ]]; then
        die_usage "rvc.json not found (produced by attach-rvc.sh)"
    fi
    resolve_run_dir >/dev/null
    path="${RUN_DIR}/rvc.json"
    if [[ -L "$path" ]]; then
        die_usage "rvc.json not found at ${path} (produced by attach-rvc.sh)"
    fi
    if [[ ! -f "$path" ]]; then
        die_usage "rvc.json not found at ${path} (produced by attach-rvc.sh)"
    fi
}

_scrape_raw() {
    local out="$1"
    local rc=0
    if [[ -L "$out" ]]; then
        die_usage "refusing symlink: ${out}"
    fi
    "$DEVNET_REPORT" scrape --url "$(_metrics_url)" --out "$out" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
        die_usage "devnet_report.py scrape usage error"
    fi
    if [[ "$rc" -ne 0 ]]; then
        log_warn "scrape failed for ${out##*/}; continuing"
        if [[ -L "$out" ]]; then
            die_usage "refusing symlink: ${out}"
        fi
        if [[ ! -e "$out" ]]; then
            _soak_truncate "$out"
        fi
        return 1
    fi
    return 0
}

_scrape_gauges() {
    local slot="$1"
    local samples="$2"
    local rc=0
    "$DEVNET_REPORT" scrape \
        --url "$(_metrics_url)" \
        --gauges-only \
        --slot "$slot" \
        --append "$samples" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
        die_usage "devnet_report.py scrape --gauges-only usage error"
    fi
    if [[ "$rc" -ne 0 ]]; then
        log_warn "scrape --gauges-only failed at slot ${slot}; skipping sample"
        return 1
    fi
    return 0
}

_check_gates() {
    local rvc_code bn_code k8_now
    rvc_code="$(_soak_http_status "$(rvc_url)/health")"
    if [[ "$rvc_code" != "200" ]]; then
        _SOAK_TRIP_MSG="RVC /health HTTP ${rvc_code}"
        return 1
    fi
    bn_code="$(_soak_http_status "$(bn_url)/eth/v1/node/health")"
    if [[ "$bn_code" != "200" && "$bn_code" != "206" ]]; then
        _SOAK_TRIP_MSG="BN /eth/v1/node/health HTTP ${bn_code}"
        return 1
    fi
    if ! k8_now="$(k8_blocked_total)"; then
        _SOAK_TRIP_MSG="K8 blocked metric unreadable"
        return 1
    fi
    if [[ -z "${_K8_BASE}" ]]; then
        _K8_BASE="$k8_now"
    elif [[ "$k8_now" -gt "$_K8_BASE" ]]; then
        _SOAK_TRIP_MSG="K8 blocked increased ${_K8_BASE} -> ${k8_now}"
        return 1
    fi
    return 0
}

print_soak_plan() {
    log_info "soak plan:"
    log_info "  run dir: ${RUN_DIR}"
    log_info "  epochs: ${SOAK_EPOCHS}"
    log_info "  soak start offset epochs: ${SOAK_START_OFFSET_EPOCHS:-0}"
    if [[ "${SOAK_START_OFFSET_EPOCHS:-0}" -gt 0 ]]; then
        log_info "  end clamp epochs: ${_SOAK_END_CLAMP_EPOCHS}"
    fi
    log_info "  gate interval: ${GATE_INTERVAL}"
    log_info "  1. scrape metrics-start.txt"
    log_info "  2. per-slot gates + samples.jsonl"
    log_info "  3. scrape metrics-end.txt"
}

_soak_gate_loop() {
    local slot="$1"
    local end_slot="$2"
    local step="$3"
    local do_sleep="$4"
    local sample="$5"
    local samples="$6"
    while [[ "$slot" -lt "$end_slot" ]]; do
        if [[ "$do_sleep" -eq 1 ]]; then
            sleep_until_slot "$slot"
        fi
        if ! _check_gates; then
            _SOAK_TRIPPED=1
            return 0
        fi
        if [[ "$sample" -eq 1 ]]; then
            _scrape_gauges "$slot" "$samples" || true
        fi
        slot=$((slot + step))
    done
}

main() {
    local start_slot step do_sleep samples spe total
    local offset offset_slots sample_start

    parse_soak_flags "$@"
    unset MNEMONIC || true
    require_chain_1337
    _require_rvc_json
    if [[ -n "${PROFILE:-}" ]]; then
        resolve_profile "$PROFILE"
        if [[ -z "${SOAK_EPOCHS}" ]]; then
            SOAK_EPOCHS="${EPOCHS}"
        else
            EPOCHS="${SOAK_EPOCHS}"
        fi
    fi
    if [[ -z "${SOAK_EPOCHS}" ]]; then
        die_usage "--epochs requires a non-negative integer"
    fi
    _require_nnint "--epochs" "$SOAK_EPOCHS"
    _require_nnint "--gate-interval" "$GATE_INTERVAL"
    offset="${SOAK_START_OFFSET_EPOCHS:-0}"
    _require_nnint "SOAK_START_OFFSET_EPOCHS" "$offset"
    SOAK_START_OFFSET_EPOCHS="$offset"
    EPOCHS="$SOAK_EPOCHS"
    export EPOCHS GATE_INTERVAL SOAK_START_OFFSET_EPOCHS

    if [[ "$DRY_RUN" == "1" ]]; then
        print_soak_plan
        log_success "dry-run complete"
        return 0
    fi

    if [[ ! -e "$DEVNET_REPORT" ]]; then
        die_usage "DEVNET_REPORT not found: ${DEVNET_REPORT}"
    fi
    require_cmd python3

    samples="${RUN_DIR}/samples.jsonl"
    _soak_truncate "$samples"
    _soak_truncate "${RUN_DIR}/metrics-start.txt"
    _soak_truncate "${RUN_DIR}/metrics-end.txt"

    # Offset 0 keeps the Phase-5 start scrape before the genesis clock so a
    # dead BN is still health 3 (not bn_get infra 1) with metrics-start present.
    if [[ "$offset" -eq 0 ]]; then
        _scrape_raw "${RUN_DIR}/metrics-start.txt" || true
    fi

    # DN-8 health before the BN genesis clock, so a dead BN is exit 3
    # with metrics-end.txt present rather than bn_get infra 1.
    if ! _check_gates; then
        _SOAK_TRIPPED=1
    fi

    spe="$(_slots_per_epoch)"
    total=$((SOAK_EPOCHS * spe))
    offset_slots=$((offset * spe))
    step="$GATE_INTERVAL"
    do_sleep=1
    if [[ "$step" -eq 0 ]]; then
        step=1
        do_sleep=0
    fi

    if [[ "$_SOAK_TRIPPED" -eq 0 ]]; then
        bn_genesis_time >/dev/null
        start_slot="$(current_slot)"
        sample_start="$start_slot"
        # Offset hold: DN-8 gates stay live; sampling and start scrape wait.
        if [[ "$offset_slots" -gt 0 ]]; then
            _soak_gate_loop "$start_slot" "$((start_slot + offset_slots))" \
                "$step" "$do_sleep" 0 "$samples"
            sample_start=$((start_slot + offset_slots))
            if [[ "$_SOAK_TRIPPED" -eq 0 ]]; then
                _scrape_raw "${RUN_DIR}/metrics-start.txt" || true
            fi
        fi
        if [[ "$_SOAK_TRIPPED" -eq 0 ]]; then
            _soak_gate_loop "$sample_start" "$((sample_start + total))" \
                "$step" "$do_sleep" 1 "$samples"
        fi
        # P6-A2: DN-8 gates stay live through validator_perf's head−2 clamp.
        if [[ "$_SOAK_TRIPPED" -eq 0 && "$offset_slots" -gt 0 ]]; then
            _soak_gate_loop "$((sample_start + total))" \
                "$((sample_start + total + _SOAK_END_CLAMP_EPOCHS * spe))" \
                "$step" "$do_sleep" 0 "$samples"
        fi
    fi

    _scrape_raw "${RUN_DIR}/metrics-end.txt" || true
    chmod 600 "${RUN_DIR}/metrics-start.txt" "${RUN_DIR}/metrics-end.txt" "$samples" || true

    if [[ "$_SOAK_TRIPPED" -eq 1 ]]; then
        die_health "${_SOAK_TRIP_MSG}"
    fi
    log_success "soak complete"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
