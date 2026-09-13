#!/usr/bin/env bash
# Chain-side report: validator_perf.py → chain.json, plus exit translation.

set -euo pipefail

_REPORT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_REPORT_DIR}/lib/common.sh"

STRICT="${STRICT:-0}"
FAIL_UNDER_ARGS=()
ANNOTATIONS=()

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
            return 0
            ;;
        4)
            die_kpi "validator_perf.py KPI threshold breach (exit 4)"
            ;;
        3)
            ANNOTATIONS+=("degraded")
            if [[ "$STRICT" == "1" ]]; then
                die_health "validator_perf.py degraded (exit 3) under --strict"
            fi
            log_warn "validator_perf.py degraded; annotating degraded"
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

print_report_plan() {
    log_info "report plan:"
    log_info "  run dir: ${RUN_DIR}"
    log_info "  validator_perf: ${VALIDATOR_PERF}"
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

    if [[ ${#ANNOTATIONS[@]} -gt 0 ]]; then
        log_info "annotations: ${ANNOTATIONS[*]}"
    fi
    log_success "report chain ok"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
