#!/usr/bin/env bash
# Remove every resource inventory.json names; --data purges the data/ root.

set -euo pipefail

_DOWN_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_DOWN_DIR}/lib/common.sh"

PURGE_DATA="${PURGE_DATA:-0}"

parse_down_flags() {
    local -a rest
    rest=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --data)
                PURGE_DATA=1
                shift
                ;;
            *)
                rest+=("$1")
                shift
                ;;
        esac
    done
    export PURGE_DATA
    if [[ ${#rest[@]} -eq 0 ]]; then
        parse_common_flags
    else
        parse_common_flags "${rest[@]}"
    fi
}

_bind_run_dir() {
    if [[ -z "${RUN_DIR:-}" ]]; then
        RUN_DIR="${RUNS_DIR:-${SCRIPT_DIR}/runs}/standalone"
    fi
    export RUN_DIR
}

_inventory_path() {
    printf '%s' "${RUN_DIR}/inventory.json"
}

_has_inventory() {
    local p
    p="$(_inventory_path)"
    if [[ -L "$p" ]]; then
        return 1
    fi
    if [[ -f "$p" && -s "$p" ]]; then
        return 0
    fi
    return 1
}

_load_teardown_rows() {
    if _has_inventory; then
        inventory_rows "$(_inventory_path)"
        return 0
    fi
    log_info "no inventory.json; falling back to ${CONTAINER_PREFIX}-* name scan"
    inventory_name_scan
}

purge_data_dir() {
    local data runs pidfile
    if [[ "$PURGE_DATA" != "1" ]]; then
        return 0
    fi
    data="$(_canon_path "${DATA_DIR:-}")"
    runs="$(_canon_path "${RUNS_DIR:-}")"
    data="${data%/}"
    runs="${runs%/}"
    if [[ -z "$data" || "$data" == "/" ]]; then
        log_info "skip data dir: refusing empty or root path"
        return 0
    fi
    if [[ -n "$runs" && "$data" == "$runs" ]]; then
        log_info "skip data dir: refusing to purge RUNS_DIR"
        return 0
    fi
    if [[ -n "$runs" && "$runs" != "/" ]]; then
        case "$runs" in
            "$data" | "$data"/*)
                log_info "skip data dir: refusing to purge a tree that contains RUNS_DIR"
                return 0
                ;;
        esac
    fi
    if [[ ! -e "$data" ]]; then
        log_info "skip data dir: ${data} absent"
        return 0
    fi
    pidfile="${data}/rvc/rvc.pid"
    if [[ -f "$pidfile" && ! -L "$pidfile" ]]; then
        stop_rvc "$pidfile"
    fi
    log_info "purging data dir ${data}"
    rm -rf -- "$data" || true
}

main() {
    local rows row kind name path

    parse_down_flags "$@"
    unset MNEMONIC || true
    _bind_run_dir

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "down plan:"
        log_info "  inventory: $(_inventory_path)"
        if [[ "$PURGE_DATA" == "1" ]]; then
            log_info "  purge data dir: ${DATA_DIR}"
        fi
        log_success "dry-run complete"
        return 0
    fi

    rows="$(_load_teardown_rows || true)"
    while IFS= read -r row || [[ -n "${row:-}" ]]; do
        if [[ -z "${row:-}" ]]; then
            continue
        fi
        kind="$(printf '%s' "$row" | jq -r '.kind // empty' 2>/dev/null || true)"
        name="$(printf '%s' "$row" | jq -r '.name // empty' 2>/dev/null || true)"
        path="$(printf '%s' "$row" | jq -r '.path // empty' 2>/dev/null || true)"
        remove_resource "$kind" "$name" "$path" || true
    done <<< "$rows"

    purge_data_dir
    log_success "devnet down"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
