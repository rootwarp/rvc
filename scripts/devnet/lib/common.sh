#!/usr/bin/env bash
# Sourced by every scripts/devnet stage. Not executed directly.

set -euo pipefail

umask 077
unset CDPATH

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

log_info() {
    printf '%s\n' "${BLUE}[INFO]${NC} $*" >&2
}

log_success() {
    printf '%s\n' "${GREEN}[SUCCESS]${NC} $*" >&2
}

log_warn() {
    printf '%s\n' "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    printf '%s\n' "${RED}[ERROR]${NC} $*" >&2
}

_die() {
    local code="$1"
    shift
    log_error "$*"
    exit "$code"
}

die_infra() { _die 1 "$@"; }
die_usage() { _die 2 "$@"; }
die_health() { _die 3 "$@"; }
die_kpi() { _die 4 "$@"; }
die_notready() { _die 5 "$@"; }

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd -P)"

if [[ ! -f "${SCRIPT_DIR}/devnet.env" ]]; then
    die_usage "devnet.env not found at ${SCRIPT_DIR}/devnet.env"
fi
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/devnet.env"

DOCKER="${DOCKER:-docker}"
CURL="${CURL:-curl}"
DEVNET_STAGE_DIR="${DEVNET_STAGE_DIR:-$SCRIPT_DIR}"

DATA_DIR="${DATA_DIR:-${SCRIPT_DIR}/data}"
RUNS_DIR="${RUNS_DIR:-${SCRIPT_DIR}/runs}"
JWT_DIR="${DATA_DIR}/jwt"
EL_DATA_DIR="${DATA_DIR}/el"
CL_DATA_DIR="${DATA_DIR}/cl"
GENESIS_DIR="${DATA_DIR}/genesis"
KEYS_DIR="${DATA_DIR}/keys"

CONTAINER_PREFIX="eth-devnet"
GETH_CONTAINER="${CONTAINER_PREFIX}-geth"
BEACON_CONTAINER="${CONTAINER_PREFIX}-beacon"
VALIDATOR_CONTAINER="${CONTAINER_PREFIX}-validator"
DOCKER_NETWORK="${CONTAINER_PREFIX}-network"

FORCE="${FORCE:-0}"
INTERACTIVE="${INTERACTIVE:-0}"
DRY_RUN="${DRY_RUN:-0}"
PROFILE="${PROFILE:-}"
RUN_DIR="${RUN_DIR:-}"

export SCRIPT_DIR
export DOCKER CURL DEVNET_STAGE_DIR
export DATA_DIR RUNS_DIR
export JWT_DIR EL_DATA_DIR CL_DATA_DIR GENESIS_DIR KEYS_DIR
export CONTAINER_PREFIX GETH_CONTAINER BEACON_CONTAINER VALIDATOR_CONTAINER DOCKER_NETWORK
export FORCE INTERACTIVE DRY_RUN PROFILE RUN_DIR

_mode_octal() {
    local path="$1"
    local mode=""
    if mode="$(stat -c '%a' -- "$path" 2>/dev/null)"; then
        printf '%s\n' "$mode"
        return 0
    fi
    if mode="$(stat -f '%OLp' -- "$path" 2>/dev/null)"; then
        printf '%s\n' "$mode"
        return 0
    fi
    return 1
}

_is_world_writable() {
    local path="$1"
    local mode
    mode="$(_mode_octal "$path")" || die_infra "cannot stat ${path}"
    case "$mode" in
        *[!0-7]*)
            die_infra "unexpected mode for ${path}: ${mode}"
            ;;
    esac
    if ((8#$mode & 2)); then
        return 0
    fi
    return 1
}

_resolve_data_dir() {
    if [[ -z "${DATA_DIR:-}" ]]; then
        die_usage "--data-dir requires a path"
    fi
    if [[ -L "$DATA_DIR" ]]; then
        die_usage "refusing symlink data dir: ${DATA_DIR}"
    fi
    if [[ -e "$DATA_DIR" && ! -d "$DATA_DIR" ]]; then
        die_usage "data dir is not a directory: ${DATA_DIR}"
    fi
    mkdir -p -- "$DATA_DIR" || die_usage "cannot create data dir: ${DATA_DIR}"
    if [[ -L "$DATA_DIR" ]]; then
        die_usage "refusing symlink data dir: ${DATA_DIR}"
    fi
    if [[ ! -d "$DATA_DIR" ]]; then
        die_usage "data dir is not a directory: ${DATA_DIR}"
    fi
    if _is_world_writable "$DATA_DIR"; then
        die_usage "refusing world-writable data dir: ${DATA_DIR}"
    fi
    DATA_DIR="$(cd -P -- "$DATA_DIR" >/dev/null && pwd -P)" || die_usage "cannot resolve data dir: ${DATA_DIR}"
    export DATA_DIR
}

_require_docker_ident() {
    local name="${1:-}"
    local what="${2:-name}"
    case "$name" in
        "" | *[!A-Za-z0-9_.-]*)
            die_usage "invalid ${what}: ${name:-<empty>}"
            ;;
    esac
    case "$name" in
        [A-Za-z0-9]*)
            ;;
        *)
            die_usage "invalid ${what}: ${name}"
            ;;
    esac
}

parse_common_flags() {
    local data_dir_from_flag=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force)
                FORCE=1
                shift
                ;;
            --interactive)
                INTERACTIVE=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --run-dir)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--run-dir requires a path"
                fi
                RUN_DIR="$2"
                shift 2
                ;;
            --run-dir=*)
                RUN_DIR="${1#--run-dir=}"
                if [[ -z "$RUN_DIR" ]]; then
                    die_usage "--run-dir requires a path"
                fi
                shift
                ;;
            --data-dir)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--data-dir requires a path"
                fi
                DATA_DIR="$2"
                data_dir_from_flag=1
                shift 2
                ;;
            --data-dir=*)
                DATA_DIR="${1#--data-dir=}"
                if [[ -z "$DATA_DIR" ]]; then
                    die_usage "--data-dir requires a path"
                fi
                data_dir_from_flag=1
                shift
                ;;
            --profile)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--profile requires a value"
                fi
                PROFILE="$2"
                shift 2
                ;;
            --profile=*)
                PROFILE="${1#--profile=}"
                if [[ -z "$PROFILE" ]]; then
                    die_usage "--profile requires a value"
                fi
                shift
                ;;
            --)
                shift
                break
                ;;
            -*)
                die_usage "unknown flag: $1"
                ;;
            *)
                die_usage "unknown flag: $1"
                ;;
        esac
    done
    if [[ "$data_dir_from_flag" -eq 1 ]]; then
        _resolve_data_dir
    fi
    JWT_DIR="${DATA_DIR}/jwt"
    EL_DATA_DIR="${DATA_DIR}/el"
    CL_DATA_DIR="${DATA_DIR}/cl"
    GENESIS_DIR="${DATA_DIR}/genesis"
    KEYS_DIR="${DATA_DIR}/keys"
    export FORCE INTERACTIVE DRY_RUN PROFILE RUN_DIR
    export DATA_DIR JWT_DIR EL_DATA_DIR CL_DATA_DIR GENESIS_DIR KEYS_DIR
}

require_cmd() {
    local cmd="${1:-}"
    if [[ -z "$cmd" ]]; then
        die_usage "require_cmd requires a command name"
    fi
    if ! command -v "$cmd" >/dev/null 2>&1; then
        die_usage "required command not found: ${cmd}"
    fi
}

require_chain_1337() {
    if [[ "${CHAIN_ID:-}" != "1337" ]]; then
        die_usage "CHAIN_ID must be 1337 (got ${CHAIN_ID:-unset})"
    fi
}

resolve_run_dir() {
    if [[ -z "${RUN_DIR:-}" ]]; then
        RUN_DIR="${RUNS_DIR}/standalone"
    fi
    mkdir -p -- "$RUN_DIR"
    if [[ -L "$RUN_DIR" ]]; then
        die_usage "refusing symlink --run-dir: $RUN_DIR"
    fi
    if [[ ! -d "$RUN_DIR" ]]; then
        die_usage "run dir is not a directory: $RUN_DIR"
    fi
    if _is_world_writable "$RUN_DIR"; then
        die_usage "refusing world-writable --run-dir: $RUN_DIR"
    fi
    RUN_DIR="$(cd -P -- "$RUN_DIR" >/dev/null && pwd -P)"
    export RUN_DIR
    printf '%s\n' "$RUN_DIR"
}

resolve_profile() {
    local profile="${1:-${PROFILE:-}}"
    case "$profile" in
        fast)
            EPOCHS="${FAST_EPOCHS}"
            DOPPELGANGER="${FAST_DOPPELGANGER}"
            ;;
        safe)
            EPOCHS="${SAFE_EPOCHS}"
            DOPPELGANGER="${SAFE_DOPPELGANGER}"
            ;;
        *)
            die_usage "unknown profile: ${profile:-<empty>} (expected fast|safe)"
            ;;
    esac
    PROFILE="$profile"
    export PROFILE EPOCHS DOPPELGANGER
}

validate_data_exists() {
    local name="${1:-}"
    local path="${2:-}"
    local stage="${3:-}"
    if [[ -z "$name" || -z "$path" || -z "$stage" ]]; then
        die_usage "validate_data_exists requires NAME PATH STAGE"
    fi
    if [[ ! -e "$path" ]]; then
        die_usage "${name} not found at ${path} (produced by ${stage})"
    fi
}

is_container_running() {
    local container="${1:-}"
    local names
    names="$("$DOCKER" ps --format '{{.Names}}')" || return 1
    if printf '%s\n' "$names" | grep -Fxq -- "$container"; then
        return 0
    fi
    return 1
}

container_exists() {
    local container="${1:-}"
    local names
    names="$("$DOCKER" ps -a --format '{{.Names}}')" || return 1
    if printf '%s\n' "$names" | grep -Fxq -- "$container"; then
        return 0
    fi
    return 1
}

stop_container() {
    local container="${1:-}"
    if is_container_running "$container"; then
        log_info "Stopping container: $container"
        "$DOCKER" stop -- "$container" || true
    fi
}

remove_container() {
    local container="${1:-}"
    if container_exists "$container"; then
        log_info "Removing container: $container"
        "$DOCKER" rm -f -- "$container" || true
    fi
}

ensure_docker_network() {
    local names
    names="$("$DOCKER" network ls --format '{{.Name}}')" || names=""
    if printf '%s\n' "$names" | grep -Fxq -- "$DOCKER_NETWORK"; then
        return 0
    fi
    log_info "Creating Docker network: $DOCKER_NETWORK"
    "$DOCKER" network create "$DOCKER_NETWORK"
}

remove_docker_network() {
    local names
    names="$("$DOCKER" network ls --format '{{.Name}}')" || return 0
    if printf '%s\n' "$names" | grep -Fxq -- "$DOCKER_NETWORK"; then
        log_info "Removing Docker network: $DOCKER_NETWORK"
        "$DOCKER" network rm "$DOCKER_NETWORK" || true
    fi
}

wait_for_service() {
    local url="${1:-}"
    local max_attempts="${2:-30}"
    local attempt=1

    if [[ -z "$url" ]]; then
        die_usage "wait_for_service requires a URL"
    fi
    case "$max_attempts" in
        '' | *[!0-9]*)
            die_usage "wait_for_service max_attempts must be a non-negative integer"
            ;;
    esac

    log_info "Waiting for service at $url..."
    while [[ "$attempt" -le "$max_attempts" ]]; do
        if "$CURL" -sS --fail --max-time 2 -- "$url" >/dev/null 2>&1; then
            log_success "Service is ready"
            return 0
        fi
        if [[ "$attempt" -lt "$max_attempts" ]]; then
            printf '%s' "." >&2
            sleep 2
        fi
        attempt=$((attempt + 1))
    done
    printf '\n' >&2
    log_error "Service did not become ready after $max_attempts attempts"
    return 1
}

docker_run_as_user() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            -u* | --user | --user=*)
                die_usage "docker_run_as_user: -u/--user is not allowed"
                ;;
        esac
    done
    "$DOCKER" run -u "$(id -u):$(id -g)" "$@"
}

inventory_append() {
    local kind="${1:-}"
    local name="${2:-}"
    local path="${3:-}"
    local run_dir inventory row

    if [[ -z "$kind" || -z "$name" ]]; then
        die_usage "inventory_append requires KIND and NAME"
    fi

    run_dir="$(resolve_run_dir)"
    inventory="${run_dir}/inventory.json"

    if [[ -n "$path" ]]; then
        row="$(jq -nc --arg kind "$kind" --arg name "$name" --arg path "$path" \
            '{kind:$kind,name:$name,path:$path}')"
    else
        row="$(jq -nc --arg kind "$kind" --arg name "$name" \
            '{kind:$kind,name:$name}')"
    fi

    if [[ -L "$inventory" ]]; then
        die_usage "refusing symlink inventory: $inventory"
    fi
    if [[ ! -e "$inventory" ]]; then
        : >"$inventory"
    fi
    if [[ -L "$inventory" ]]; then
        die_usage "refusing symlink inventory: $inventory"
    fi
    if [[ ! -f "$inventory" ]]; then
        die_usage "inventory is not a regular file: $inventory"
    fi
    chmod 0600 "$inventory"
    printf '%s\n' "$row" >>"$inventory"
}

capture_container_logs() {
    local name="${1:-}"
    local log_dir

    _require_docker_ident "$name" "container name"

    log_dir="$(resolve_run_dir)/logs"
    mkdir -p -- "$log_dir"
    "$DOCKER" logs -- "$name" >"${log_dir}/${name}.log" 2>&1 || true
}

# BN HTTP GET. Parsers and asserts below do not call curl (ADR-013).
bn_get() {
    local path="${1:-}"
    local port="${CL_HTTP_PORT:-}"
    if [[ -z "$path" ]]; then
        die_usage "bn_get requires a path"
    fi
    case "$path" in
        /eth/v1/*) ;;
        *)
            die_usage "bn_get path must start with /eth/v1/"
            ;;
    esac
    case "$path" in
        *..*)
            die_usage "bn_get path must not contain .."
            ;;
        *[!A-Za-z0-9/_.-]*)
            die_usage "bn_get path contains invalid characters"
            ;;
    esac
    if [[ -z "$port" ]]; then
        die_usage "CL_HTTP_PORT is not set"
    fi
    case "$port" in
        *@*)
            die_usage "CL_HTTP_PORT must not contain @"
            ;;
        *[!0-9]*)
            die_usage "CL_HTTP_PORT must be a port number"
            ;;
    esac
    "$CURL" -sS --fail --max-time 5 -g --proto '=http' --path-as-is -- \
        "http://127.0.0.1:${port}${path}" \
        || die_infra "BN GET ${path} failed"
}

bn_genesis_json() {
    bn_get /eth/v1/beacon/genesis
}

bn_spec_json() {
    bn_get /eth/v1/config/spec
}

bn_head_fork_version() {
    local v
    v="$(bn_get /eth/v1/beacon/states/head/fork \
        | jq -r '.data.current_version // empty' \
        | tr -d '[:space:]')" \
        || die_infra "failed to parse BN head current_version"
    if [[ -z "$v" || "$v" == "null" ]]; then
        die_infra "current_version missing from BN head fork"
    fi
    printf '%s\n' "$v"
}

# Pure stdin/jq. Genesis facts never come from devnet.env (ADR-013).
parse_genesis_time() {
    local v
    v="$(jq -r '.data.genesis_time // empty' | tr -d '[:space:]')" \
        || die_infra "failed to parse genesis_time from BN genesis JSON"
    if [[ -z "$v" || "$v" == "null" ]]; then
        die_infra "genesis_time missing from BN genesis JSON"
    fi
    case "$v" in
        *[!0-9]*)
            die_infra "genesis_time is not an integer: ${v}"
            ;;
    esac
    printf '%s\n' "$v"
}

parse_genesis_validators_root() {
    local v
    v="$(jq -r '.data.genesis_validators_root // empty' | tr -d '[:space:]')" \
        || die_infra "failed to parse genesis_validators_root from BN genesis JSON"
    if [[ -z "$v" || "$v" == "null" ]]; then
        die_infra "genesis_validators_root missing from BN genesis JSON"
    fi
    if [[ ! "$v" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
        die_infra "genesis_validators_root is not a 32-byte 0x value: ${v}"
    fi
    printf '%s\n' "$v"
}

_is_hex0x() {
    [[ "${1:-}" =~ ^0x[0-9a-fA-F]+$ ]]
}

parse_fork_versions() {
    local out
    out="$(jq -r '
        (.data // {})
        | to_entries[]
        | select(.key | test("_FORK_VERSION$"))
        | (.value | tostring | gsub("\\s+";""))
        | if test("^0x[0-9a-fA-F]+$") then .
          else error("invalid fork version: \(.)")
          end
    ')" || die_infra "failed to parse fork versions from BN spec JSON"
    if [[ -n "$out" ]]; then
        printf '%s\n' "$out"
    fi
}

assert_fork_in_schedule() {
    local head="${1:-}"
    local head_n ver ver_n schedule restore_glob=0
    if [[ -z "$head" ]]; then
        die_usage "assert_fork_in_schedule requires a head fork version"
    fi
    shift
    case "$-" in
        *f*) ;;
        *)
            restore_glob=1
            set -f
            ;;
    esac
    if ! _is_hex0x "$head"; then
        die_usage "head current_version is not a 0x hex fork version: ${head}"
    fi
    head_n="$(printf '%s' "$head" | tr 'A-F' 'a-f')"
    for ver in "$@"; do
        if ! _is_hex0x "$ver"; then
            die_usage "fork schedule entry is not a 0x hex fork version: ${ver}"
        fi
        ver_n="$(printf '%s' "$ver" | tr 'A-F' 'a-f')"
        if [[ "$head_n" == "$ver_n" ]]; then
            if [[ "$restore_glob" -eq 1 ]]; then
                set +f
            fi
            return 0
        fi
    done
    schedule="$(printf '%s ' "$@")"
    schedule="${schedule% }"
    die_usage "head current_version ${head} is not in fork schedule: ${schedule:-<empty>}"
}

assert_gvr_matches_local() {
    local bn_gvr="${1:-}"
    local path local_gvr bn_n local_n
    if [[ -z "$bn_gvr" ]]; then
        die_usage "assert_gvr_matches_local requires a genesis_validators_root"
    fi
    path="${GENESIS_DIR}/genesis_validators_root.txt"
    if [[ ! -f "$path" ]]; then
        die_infra "genesis_validators_root.txt not found at ${path}; run 01-genesis.sh --force"
    fi
    local_gvr="$(tr -d '[:space:]' <"$path")"
    bn_n="$(printf '%s' "$bn_gvr" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
    bn_n="${bn_n#0x}"
    local_n="$(printf '%s' "$local_gvr" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
    local_n="${local_n#0x}"
    if [[ "$bn_n" != "$local_n" ]]; then
        die_infra "BN genesis_validators_root ${bn_gvr} does not match local ${local_gvr} at ${path}; run 01-genesis.sh --force"
    fi
}
