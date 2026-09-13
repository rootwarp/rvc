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
VALIDATOR_PERF="${VALIDATOR_PERF:-${SCRIPT_DIR}/../validator_perf.py}"
DEVNET_REPORT="${DEVNET_REPORT:-${SCRIPT_DIR}/../devnet_report.py}"

DATA_DIR="${DATA_DIR:-${SCRIPT_DIR}/data}"
RUNS_DIR="${RUNS_DIR:-${SCRIPT_DIR}/runs}"
JWT_DIR="${DATA_DIR}/jwt"
EL_DATA_DIR="${DATA_DIR}/el"
CL_DATA_DIR="${DATA_DIR}/cl"
GENESIS_DIR="${DATA_DIR}/genesis"
KEYS_DIR="${DATA_DIR}/keys"
RVC_DIR="${DATA_DIR}/rvc"

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
export DOCKER CURL DEVNET_STAGE_DIR VALIDATOR_PERF DEVNET_REPORT
export DATA_DIR RUNS_DIR
export JWT_DIR EL_DATA_DIR CL_DATA_DIR GENESIS_DIR KEYS_DIR RVC_DIR
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
    RVC_DIR="${DATA_DIR}/rvc"
    export FORCE INTERACTIVE DRY_RUN PROFILE RUN_DIR
    export DATA_DIR JWT_DIR EL_DATA_DIR CL_DATA_DIR GENESIS_DIR KEYS_DIR RVC_DIR
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

# Canonical absolute path (symlinks, .., Darwin /tmp → /private/tmp). Empty on failure.
_canon_path() {
    local path="${1:-}"
    local out=""
    if [[ -z "$path" ]]; then
        return 0
    fi
    out="$(
        PATH_TO_CANON="$path" python3 -c \
            'import os,sys; sys.stdout.write(os.path.realpath(os.environ["PATH_TO_CANON"])+"\n")' \
            2>/dev/null || true
    )"
    printf '%s\n' "$out"
}

# True iff canonical path is DATA_DIR or a descendant, and not under RUNS_DIR.
_is_under_data_dir() {
    local path data runs
    path="$(_canon_path "${1:-}")"
    data="$(_canon_path "${DATA_DIR:-}")"
    runs="$(_canon_path "${RUNS_DIR:-}")"
    path="${path%/}"
    data="${data%/}"
    runs="${runs%/}"
    if [[ -z "$path" || -z "$data" || "$data" == "/" ]]; then
        return 1
    fi
    case "$path" in
        "$data" | "$data"/*)
            ;;
        *)
            return 1
            ;;
    esac
    if [[ -n "$runs" && "$runs" != "/" ]]; then
        case "$path" in
            "$runs" | "$runs"/*)
                return 1
                ;;
        esac
    fi
    return 0
}

_is_devnet_container_name() {
    local name="${1:-}"
    case "$name" in
        "${CONTAINER_PREFIX}-"*)
            case "$name" in
                *[!A-Za-z0-9_.-]*)
                    return 1
                    ;;
            esac
            return 0
            ;;
    esac
    return 1
}

# Live process, not a zombie. kill -0 succeeds on zombies (macOS/Linux).
_pid_live() {
    local pid="${1:-}"
    local st
    case "$pid" in
        '' | *[!0-9]* | 0 | 1 | "$$")
            return 1
            ;;
    esac
    kill -0 "$pid" 2>/dev/null || return 1
    st="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
    st="$(printf '%s' "$st" | tr -d '[:space:]')"
    case "$st" in
        '' | Z*)
            return 1
            ;;
    esac
    return 0
}

_trim() {
    local s="${1-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

_pid_comm() {
    local pid="${1:-}"
    local comm
    comm="$(ps -p "$pid" -o comm= 2>/dev/null || true)"
    _trim "$comm"
}

_pid_args0() {
    local pid="${1:-}"
    local out
    out="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    if [[ -z "$(_trim "$out")" ]]; then
        out="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    fi
    out="$(_trim "$out")"
    out="${out%%[[:space:]]*}"
    printf '%s' "$out"
}

# Darwin comm= is often an absolute path; Linux is the 15-char basename.
_basename_is_rvc() {
    local s="${1:-}"
    s="${s##*/}"
    [[ "$s" == "rvc" ]]
}

_pid_is_rvc() {
    local pid="${1:-}"
    _basename_is_rvc "$(_pid_comm "$pid")" && return 0
    _basename_is_rvc "$(_pid_args0 "$pid")" && return 0
    return 1
}

# TERM, poll <= 10s, KILL. Stale (dead or comm/args basename != rvc): skip, no signal.
stop_rvc() {
    local pidfile="${1:-}"
    local pid="" comm="" end

    if [[ -z "$pidfile" ]]; then
        log_info "skip pid: empty pidfile path"
        return 0
    fi
    if [[ -L "$pidfile" ]]; then
        log_info "skip pid: refusing symlink ${pidfile}"
        return 0
    fi
    if ! _is_under_data_dir "$pidfile"; then
        log_info "skip pid: path outside data dir ${pidfile}"
        return 0
    fi
    if [[ ! -f "$pidfile" ]]; then
        log_info "skip pid: ${pidfile} absent"
        return 0
    fi

    pid="$(tr -d '[:space:]' <"$pidfile" 2>/dev/null || true)"
    case "$pid" in
        '' | *[!0-9]* | 0 | 1)
            log_info "skip pid: stale pidfile ${pidfile}"
            rm -f -- "$pidfile" || true
            return 0
            ;;
    esac

    if ! _pid_live "$pid"; then
        log_info "skip pid ${pid}: not running"
        rm -f -- "$pidfile" || true
        return 0
    fi

    comm="$(_pid_comm "$pid")"
    if ! _pid_is_rvc "$pid"; then
        log_info "skip pid ${pid}: comm=${comm:-unknown} is not rvc"
        rm -f -- "$pidfile" || true
        return 0
    fi

    log_info "stopping rvc pid ${pid}"
    kill -TERM "$pid" 2>/dev/null || true
    end=$((SECONDS + 10))
    while _pid_live "$pid" && ((SECONDS < end)); do
        sleep 1
    done
    if _pid_live "$pid"; then
        log_warn "rvc pid ${pid} still alive after TERM; sending KILL"
        kill -KILL "$pid" 2>/dev/null || true
        end=$((SECONDS + 2))
        while _pid_live "$pid" && ((SECONDS < end)); do
            sleep 1
        done
    fi
    if _pid_live "$pid"; then
        log_warn "rvc pid ${pid} still alive; leaving pidfile"
        return 0
    fi
    rm -f -- "$pidfile" || true
    return 0
}

_docker_has_container() {
    local name="${1:-}"
    local names ids
    if [[ -z "$name" ]]; then
        return 1
    fi
    names="$("$DOCKER" ps -a --format '{{.Names}}' 2>/dev/null || true)"
    if printf '%s\n' "$names" | grep -Fxq -- "$name"; then
        return 0
    fi
    ids="$("$DOCKER" ps -aq 2>/dev/null || true)"
    if printf '%s\n' "$ids" | grep -Fxq -- "$name"; then
        return 0
    fi
    return 1
}

_docker_has_network() {
    local name="${1:-}"
    local names
    if [[ -z "$name" ]]; then
        return 1
    fi
    names="$("$DOCKER" network ls --format '{{.Name}}' 2>/dev/null || true)"
    if printf '%s\n' "$names" | grep -Fxq -- "$name"; then
        return 0
    fi
    return 1
}

# NDJSON rows from runs/<id>/inventory.json, pid before slashing_db/datadir.
inventory_rows() {
    local inventory="${1:-}"
    local run_dir
    if [[ -z "$inventory" ]]; then
        run_dir="${RUN_DIR:-${RUNS_DIR}/standalone}"
        inventory="${run_dir}/inventory.json"
    fi
    if [[ -L "$inventory" || ! -f "$inventory" ]]; then
        return 0
    fi
    jq -s -c '
        def rank:
            {"pid":0,"container":1,"network":2,"slashing_db":3,"datadir":4}[.kind] // 5;
        to_entries
        | sort_by((.value | rank), -.key)
        | .[].value
    ' "$inventory" 2>/dev/null || true
}

# Fallback when no inventory exists: eth-devnet-* container names + the network.
inventory_name_scan() {
    local names
    names="$("$DOCKER" ps -a --filter "name=${CONTAINER_PREFIX}-" --format '{{.Names}}' 2>/dev/null || true)"
    printf '%s\n' "$names" | jq -R -c '
        gsub("\\s+";"") | select(length > 0) | {kind:"container",name:.}
    ' 2>/dev/null || true
    jq -nc --arg name "${DOCKER_NETWORK}" '{kind:"network",name:$name}' 2>/dev/null || true
}

# kinds: container|network|datadir|slashing_db|pid. Absent entries are skips.
remove_resource() {
    local kind="${1:-}"
    local name="${2:-}"
    local path="${3:-}"
    local data="" target=""

    case "$kind" in
        container)
            name="${name#/}"
            if [[ -z "$name" ]]; then
                log_info "skip container: empty name"
                return 0
            fi
            if ! _is_devnet_container_name "$name"; then
                log_info "skip container ${name}: not ${CONTAINER_PREFIX}-*"
                return 0
            fi
            if _docker_has_container "$name"; then
                log_info "removing container ${name}"
                "$DOCKER" rm -f -- "$name" >/dev/null 2>&1 || true
            else
                log_info "skip container ${name}: already absent"
            fi
            ;;
        network)
            if [[ -z "$name" ]]; then
                log_info "skip network: empty name"
                return 0
            fi
            if [[ "$name" != "$DOCKER_NETWORK" ]]; then
                log_info "skip network ${name}: not ${DOCKER_NETWORK}"
                return 0
            fi
            if _docker_has_network "$name"; then
                log_info "removing network ${name}"
                "$DOCKER" network rm -- "$name" >/dev/null 2>&1 || true
            else
                log_info "skip network ${name}: already absent"
            fi
            ;;
        datadir)
            if [[ -z "$path" ]]; then
                log_info "skip datadir ${name:-unknown}: no path"
                return 0
            fi
            if [[ -L "$path" ]]; then
                log_info "skip datadir ${name:-unknown}: refusing symlink ${path}"
                return 0
            fi
            if ! _is_under_data_dir "$path"; then
                log_info "skip datadir ${name:-unknown}: path outside data dir"
                return 0
            fi
            data="$(_canon_path "${DATA_DIR:-}")"
            target="$(_canon_path "$path")"
            data="${data%/}"
            target="${target%/}"
            if [[ -z "$target" || "$target" == "/" || "$target" == "$data" ]]; then
                log_info "skip datadir ${name:-unknown}: refusing data dir root"
                return 0
            fi
            if [[ ! -e "$target" ]]; then
                log_info "skip datadir ${name:-unknown}: already absent"
                return 0
            fi
            log_info "removing datadir ${name:-unknown} (${target})"
            rm -rf -- "$target" || true
            ;;
        slashing_db)
            if [[ -z "$path" ]]; then
                log_info "skip slashing_db ${name:-unknown}: no path"
                return 0
            fi
            if [[ -L "$path" ]]; then
                log_info "skip slashing_db ${name:-unknown}: refusing symlink ${path}"
                return 0
            fi
            if ! _is_under_data_dir "$path"; then
                log_info "skip slashing_db ${name:-unknown}: path outside data dir"
                return 0
            fi
            target="$(_canon_path "$path")"
            if [[ -z "$target" || "$target" == "/" ]]; then
                log_info "skip slashing_db ${name:-unknown}: path outside data dir"
                return 0
            fi
            if [[ ! -e "$target" && ! -e "${target}-wal" && ! -e "${target}-shm" ]]; then
                log_info "skip slashing_db ${name:-unknown}: already absent"
                return 0
            fi
            log_info "removing slashing_db ${name:-unknown} (${target})"
            rm -f -- "$target" "${target}-wal" "${target}-shm" || true
            ;;
        pid)
            if [[ -z "$path" ]]; then
                log_info "skip pid ${name:-unknown}: no pidfile path"
                return 0
            fi
            stop_rvc "$path"
            ;;
        *)
            log_info "skip unknown inventory kind: ${kind:-<empty>}"
            ;;
    esac
    return 0
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

# Token map for render_template. Indexed arrays are the portable source of
# truth; on bash >= 4 substitution is applied from an associative array.
RENDER_KEYS=()
RENDER_VALS=()

_render_reset() {
    RENDER_KEYS=()
    RENDER_VALS=()
}

_render_reject_unsafe_value() {
    local token="${1:-}"
    local value="${2-}"
    case "$value" in
        *$'\n'* | *$'\r'* | *@@*)
            die_usage "template value for ${token:-token} contains newline or @@"
            ;;
    esac
}

_render_set() {
    local token="${1:-}"
    local value="${2-}"
    if [[ -z "$token" ]]; then
        die_usage "_render_set requires a token"
    fi
    case "$token" in
        *[!A-Za-z0-9_]*)
            die_usage "invalid template token: ${token}"
            ;;
    esac
    _render_reject_unsafe_value "$token" "$value"
    RENDER_KEYS+=("$token")
    RENDER_VALS+=("$value")
}

# Replace @@TOKEN@@ in $_RENDER_CONTENT. ${var//a/b} cannot hold '/' in b on bash 3.2.
_render_apply() {
    local token="$1"
    local value="$2"
    local needle prefix suffix
    _render_reject_unsafe_value "$token" "$value"
    needle="@@${token}@@"
    prefix="${_RENDER_CONTENT%%"${needle}"*}"
    while [[ "$prefix" != "$_RENDER_CONTENT" ]]; do
        suffix="${_RENDER_CONTENT#*"${needle}"}"
        _RENDER_CONTENT="${prefix}${value}${suffix}"
        prefix="${_RENDER_CONTENT%%"${needle}"*}"
    done
}

_doppelganger_toml_bool() {
    case "${1:-}" in
        on | true | 1)
            printf 'true\n'
            ;;
        off | false | 0)
            printf 'false\n'
            ;;
        *)
            die_usage "DOPPELGANGER must be on or off (got ${1:-<empty>})"
            ;;
    esac
}

_assert_nonzero_fee_recipient() {
    local addr="${1:-}"
    local n
    n="$(printf '%s' "$addr" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
    n="${n#0x}"
    if [[ -z "$n" || ! "$n" =~ ^[0-9a-f]{40}$ ]]; then
        die_usage "DEV_ACCOUNT must be a 20-byte hex address (got ${addr:-<empty>})"
    fi
    if [[ "$n" == "0000000000000000000000000000000000000000" ]]; then
        die_usage "DEV_ACCOUNT fee_recipient must be non-zero (got ${addr})"
    fi
}

_assert_digit_port() {
    local name="${1:-}"
    local val="${2:-}"
    case "$val" in
        '' | *[!0-9]*)
            die_usage "${name} must be a port number (got ${val:-<empty>})"
            ;;
    esac
}

# O_NOFOLLOW atomic copy; refuses source, dest, and either parent symlink.
_copy_600() {
    local src="${1:-}"
    local dest="${2:-}"
    local src_parent dest_parent rc=0
    if [[ -z "$src" || -z "$dest" ]]; then
        die_usage "_copy_600 requires SRC and DEST"
    fi
    src_parent="$(dirname -- "$src")"
    dest_parent="$(dirname -- "$dest")"
    if [[ -L "$src" ]]; then
        die_usage "refusing symlink: ${src}"
    fi
    if [[ -L "$src_parent" ]]; then
        die_usage "refusing symlink: ${src_parent}"
    fi
    if [[ ! -f "$src" ]]; then
        die_usage "${src##*/} not found at ${src} (produced by 02-keys.sh)"
    fi
    if [[ -L "$dest_parent" ]]; then
        die_usage "refusing symlink: ${dest_parent}"
    fi
    if [[ -L "$dest" ]]; then
        die_usage "refusing symlink: ${dest}"
    fi
    python3 -c '
import os, stat, sys

src, dest = sys.argv[1], sys.argv[2]
nofollow = getattr(os, "O_NOFOLLOW", 0)

def fail_if_symlink(path, missing_ok=False):
    try:
        st = os.lstat(path)
    except OSError:
        if missing_ok:
            return
        raise SystemExit(1)
    if stat.S_ISLNK(st.st_mode):
        raise SystemExit(2)

fail_if_symlink(src)
src_dir = os.path.dirname(os.path.abspath(src))
fail_if_symlink(src_dir)
dest_dir = os.path.dirname(os.path.abspath(dest))
fail_if_symlink(dest_dir)
if not os.path.isdir(dest_dir):
    raise SystemExit(1)
fail_if_symlink(dest, missing_ok=True)

fin = os.open(src, os.O_RDONLY | nofollow)
try:
    chunks = []
    off = 0
    while True:
        buf = os.pread(fin, 1024 * 1024, off)
        if not buf:
            break
        chunks.append(buf)
        off += len(buf)
finally:
    os.close(fin)
data = b"".join(chunks)
if not data:
    raise SystemExit(1)

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
        raise SystemExit(2)
    os.replace(tmp, dest)
    tmp = ""
except OSError:
    raise SystemExit(1)
finally:
    if fd >= 0:
        os.close(fd)
    if tmp:
        try:
            os.unlink(tmp)
        except OSError:
            pass
' "$src" "$dest" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
        die_usage "refusing symlink: ${src} -> ${dest}"
    fi
    if [[ "$rc" -ne 0 ]]; then
        die_infra "failed to copy ${dest}"
    fi
    chmod 700 "$dest_parent" || die_infra "failed to chmod ${dest_parent}"
    chmod 600 "$dest" || die_infra "failed to chmod ${dest}"
}

_assert_password_keys_match_keystores() {
    local pw_file="${1:-}"
    local ks_dir="${2:-}"
    local rc=0
    if [[ -z "$pw_file" || -z "$ks_dir" ]]; then
        die_usage "_assert_password_keys_match_keystores requires PW_FILE and KS_DIR"
    fi
    PW_FILE="$pw_file" KS_DIR="$ks_dir" python3 - <<'PY' || rc=$?
import json, os, stat, sys

pw_file = os.environ["PW_FILE"]
ks_dir = os.environ["KS_DIR"]

def strip_one_0x(s: str) -> str:
    if s.startswith("0x") or s.startswith("0X"):
        return s[2:]
    return s

def is_reg(path: str) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)

pubkeys = []
try:
    names = os.listdir(ks_dir)
except OSError:
    sys.stderr.write("data/keys/rvc not found (produced by 02-keys.sh)\n")
    sys.exit(2)
for name in names:
    if not name.startswith("keystore-") or not name.endswith(".json"):
        continue
    path = os.path.join(ks_dir, name)
    if not is_reg(path):
        continue
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    pubkeys.append(doc.get("pubkey") or "")

keys = []
with open(pw_file, encoding="utf-8") as fh:
    for raw in fh:
        line = raw.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            sys.stderr.write("passwords.txt line missing '='\n")
            sys.exit(2)
        key = line.split("=", 1)[0]
        if key == "*":
            sys.stderr.write("refusing wildcard password entry\n")
            sys.exit(2)
        keys.append(key)

stripped = [strip_one_0x(k) for k in keys]
for key, s in zip(keys, stripped):
    n = sum(1 for pk in pubkeys if pk == s)
    if n != 1:
        sys.stderr.write(
            "password key does not match keystore .pubkey form (prefix/case)\n"
        )
        sys.exit(2)
for pk in pubkeys:
    n = sum(1 for s in stripped if s == pk)
    if n != 1:
        sys.stderr.write(
            "keystore .pubkey is not matched by exactly one passwords.txt key (prefix/case)\n"
        )
        sys.exit(2)
PY
    if [[ "$rc" -ne 0 ]]; then
        die_usage "password key does not match keystore .pubkey form (prefix/case)"
    fi
}

render_template() {
    local tmpl="${1:-}"
    local out="${2:-}"
    local leftover token value i
    if [[ -z "$tmpl" || -z "$out" ]]; then
        die_usage "render_template requires TMPL and OUT"
    fi
    if [[ -L "$tmpl" ]]; then
        die_usage "refusing symlink template: ${tmpl}"
    fi
    if [[ ! -f "$tmpl" ]]; then
        die_usage "template not found: ${tmpl}"
    fi
    if [[ -L "$out" ]]; then
        die_usage "refusing symlink output: ${out}"
    fi
    _RENDER_CONTENT="$(cat <"$tmpl" && printf x)"
    _RENDER_CONTENT="${_RENDER_CONTENT%x}"
    i=0
    if ((BASH_VERSINFO[0] >= 4)); then
        # shellcheck disable=SC2034,SC3045
        local -A subst=()
        while [[ "$i" -lt "${#RENDER_KEYS[@]}" ]]; do
            subst["${RENDER_KEYS[$i]}"]="${RENDER_VALS[$i]}"
            i=$((i + 1))
        done
        for token in "${!subst[@]}"; do
            _render_apply "$token" "${subst[$token]}"
        done
    else
        while [[ "$i" -lt "${#RENDER_KEYS[@]}" ]]; do
            token="${RENDER_KEYS[$i]}"
            value="${RENDER_VALS[$i]}"
            _render_apply "$token" "$value"
            i=$((i + 1))
        done
    fi
    leftover=""
    if printf '%s' "$_RENDER_CONTENT" | grep -q '@@'; then
        leftover="$(printf '%s' "$_RENDER_CONTENT" | grep -oE '@@[A-Za-z0-9_]+@@' | sort -u | tr '\n' ' ' || true)"
        leftover="${leftover% }"
        unset _RENDER_CONTENT
        die_usage "unsubstituted template token: ${leftover:-@@}"
    fi
    umask 077
    printf '%s' "$_RENDER_CONTENT" >"$out" || die_infra "failed to write ${out}"
    unset _RENDER_CONTENT
    chmod 600 "$out" || die_infra "failed to chmod ${out}"
}

render_rvc_config() {
    local genesis_json genesis_time genesis_validators_root
    local doppelganger_toml src_pw dest_pw config_out validators_out tmpl_dir
    local keystore_path password_file slashing_db_path validators_config beacon_url

    _assert_nonzero_fee_recipient "${DEV_ACCOUNT:-}"
    doppelganger_toml="$(_doppelganger_toml_bool "${DOPPELGANGER:-}")"
    _assert_digit_port "RVC_METRICS_PORT" "${RVC_METRICS_PORT:-}"

    validate_data_exists "manifest.json" "${KEYS_DIR}/manifest.json" "02-keys.sh"
    if [[ -L "${KEYS_DIR}/rvc" ]]; then
        die_usage "refusing symlink: ${KEYS_DIR}/rvc"
    fi
    if [[ ! -d "${KEYS_DIR}/rvc" ]]; then
        die_usage "data/keys/rvc not found at ${KEYS_DIR}/rvc (produced by 02-keys.sh)"
    fi
    validate_data_exists "passwords.txt" "${KEYS_DIR}/rvc/passwords.txt" "02-keys.sh"

    genesis_json="$(bn_genesis_json)"
    genesis_time="$(printf '%s\n' "$genesis_json" | parse_genesis_time)"
    genesis_validators_root="$(printf '%s\n' "$genesis_json" | parse_genesis_validators_root)"

    RVC_DIR="${DATA_DIR}/rvc"
    export RVC_DIR
    if [[ -L "$RVC_DIR" ]]; then
        die_usage "refusing symlink rvc dir: ${RVC_DIR}"
    fi

    src_pw="${KEYS_DIR}/rvc/passwords.txt"
    dest_pw="${RVC_DIR}/passwords.txt"
    keystore_path="${KEYS_DIR}/rvc"
    password_file="${RVC_DIR}/passwords.txt"
    slashing_db_path="${RVC_DIR}/slashing_protection.sqlite"
    validators_config="${RVC_DIR}/validators.toml"
    beacon_url="http://127.0.0.1:${CL_HTTP_PORT}"
    tmpl_dir="${SCRIPT_DIR}/config/templates"
    config_out="${RVC_DIR}/config.toml"
    validators_out="${RVC_DIR}/validators.toml"

    _render_reset
    _render_set BEACON_URL "$beacon_url"
    _render_set KEYSTORE_PATH "$keystore_path"
    _render_set PASSWORD_FILE "$password_file"
    _render_set SLASHING_DB_PATH "$slashing_db_path"
    _render_set NETWORK "custom"
    _render_set GENESIS_TIME "$genesis_time"
    _render_set GENESIS_VALIDATORS_ROOT "$genesis_validators_root"
    _render_set VALIDATORS_CONFIG "$validators_config"
    _render_set LOG_LEVEL "info"
    _render_set METRICS_PORT "${RVC_METRICS_PORT}"
    _render_set DOPPELGANGER_DETECTION "$doppelganger_toml"
    _render_set FEE_RECIPIENT "${DEV_ACCOUNT}"

    umask 077
    mkdir -p -- "$RVC_DIR" || die_infra "cannot create ${RVC_DIR}"
    if [[ -L "$RVC_DIR" ]]; then
        die_usage "refusing symlink rvc dir: ${RVC_DIR}"
    fi
    chmod 700 "$RVC_DIR" || die_infra "failed to chmod ${RVC_DIR}"

    _copy_600 "$src_pw" "$dest_pw"
    _assert_password_keys_match_keystores "$dest_pw" "${KEYS_DIR}/rvc"

    render_template "${tmpl_dir}/config.toml" "$config_out"
    render_template "${tmpl_dir}/validators.toml" "$validators_out"
    chmod 600 "$config_out" "$validators_out" "$dest_pw"
    log_info "rendered ${config_out}"
    log_info "rendered ${validators_out}"
}
