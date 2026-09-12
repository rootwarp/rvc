#!/usr/bin/env bash
# Start geth + Lighthouse BN from generated genesis and assert an Electra head.

set -euo pipefail

# Process env wins over devnet.env (CHAIN_ID=1). Capture before common.sh
# sources the file, which would otherwise overwrite.
_OV_CHAIN_ID=0
_KEEP_CHAIN_ID=""
if [[ "${CHAIN_ID+x}" == "x" ]]; then
    _OV_CHAIN_ID=1
    _KEEP_CHAIN_ID="$CHAIN_ID"
fi

_CHAIN_STAGE_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_CHAIN_STAGE_DIR}/lib/common.sh"

if [[ "$_OV_CHAIN_ID" -eq 1 ]]; then
    CHAIN_ID="$_KEEP_CHAIN_ID"
    export CHAIN_ID
fi
unset _OV_CHAIN_ID _KEEP_CHAIN_ID

BEACON_TESTNET_DIR="${BEACON_TESTNET_DIR:-/genesis}"
_EL_GVR_REINIT=0

_require_uint() {
    local name="$1"
    local val="$2"
    case "$val" in
        '' | *[!0-9]*)
            die_usage "${name} must be a non-negative integer (got ${val:-empty})"
            ;;
    esac
}

_is_uint() {
    case "${1:-}" in
        '' | *[!0-9]*)
            return 1
            ;;
    esac
    return 0
}

_file_uid() {
    local path="$1"
    local uid=""
    if uid="$(stat -c '%u' -- "$path" 2>/dev/null)"; then
        printf '%s\n' "$uid"
        return 0
    fi
    if uid="$(stat -f '%u' -- "$path" 2>/dev/null)"; then
        printf '%s\n' "$uid"
        return 0
    fi
    return 1
}

_el_rpc_url() {
    printf 'http://127.0.0.1:%s' "${EL_RPC_PORT}"
}

_cl_base_url() {
    printf 'http://127.0.0.1:%s' "${CL_HTTP_PORT}"
}

_norm_fork() {
    local v="$1"
    v="$(printf '%s' "$v" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
    case "$v" in
        0x*)
            ;;
        *)
            v="0x${v}"
            ;;
    esac
    printf '%s' "$v"
}

_gvr_from_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        return 1
    fi
    tr -d '[:space:]' <"$path"
}

_normalize_gvr() {
    local s="$1"
    s="$(printf '%s' "$s" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
    s="${s#0x}"
    printf '%s' "$s"
}

_chain_wait_attempts() {
    local n="${CHAIN_WAIT_ATTEMPTS:-90}"
    _require_uint "CHAIN_WAIT_ATTEMPTS" "$n"
    printf '%s' "$n"
}

_chain_wait_sleep() {
    local n="${CHAIN_WAIT_SLEEP:-2}"
    _require_uint "CHAIN_WAIT_SLEEP" "$n"
    printf '%s' "$n"
}

_curl_body() {
    local body
    body="$("$CURL" -s --max-time 2 "$@" 2>/dev/null || true)"
    printf '%s' "$body"
}

_curl_http_code() {
    local code
    code="$("$CURL" -s --max-time 2 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true)"
    if ! _is_uint "$code"; then
        code="000"
    fi
    printf '%s' "$code"
}

_jq_raw() {
    local json="$1"
    local expr="$2"
    printf '%s' "$json" | jq -r "$expr" 2>/dev/null || true
}

_scrub_container_log() {
    local path="$1"
    if [[ ! -f "$path" || -L "$path" ]]; then
        return 0
    fi
    MNEMONIC="${MNEMONIC-}" python3 -c '
import os, re, sys
path = sys.argv[1]
try:
    text = open(path, "r", encoding="utf-8", errors="replace").read()
except OSError:
    raise SystemExit(0)
mnemo = os.environ.get("MNEMONIC") or ""
if mnemo:
    text = text.replace(mnemo, "<redacted>")
text = re.sub(r"0x[0-9a-fA-F]{64}", "0x<redacted>", text)
text = re.sub(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", "<redacted>", text)
fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
try:
    os.write(fd, text.encode("utf-8"))
finally:
    os.close(fd)
' "$path" || true
}

_fail_chain() {
    local log_dir
    capture_container_logs "$GETH_CONTAINER"
    capture_container_logs "$BEACON_CONTAINER"
    log_dir="$(resolve_run_dir)/logs"
    _scrub_container_log "${log_dir}/${GETH_CONTAINER}.log"
    _scrub_container_log "${log_dir}/${BEACON_CONTAINER}.log"
    die_infra "$@"
}

_truncate_inventory() {
    local inventory
    inventory="$(resolve_run_dir)/inventory.json"
    if [[ -L "$inventory" ]]; then
        die_usage "refusing symlink inventory: $inventory"
    fi
    if [[ -e "$inventory" && ! -f "$inventory" ]]; then
        die_usage "inventory is not a regular file: $inventory"
    fi
    : >"$inventory"
    chmod 0600 "$inventory"
}

_chmod_dir() {
    local path="$1"
    chmod 700 "$path" || die_infra "cannot chmod 700 ${path}"
}

_refuse_symlink() {
    local path="$1"
    local what="$2"
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink ${what}: ${path}"
    fi
}

_require_jwt() {
    local jwt="${JWT_DIR}/jwt.hex"
    local mode uid self
    _refuse_symlink "$JWT_DIR" "jwt dir"
    _refuse_symlink "$jwt" "jwt"
    validate_data_exists "JWT secret" "$jwt" "01-genesis.sh"
    if [[ ! -f "$jwt" ]]; then
        die_usage "jwt is not a regular file: ${jwt}"
    fi
    mode="$(_mode_octal "$jwt")" || die_infra "cannot stat jwt: ${jwt}"
    if [[ "$mode" != "600" ]]; then
        die_usage "jwt must be mode 0600 (got ${mode}): ${jwt}"
    fi
    uid="$(_file_uid "$jwt")" || die_infra "cannot stat jwt owner: ${jwt}"
    self="$(id -u)"
    if [[ "$uid" != "$self" ]]; then
        die_usage "jwt not owned by uid ${self} (got ${uid}): ${jwt}"
    fi
}

# Stamp genesis GVR into a datadir only when missing. A conflicting stamp
# without --force is a usage error so genesis_is_stale still sees it.
_stamp_gvr() {
    local dir="$1"
    local src dest genesis_gvr dest_gvr
    src="${GENESIS_DIR}/genesis_validators_root.txt"
    dest="${dir}/genesis_validators_root.txt"
    _refuse_symlink "$dir" "datadir"
    if [[ ! -f "$src" || ! -d "$dir" ]]; then
        return 0
    fi
    _refuse_symlink "$dest" "GVR stamp"
    genesis_gvr="$(_normalize_gvr "$(_gvr_from_file "$src")")"
    if [[ -f "$dest" ]]; then
        dest_gvr="$(_normalize_gvr "$(_gvr_from_file "$dest")")"
        if [[ "$dest_gvr" == "$genesis_gvr" ]]; then
            return 0
        fi
        if [[ "$FORCE" != "1" ]]; then
            die_usage "datadir GVR does not match genesis (${dir}); re-run with --force"
        fi
        if [[ "$dir" == "$EL_DATA_DIR" ]]; then
            _EL_GVR_REINIT=1
        fi
    fi
    cp -- "$src" "$dest"
}

_wipe_geth_chaindata() {
    local geth_dir="${EL_DATA_DIR}/geth"
    local chaindata="${geth_dir}/chaindata"
    _refuse_symlink "$EL_DATA_DIR" "EL datadir"
    _refuse_symlink "$geth_dir" "geth dir"
    _refuse_symlink "$chaindata" "geth chaindata"
    if [[ -d "$chaindata" ]]; then
        rm -rf -- "$chaindata"
    fi
}

_geth_needs_init() {
    if [[ "$_EL_GVR_REINIT" == "1" ]]; then
        _wipe_geth_chaindata
        return 0
    fi
    [[ ! -d "${EL_DATA_DIR}/geth/chaindata" ]]
}

print_chain_plan() {
    log_info "chain plan:"
    log_info "  1. start_geth"
    log_info "  2. start_beacon"
    log_info "  3. wait_for_chain"
    log_info "  4. assert_head_fork_electra"
}

start_geth() {
    local uid gid
    uid="$(id -u)"
    gid="$(id -g)"

    if is_container_running "$GETH_CONTAINER"; then
        log_info "geth already running"
        return 0
    fi

    inventory_append network "$DOCKER_NETWORK"
    ensure_docker_network

    inventory_append datadir el "$EL_DATA_DIR"
    mkdir -p -- "$EL_DATA_DIR"
    _chmod_dir "$EL_DATA_DIR"
    _stamp_gvr "$EL_DATA_DIR"

    if container_exists "$GETH_CONTAINER"; then
        remove_container "$GETH_CONTAINER"
    fi

    inventory_append container "$GETH_CONTAINER"

    if _geth_needs_init; then
        log_info "initializing geth genesis"
        if ! docker_run_as_user --rm \
            -v "${EL_DATA_DIR}:/data" \
            -v "${GENESIS_DIR}:/genesis:ro" \
            -- \
            "$IMG_GETH" \
            --datadir=/data \
            init /genesis/genesis.json >&2; then
            _fail_chain "geth init failed"
        fi
    fi

    log_info "starting geth"
    # Host publishes loopback-only HTTP. Engine API stays on the docker
    # network (BN uses eth-devnet-geth:8551); do not publish 8551.
    if ! docker_run_as_user -d \
        --name "$GETH_CONTAINER" \
        --network "$DOCKER_NETWORK" \
        --restart unless-stopped \
        -p "127.0.0.1:${EL_RPC_PORT}:8545" \
        -v "${EL_DATA_DIR}:/data" \
        -v "${GENESIS_DIR}:/genesis:ro" \
        -v "${JWT_DIR}:/jwt:ro" \
        -- \
        "$IMG_GETH" \
        --datadir=/data \
        --http \
        --http.addr=0.0.0.0 \
        --http.port=8545 \
        --http.api=eth,net,web3,debug,txpool \
        --http.corsdomain='*' \
        --http.vhosts='*' \
        --authrpc.addr=0.0.0.0 \
        --authrpc.port=8551 \
        --authrpc.vhosts='*' \
        --authrpc.jwtsecret=/jwt/jwt.hex \
        --networkid="${NETWORK_ID}" \
        --nodiscover \
        --syncmode=full \
        --gcmode=archive \
        --ipcdisable >/dev/null; then
        _fail_chain "failed to start ${GETH_CONTAINER}"
    fi
    log_success "geth started (uid ${uid}:${gid})"
}

start_beacon() {
    local testnet_dir="${BEACON_TESTNET_DIR}"

    if is_container_running "$BEACON_CONTAINER"; then
        log_info "beacon already running"
        return 0
    fi

    inventory_append datadir cl "$CL_DATA_DIR"
    mkdir -p -- "${CL_DATA_DIR}/beacon"
    _chmod_dir "$CL_DATA_DIR"
    _chmod_dir "${CL_DATA_DIR}/beacon"
    _stamp_gvr "$CL_DATA_DIR"

    if container_exists "$BEACON_CONTAINER"; then
        remove_container "$BEACON_CONTAINER"
    fi

    inventory_append container "$BEACON_CONTAINER"

    log_info "starting lighthouse beacon_node"
    if ! docker_run_as_user -d \
        --name "$BEACON_CONTAINER" \
        --network "$DOCKER_NETWORK" \
        --restart unless-stopped \
        -p "127.0.0.1:${CL_HTTP_PORT}:5052" \
        -p "127.0.0.1:${CL_METRICS_PORT}:5054" \
        -v "${CL_DATA_DIR}/beacon:/data" \
        -v "${GENESIS_DIR}:/genesis:ro" \
        -v "${JWT_DIR}:/jwt:ro" \
        -- \
        "$IMG_LIGHTHOUSE" \
        lighthouse \
        beacon_node \
        --datadir=/data \
        --testnet-dir="${testnet_dir}" \
        --execution-endpoint="http://${GETH_CONTAINER}:8551" \
        --execution-jwt=/jwt/jwt.hex \
        --http \
        --http-address=0.0.0.0 \
        --http-port=5052 \
        --http-allow-origin='*' \
        --metrics \
        --metrics-address=0.0.0.0 \
        --metrics-port=5054 \
        --disable-peer-scoring \
        --enable-private-discovery \
        --staking \
        --enr-address=127.0.0.1 \
        --enr-udp-port=9000 \
        --enr-tcp-port=9000 \
        --disable-packet-filter \
        --subscribe-all-subnets >/dev/null; then
        _fail_chain "failed to start ${BEACON_CONTAINER}"
    fi
    log_success "beacon started"
}

_wait_loop() {
    local label="$1"
    local attempts sleep_s attempt
    attempts="$(_chain_wait_attempts)"
    sleep_s="$(_chain_wait_sleep)"
    attempt=1
    log_info "waiting for ${label}..."
    while [[ "$attempt" -le "$attempts" ]]; do
        if "$2"; then
            log_success "${label} ready"
            return 0
        fi
        if [[ "$attempt" -lt "$attempts" ]]; then
            printf '%s' "." >&2
            if [[ "$sleep_s" -gt 0 ]]; then
                sleep "$sleep_s"
            fi
        fi
        attempt=$((attempt + 1))
    done
    printf '\n' >&2
    return 1
}

_el_chain_id_ready() {
    local body result
    body="$(_curl_body -X POST \
        -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
        -- "$(_el_rpc_url)")"
    result="$(_jq_raw "$body" '.result // empty')"
    [[ -n "$result" && "$result" != "null" ]]
}

_bn_health_ready() {
    local code
    code="$(_curl_http_code -- "$(_cl_base_url)/eth/v1/node/health")"
    [[ "$code" == "200" || "$code" == "206" ]]
}

# BN-only: canonical head_slot stays 0 without a VC. Gate on the BN clock
# (head_slot + sync_distance). Live path is health 206 + head_slot=0.
_head_slot_ready() {
    local body head_slot sync_distance current
    body="$(_curl_body -- "$(_cl_base_url)/eth/v1/node/syncing")"
    head_slot="$(_jq_raw "$body" '.data.head_slot // "0"')"
    sync_distance="$(_jq_raw "$body" '.data.sync_distance // "0"')"
    if ! _is_uint "$head_slot"; then
        head_slot=0
    fi
    if ! _is_uint "$sync_distance"; then
        sync_distance=0
    fi
    current=$((head_slot + sync_distance))
    [[ "$current" -gt 1 ]]
}

wait_for_chain() {
    if ! _wait_loop "EL eth_chainId" _el_chain_id_ready; then
        _fail_chain "EL eth_chainId did not respond"
    fi
    if ! _wait_loop "BN /eth/v1/node/health" _bn_health_ready; then
        _fail_chain "BN /eth/v1/node/health not in {200,206}"
    fi
    if ! _wait_loop "clock slot > 1" _head_slot_ready; then
        _fail_chain "clock slot (head_slot+sync_distance) did not advance past 1"
    fi
}

assert_head_fork_electra() {
    local spec_body fork_body seconds got want
    spec_body="$(_curl_body -- "$(_cl_base_url)/eth/v1/config/spec")"
    seconds="$(_jq_raw "$spec_body" '.data.SECONDS_PER_SLOT // empty')"
    if [[ "$seconds" != "12" ]]; then
        _fail_chain "SECONDS_PER_SLOT is ${seconds:-<empty>} (want 12)"
    fi
    fork_body="$(_curl_body -- "$(_cl_base_url)/eth/v1/beacon/states/head/fork")"
    got="$(_norm_fork "$(_jq_raw "$fork_body" '.data.current_version // empty')")"
    want="$(_norm_fork "${ELECTRA_FORK_VERSION}")"
    if [[ -z "$got" || "$got" == "0x" ]]; then
        _fail_chain "head current_version missing from /eth/v1/beacon/states/head/fork"
    fi
    if [[ "$got" != "$want" ]]; then
        _fail_chain "head current_version ${got} != ELECTRA_FORK_VERSION ${want}"
    fi
    log_success "head fork is Electra (${got}), SECONDS_PER_SLOT=12"
}

_validate_inputs() {
    if [[ -L "$DATA_DIR" ]]; then
        die_usage "refusing symlink purge root: ${DATA_DIR}"
    fi
    _refuse_symlink "$GENESIS_DIR" "genesis dir"
    _require_jwt
    validate_data_exists "EL genesis" "${GENESIS_DIR}/genesis.json" "01-genesis.sh"
    validate_data_exists "CL genesis" "${GENESIS_DIR}/genesis.ssz" "01-genesis.sh"
    validate_data_exists "CL config" "${GENESIS_DIR}/config.yaml" "01-genesis.sh"
}

main() {
    parse_common_flags "$@"
    require_chain_1337
    require_cmd jq
    resolve_run_dir >/dev/null
    _validate_inputs

    if [[ "$DRY_RUN" == "1" ]]; then
        print_chain_plan
        if is_container_running "$GETH_CONTAINER" && is_container_running "$BEACON_CONTAINER" && [[ "$FORCE" != "1" ]]; then
            log_info "would no-op (geth and beacon already running)"
        else
            log_info "would start ${GETH_CONTAINER} and ${BEACON_CONTAINER}"
        fi
        log_success "dry-run complete"
        return 0
    fi

    require_cmd "$DOCKER"
    require_cmd "$CURL"

    if [[ "$FORCE" == "1" ]]; then
        _truncate_inventory
        remove_container "$GETH_CONTAINER"
        remove_container "$BEACON_CONTAINER"
    elif is_container_running "$GETH_CONTAINER" && is_container_running "$BEACON_CONTAINER"; then
        log_success "geth and beacon already running"
        return 0
    fi

    start_geth
    start_beacon
    wait_for_chain
    assert_head_fork_electra
    log_success "chain ready"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
