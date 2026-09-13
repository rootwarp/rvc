#!/usr/bin/env bash
# Start geth + Lighthouse BN + Lighthouse VC from generated genesis.

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
# Preserve an explicit VC_KEYS_SRC override; default after parse from KEYS_DIR.
_VC_KEYS_SRC_OVERRIDE="${VC_KEYS_SRC:-}"
_EL_GVR_REINIT=0

_bind_chain_paths() {
    if [[ -n "$_VC_KEYS_SRC_OVERRIDE" ]]; then
        VC_KEYS_SRC="$_VC_KEYS_SRC_OVERRIDE"
    else
        VC_KEYS_SRC="${KEYS_DIR}/vc"
    fi
    VALIDATOR_DATA_DIR="${CL_DATA_DIR}/validator"
}

_bind_chain_paths

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
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink container log: ${path}"
    fi
    if [[ ! -e "$path" ]]; then
        return 0
    fi
    if [[ ! -f "$path" ]]; then
        die_infra "container log is not a regular file: ${path}"
    fi
    MNEMONIC="${MNEMONIC-}" \
        VC_SCRUB_SECRET_DIRS="${VALIDATOR_DATA_DIR}/secrets:${VC_KEYS_SRC}/secrets" \
        python3 -c '
import os, re, stat, sys
path = sys.argv[1]
try:
    st = os.lstat(path)
except OSError as exc:
    raise SystemExit("cannot stat log: %s" % exc)
if stat.S_ISLNK(st.st_mode):
    raise SystemExit("symlink log")
if not stat.S_ISREG(st.st_mode):
    raise SystemExit("log is not a regular file")
try:
    text = open(path, "r", encoding="utf-8", errors="replace").read()
except OSError as exc:
    raise SystemExit("cannot read log: %s" % exc)
mnemo = os.environ.get("MNEMONIC") or ""
if mnemo:
    text = text.replace(mnemo, "<redacted>")
for d in (os.environ.get("VC_SCRUB_SECRET_DIRS") or "").split(":"):
    if not d or not os.path.isdir(d) or os.path.islink(d):
        continue
    try:
        names = os.listdir(d)
    except OSError:
        continue
    for name in names:
        p = os.path.join(d, name)
        try:
            pst = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISLNK(pst.st_mode) or not stat.S_ISREG(pst.st_mode):
            continue
        try:
            body = open(p, "r", encoding="utf-8", errors="replace").read().strip()
        except OSError:
            continue
        if len(body) >= 4:
            text = text.replace(body, "<redacted>")
text = re.sub(r"0x[0-9a-fA-F]{64}", "0x<redacted>", text)
text = re.sub(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", "<redacted>", text)
text = re.sub(r"(?i)(password[\s:=]+)[^\s,;]+", r"\1<redacted>", text)
text = re.sub(
    r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_=-])",
    "<redacted>",
    text,
)
fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
try:
    os.write(fd, text.encode("utf-8"))
finally:
    os.close(fd)
' "$path" || die_infra "failed to scrub container log: ${path}"
}

_fail_chain() {
    local log_dir path name
    log_dir="$(resolve_run_dir)/logs"
    mkdir -p -- "$log_dir"
    _refuse_symlink "$log_dir" "log dir"
    for name in "$GETH_CONTAINER" "$BEACON_CONTAINER" "$VALIDATOR_CONTAINER"; do
        path="${log_dir}/${name}.log"
        _refuse_symlink "$path" "container log"
    done
    capture_container_logs "$GETH_CONTAINER"
    capture_container_logs "$BEACON_CONTAINER"
    capture_container_logs "$VALIDATOR_CONTAINER"
    _scrub_container_log "${log_dir}/${GETH_CONTAINER}.log"
    _scrub_container_log "${log_dir}/${BEACON_CONTAINER}.log"
    _scrub_container_log "${log_dir}/${VALIDATOR_CONTAINER}.log"
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

_normalize_pubkey() {
    local pk="${1-}"
    pk="${pk#0x}"
    pk="${pk#0X}"
    printf '%s\n' "$pk" | tr '[:upper:]' '[:lower:]'
}

# Walk dirname(path) up through VALIDATOR_DATA_DIR; each component must not be a symlink.
_refuse_symlink_parents() {
    local path="$1"
    local what="$2"
    local root="${VALIDATOR_DATA_DIR:-}"
    local cur next
    if [[ -z "$root" ]]; then
        die_infra "VC datadir unset"
    fi
    cur="$(dirname -- "$path")"
    while true; do
        _refuse_symlink "$cur" "${what} parent"
        if [[ "$cur" == "$root" ]]; then
            return 0
        fi
        next="$(dirname -- "$cur")"
        if [[ "$next" == "$cur" ]]; then
            die_usage "refusing dest outside VC datadir: ${path}"
        fi
        cur="$next"
    done
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

_all_chain_running() {
    is_container_running "$GETH_CONTAINER" \
        && is_container_running "$BEACON_CONTAINER" \
        && is_container_running "$VALIDATOR_CONTAINER"
}

_require_fee_recipient() {
    local a hex
    a="${DEV_ACCOUNT:-}"
    a="$(printf '%s' "$a" | tr -d '[:space:]')"
    case "$a" in
        0x[0-9a-fA-F]*)
            ;;
        *)
            die_usage "DEV_ACCOUNT must be a non-zero 0x-prefixed address"
            ;;
    esac
    hex="${a#0x}"
    hex="$(printf '%s' "$hex" | tr 'A-F' 'a-f')"
    case "$hex" in
        "" | *[!0-9a-f]*)
            die_usage "DEV_ACCOUNT must be a non-zero 0x-prefixed address"
            ;;
    esac
    if [[ "${#hex}" -ne 40 ]]; then
        die_usage "DEV_ACCOUNT must be a 20-byte address (got ${#hex} hex chars)"
    fi
    if [[ "$hex" =~ ^0+$ ]]; then
        die_usage "DEV_ACCOUNT must be a non-zero address"
    fi
}

_vc_source_count() {
    local dir="${VC_KEYS_SRC}/validators"
    local n=0 p
    if [[ ! -d "$dir" || -L "$dir" ]]; then
        printf '0'
        return 0
    fi
    shopt -s nullglob
    for p in "$dir"/0x*; do
        if [[ -d "$p" && ! -L "$p" && -f "${p}/voting-keystore.json" && ! -L "${p}/voting-keystore.json" ]]; then
            n=$((n + 1))
        fi
    done
    shopt -u nullglob
    printf '%s' "$n"
}

# VC subset is [0, N-K); RVC takes the tail of K keys.
_require_split_bounds() {
    _require_uint "NUM_VALIDATORS" "${NUM_VALIDATORS:-}"
    _require_uint "RVC_KEYS" "${RVC_KEYS:-}"
    if [[ "$NUM_VALIDATORS" -lt 1 ]]; then
        die_usage "NUM_VALIDATORS must be a positive integer (got ${NUM_VALIDATORS})"
    fi
    if [[ "$RVC_KEYS" -lt 1 ]]; then
        die_usage "RVC_KEYS must be a positive integer (got ${RVC_KEYS})"
    fi
    if [[ "$RVC_KEYS" -ge "$NUM_VALIDATORS" ]]; then
        die_usage "RVC_KEYS must be < NUM_VALIDATORS (got ${RVC_KEYS} >= ${NUM_VALIDATORS})"
    fi
}

_vc_expected_count() {
    printf '%s' "$((NUM_VALIDATORS - RVC_KEYS))"
}

print_chain_plan() {
    log_info "chain plan:"
    log_info "  1. start_geth"
    log_info "  2. start_beacon"
    log_info "  3. wait_for_chain"
    log_info "  4. assert_head_fork_electra"
    log_info "  5. copy_vc_keys"
    log_info "  6. start_vc"
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

_install_regular_file() {
    local src="$1"
    local dest="$2"
    local rc=0
    if [[ -z "${VALIDATOR_DATA_DIR:-}" ]]; then
        die_infra "VC datadir unset"
    fi
    _refuse_symlink_parents "$dest" "install dest"
    python3 -c '
import os, stat, sys
src, dest, root = sys.argv[1], sys.argv[2], sys.argv[3]
nofollow = getattr(os, "O_NOFOLLOW", 0)

def check(path, missing_ok=False, want_dir=False):
    try:
        st = os.lstat(path)
    except OSError:
        if missing_ok:
            return
        raise SystemExit(1)
    if stat.S_ISLNK(st.st_mode):
        raise SystemExit(2)
    if want_dir:
        if not stat.S_ISDIR(st.st_mode):
            raise SystemExit(1)
        return
    if not stat.S_ISREG(st.st_mode):
        raise SystemExit(1)

src = os.path.abspath(src)
dest = os.path.abspath(dest)
root = os.path.abspath(root)
sep = os.sep
if dest != root and not dest.startswith(root + sep):
    raise SystemExit(1)

check(src)
check(dest, missing_ok=True)
cur = os.path.dirname(dest)
while True:
    check(cur, want_dir=True)
    if cur == root:
        break
    nxt = os.path.dirname(cur)
    if nxt == cur:
        raise SystemExit(1)
    cur = nxt
fin = os.open(src, os.O_RDONLY | nofollow)
try:
    chunks = []
    while True:
        buf = os.read(fin, 1024 * 1024)
        if not buf:
            break
        chunks.append(buf)
finally:
    os.close(fin)
fout = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | nofollow, 0o600)
try:
    os.write(fout, b"".join(chunks))
    os.fchmod(fout, 0o600)
finally:
    os.close(fout)
' "$src" "$dest" "$VALIDATOR_DATA_DIR" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
        die_usage "refusing symlink file: ${src} -> ${dest}"
    fi
    if [[ "$rc" -ne 0 ]]; then
        die_infra "failed to install ${dest}"
    fi
}

_ensure_dir() {
    local path="$1"
    local what="$2"
    if [[ -e "$path" ]]; then
        _refuse_symlink "$path" "$what"
        if [[ ! -d "$path" ]]; then
            die_infra "${what} is not a directory: ${path}"
        fi
    else
        mkdir -p -- "$path"
    fi
    _chmod_dir "$path"
}

# --force only: drop the VC datadir (definitions + slashing DB) before recopy (K-A10).
_reset_vc_datadir() {
    local dest="$VALIDATOR_DATA_DIR"
    _refuse_symlink "$CL_DATA_DIR" "CL datadir"
    _refuse_symlink "$dest" "VC datadir"
    if [[ -z "$dest" || "$dest" == "/" || "$dest" == "$CL_DATA_DIR" ]]; then
        die_infra "refusing to wipe empty VC datadir"
    fi
    if [[ -e "$dest" && ! -d "$dest" ]]; then
        die_infra "VC datadir is not a directory: ${dest}"
    fi
    if [[ -d "$dest" ]]; then
        _refuse_symlink "${dest}/validators" "VC validators"
        _refuse_symlink "${dest}/secrets" "VC secrets"
        _refuse_symlink "${dest}/validators/validator_definitions.yml" "validator definitions"
        _refuse_symlink "${dest}/validators/slashing_protection.sqlite" "slashing protection db"
        _refuse_symlink "${dest}/slashing_protection.sqlite" "slashing protection db"
        rm -rf -- "$dest"
    fi
}

_vc_slashing_db() {
    printf '%s' "${VALIDATOR_DATA_DIR}/validators/slashing_protection.sqlite"
}

# Leftover definitions or sqlite sidecars mean this datadir already signed.
_vc_slashing_history_present() {
    local dest_val db defs
    dest_val="${VALIDATOR_DATA_DIR}/validators"
    db="$(_vc_slashing_db)"
    defs="${dest_val}/validator_definitions.yml"
    _refuse_symlink "$defs" "validator definitions"
    _refuse_symlink "${db}-wal" "slashing protection wal"
    _refuse_symlink "${db}-journal" "slashing protection journal"
    [[ -e "$defs" || -e "${db}-wal" || -e "${db}-journal" ]]
}

_rvc_pubkeys_file() {
    printf '%s' "${KEYS_DIR}/rvc/pubkeys.txt"
}

_die_rvc_in_vc_datadir() {
    die_usage "VC datadir contains RVC pubkeys from $(_rvc_pubkeys_file); re-run with --force"
}

# True if dest validators/secrets/defs mention a pubkey from rvc/pubkeys.txt.
_vc_datadir_contains_rvc() {
    local dest_val dest_sec defs f pk norm
    dest_val="${VALIDATOR_DATA_DIR}/validators"
    dest_sec="${VALIDATOR_DATA_DIR}/secrets"
    defs="${dest_val}/validator_definitions.yml"
    f="$(_rvc_pubkeys_file)"
    if [[ -L "$f" ]]; then
        die_usage "refusing symlink rvc pubkeys: ${f}"
    fi
    if [[ ! -f "$f" ]]; then
        return 1
    fi
    _refuse_symlink "$dest_val" "VC validators"
    _refuse_symlink "$dest_sec" "VC secrets"
    _refuse_symlink "$defs" "validator definitions"
    while IFS= read -r pk || [[ -n "$pk" ]]; do
        [[ -n "$pk" ]] || continue
        norm="$(_normalize_pubkey "$pk")"
        case "$norm" in
            *[!0-9a-f]* | "")
                continue
                ;;
        esac
        if [[ "${#norm}" -ne 96 ]]; then
            continue
        fi
        if [[ -e "${dest_val}/0x${norm}" || -L "${dest_val}/0x${norm}" ]]; then
            return 0
        fi
        if [[ -e "${dest_sec}/0x${norm}" || -L "${dest_sec}/0x${norm}" ]]; then
            return 0
        fi
        if [[ -f "$defs" ]] && grep -Fq -- "0x${norm}" "$defs"; then
            return 0
        fi
    done <"$f"
    return 1
}

# True if dest holds a 0x* tree that is not in the VC source set.
_vc_dest_has_unlisted_keys() {
    local src_val dest_val dest_sec p base
    src_val="${VC_KEYS_SRC}/validators"
    dest_val="${VALIDATOR_DATA_DIR}/validators"
    dest_sec="${VALIDATOR_DATA_DIR}/secrets"
    if [[ -d "$dest_val" ]]; then
        _refuse_symlink "$dest_val" "VC validators"
        shopt -s nullglob
        for p in "$dest_val"/0x*; do
            base="$(basename -- "$p")"
            if [[ ! -f "${src_val}/${base}/voting-keystore.json" ]]; then
                shopt -u nullglob
                return 0
            fi
        done
        shopt -u nullglob
    fi
    if [[ -d "$dest_sec" ]]; then
        _refuse_symlink "$dest_sec" "VC secrets"
        shopt -s nullglob
        for p in "$dest_sec"/0x*; do
            base="$(basename -- "$p")"
            if [[ ! -f "${src_val}/${base}/voting-keystore.json" ]]; then
                shopt -u nullglob
                return 0
            fi
        done
        shopt -u nullglob
    fi
    return 1
}

# Drop dest 0x* keystores/secrets that are not in the VC source set.
_prune_unlisted_vc_keys() {
    local src_val dest_val dest_sec p base
    src_val="${VC_KEYS_SRC}/validators"
    dest_val="${VALIDATOR_DATA_DIR}/validators"
    dest_sec="${VALIDATOR_DATA_DIR}/secrets"
    if [[ -d "$dest_val" ]]; then
        _refuse_symlink "$dest_val" "VC validators"
        shopt -s nullglob
        for p in "$dest_val"/0x*; do
            base="$(basename -- "$p")"
            if [[ -f "${src_val}/${base}/voting-keystore.json" ]]; then
                continue
            fi
            _refuse_symlink "$p" "stale VC key dest"
            rm -rf -- "$p"
        done
        shopt -u nullglob
    fi
    if [[ -d "$dest_sec" ]]; then
        _refuse_symlink "$dest_sec" "VC secrets"
        shopt -s nullglob
        for p in "$dest_sec"/0x*; do
            base="$(basename -- "$p")"
            if [[ -f "${src_val}/${base}/voting-keystore.json" ]]; then
                continue
            fi
            _refuse_symlink "$p" "stale VC secret dest"
            rm -f -- "$p"
        done
        shopt -u nullglob
    fi
}

copy_vc_keys() {
    local src_val src_sec dest_val dest_sec keydir pubkey ks secret dest_ks dest_secret count want

    src_val="${VC_KEYS_SRC}/validators"
    src_sec="${VC_KEYS_SRC}/secrets"
    dest_val="${VALIDATOR_DATA_DIR}/validators"
    dest_sec="${VALIDATOR_DATA_DIR}/secrets"

    _require_split_bounds
    want="$(_vc_expected_count)"

    _refuse_symlink "$VC_KEYS_SRC" "VC keys source"
    _refuse_symlink "$src_val" "VC keystores"
    _refuse_symlink "$src_sec" "VC secrets"
    _refuse_symlink "$CL_DATA_DIR" "CL datadir"
    _refuse_symlink "$VALIDATOR_DATA_DIR" "VC datadir"

    validate_data_exists "data/keys/vc" "$VC_KEYS_SRC" "02-keys.sh"
    validate_data_exists "validator keystores" "$src_val" "02-keys.sh"
    validate_data_exists "validator secrets" "$src_sec" "02-keys.sh"
    if [[ ! -d "$src_val" ]]; then
        die_usage "validator keystores not a directory: ${src_val} (produced by 02-keys.sh)"
    fi
    if [[ ! -d "$src_sec" ]]; then
        die_usage "validator secrets not a directory: ${src_sec} (produced by 02-keys.sh)"
    fi

    mkdir -p -- "$VALIDATOR_DATA_DIR"
    _chmod_dir "$VALIDATOR_DATA_DIR"
    _ensure_dir "$dest_val" "VC validators"
    _ensure_dir "$dest_sec" "VC secrets"
    _refuse_symlink "${dest_val}/slashing_protection.sqlite" "slashing protection db"

    count=0
    shopt -s nullglob
    for keydir in "$src_val"/0x*; do
        if [[ -L "$keydir" ]]; then
            shopt -u nullglob
            die_usage "refusing symlink keystore dir: ${keydir}"
        fi
        if [[ ! -d "$keydir" ]]; then
            continue
        fi
        pubkey="$(basename -- "$keydir")"
        ks="${keydir}/voting-keystore.json"
        secret="${src_sec}/${pubkey}"
        dest_ks="${dest_val}/${pubkey}/voting-keystore.json"
        dest_secret="${dest_sec}/${pubkey}"
        if [[ -L "$ks" ]]; then
            shopt -u nullglob
            die_usage "refusing symlink keystore: ${ks}"
        fi
        if [[ ! -f "$ks" ]]; then
            shopt -u nullglob
            die_infra "missing voting-keystore.json in ${keydir}"
        fi
        if [[ -L "$secret" ]]; then
            shopt -u nullglob
            die_usage "refusing symlink secret: ${secret}"
        fi
        if [[ ! -f "$secret" ]]; then
            shopt -u nullglob
            die_infra "missing validator secret for ${pubkey}"
        fi
        _refuse_symlink "${dest_val}/${pubkey}" "VC keystore dest dir"
        if [[ -e "${dest_val}/${pubkey}" ]]; then
            if [[ ! -d "${dest_val}/${pubkey}" ]]; then
                shopt -u nullglob
                die_infra "keystore dest is not a directory: ${dest_val}/${pubkey}"
            fi
        fi
        mkdir -p -- "${dest_val}/${pubkey}"
        _refuse_symlink "${dest_val}/${pubkey}" "VC keystore dest dir"
        chmod 700 "${dest_val}/${pubkey}" || die_infra "cannot chmod 700 ${dest_val}/${pubkey}"
        _refuse_symlink "$dest_ks" "VC keystore dest"
        _refuse_symlink "$dest_secret" "VC secret dest"
        _refuse_symlink_parents "$dest_ks" "VC keystore dest"
        _refuse_symlink_parents "$dest_secret" "VC secret dest"
        _install_regular_file "$ks" "$dest_ks"
        _install_regular_file "$secret" "$dest_secret"
        count=$((count + 1))
    done
    shopt -u nullglob

    if [[ "$count" -ne "$want" ]]; then
        die_infra "copied ${count} keystores, expected ${want}"
    fi
    _prune_unlisted_vc_keys
    if _vc_datadir_contains_rvc; then
        _die_rvc_in_vc_datadir
    fi
    log_success "copied ${count} validator keystores"
}

_start_vc_container() {
    docker_run_as_user -d \
        --name "$VALIDATOR_CONTAINER" \
        --network "$DOCKER_NETWORK" \
        --restart unless-stopped \
        -v "${VALIDATOR_DATA_DIR}:/data" \
        -v "${GENESIS_DIR}:/genesis:ro" \
        -- \
        "$IMG_LIGHTHOUSE" \
        lighthouse \
        validator_client \
        --datadir=/data \
        --testnet-dir=/genesis \
        --beacon-nodes="http://${BEACON_CONTAINER}:5052" \
        --suggested-fee-recipient="${DEV_ACCOUNT}" \
        --graffiti="eth-devnet" \
        "$@"
}

start_vc() {
    local uid gid db
    uid="$(id -u)"
    gid="$(id -g)"

    if is_container_running "$VALIDATOR_CONTAINER"; then
        if _vc_datadir_contains_rvc; then
            _die_rvc_in_vc_datadir
        fi
        if _vc_dest_has_unlisted_keys; then
            remove_container "$VALIDATOR_CONTAINER"
        else
            log_info "validator already running"
            return 0
        fi
    fi

    _require_fee_recipient

    if [[ "$FORCE" == "1" ]]; then
        _reset_vc_datadir
    fi

    inventory_append datadir validator "$VALIDATOR_DATA_DIR"
    mkdir -p -- "$VALIDATOR_DATA_DIR"
    _chmod_dir "$VALIDATOR_DATA_DIR"
    copy_vc_keys

    db="$(_vc_slashing_db)"
    _refuse_symlink "$db" "slashing protection db"
    if [[ ! -f "$db" && "$FORCE" != "1" ]] && _vc_slashing_history_present; then
        die_usage "slashing protection db missing at ${db} but validator datadir is in use; re-run with --force"
    fi

    if container_exists "$VALIDATOR_CONTAINER"; then
        remove_container "$VALIDATOR_CONTAINER"
    fi

    inventory_append container "$VALIDATOR_CONTAINER"

    log_info "starting lighthouse validator_client"
    # Lighthouse VC doppelganger protection only when DOPPELGANGER=on (P6-A12).
    if [[ "${DOPPELGANGER:-off}" == "on" ]]; then
        set -- --enable-doppelganger-protection
    else
        set --
    fi
    if [[ -f "$db" ]]; then
        if ! _start_vc_container "$@" >/dev/null; then
            _fail_chain "failed to start ${VALIDATOR_CONTAINER}"
        fi
    else
        if ! _start_vc_container "$@" --init-slashing-protection >/dev/null; then
            _fail_chain "failed to start ${VALIDATOR_CONTAINER}"
        fi
    fi
    if ! is_container_running "$VALIDATOR_CONTAINER"; then
        _fail_chain "validator container is not running"
    fi
    log_success "validator started (uid ${uid}:${gid})"
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
    local got want
    if [[ -L "$DATA_DIR" ]]; then
        die_usage "refusing symlink purge root: ${DATA_DIR}"
    fi
    _refuse_symlink "$GENESIS_DIR" "genesis dir"
    _require_jwt
    validate_data_exists "EL genesis" "${GENESIS_DIR}/genesis.json" "01-genesis.sh"
    validate_data_exists "CL genesis" "${GENESIS_DIR}/genesis.ssz" "01-genesis.sh"
    validate_data_exists "CL config" "${GENESIS_DIR}/config.yaml" "01-genesis.sh"
    _require_split_bounds
    _require_fee_recipient
    _refuse_symlink "$VC_KEYS_SRC" "VC keys source"
    validate_data_exists "data/keys/vc" "$VC_KEYS_SRC" "02-keys.sh"
    validate_data_exists "validator keystores" "${VC_KEYS_SRC}/validators" "02-keys.sh"
    validate_data_exists "validator secrets" "${VC_KEYS_SRC}/secrets" "02-keys.sh"
    got="$(_vc_source_count)"
    want="$(_vc_expected_count)"
    if [[ "$got" -ne "$want" ]]; then
        die_usage "validator keystores ${got} != ${want} at ${VC_KEYS_SRC}/validators (produced by 02-keys.sh)"
    fi
}

main() {
    parse_common_flags "$@"
    _bind_chain_paths
    if [[ -n "${PROFILE:-}" ]]; then
        resolve_profile "$PROFILE"
    fi
    require_chain_1337
    require_cmd jq
    require_cmd python3
    resolve_run_dir >/dev/null
    _validate_inputs

    if [[ "$DRY_RUN" == "1" ]]; then
        print_chain_plan
        if _vc_datadir_contains_rvc; then
            _die_rvc_in_vc_datadir
        fi
        if _all_chain_running && [[ "$FORCE" != "1" ]] && ! _vc_dest_has_unlisted_keys; then
            log_info "would no-op (geth, beacon and validator already running)"
        else
            log_info "would start ${GETH_CONTAINER}, ${BEACON_CONTAINER} and ${VALIDATOR_CONTAINER}"
        fi
        log_success "dry-run complete"
        return 0
    fi

    require_cmd "$DOCKER"
    require_cmd "$CURL"

    if [[ "$FORCE" == "1" ]]; then
        _truncate_inventory
        remove_container "$VALIDATOR_CONTAINER"
        remove_container "$BEACON_CONTAINER"
        remove_container "$GETH_CONTAINER"
        _reset_vc_datadir
    elif _all_chain_running; then
        if _vc_datadir_contains_rvc; then
            _die_rvc_in_vc_datadir
        fi
        if _vc_dest_has_unlisted_keys; then
            remove_container "$VALIDATOR_CONTAINER"
        else
            log_success "geth, beacon and validator already running"
            return 0
        fi
    fi

    start_geth
    start_beacon
    wait_for_chain
    assert_head_fork_electra
    start_vc
    log_success "chain ready"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
