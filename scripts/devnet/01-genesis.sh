#!/usr/bin/env bash
# JWT + Electra-at-genesis chain config (12 s × 32 slots).

set -euo pipefail

# Process env wins over devnet.env (CHAIN_ID=1). Capture before common.sh
# sources the file, which would otherwise overwrite.
_OV_CHAIN_ID=0
_KEEP_CHAIN_ID=""
if [[ "${CHAIN_ID+x}" == "x" ]]; then
    _OV_CHAIN_ID=1
    _KEEP_CHAIN_ID="$CHAIN_ID"
fi

_GENESIS_STAGE_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_GENESIS_STAGE_DIR}/lib/common.sh"

if [[ "$_OV_CHAIN_ID" -eq 1 ]]; then
    CHAIN_ID="$_KEEP_CHAIN_ID"
    export CHAIN_ID
fi
unset _OV_CHAIN_ID _KEEP_CHAIN_ID

_GENESIS_STALE_REASON=""

_refuse_symlink() {
    local path="$1"
    local what="$2"
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink ${what}: ${path}"
    fi
}

_yaml_has() {
    local key="$1"
    local val="$2"
    local file="$3"
    grep -Eq "^${key}:[[:space:]]*['\"]?${val}['\"]?[[:space:]]*$" "$file"
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

_datadir_present() {
    local dir="$1"
    [[ -d "$dir" ]] || return 1
    [[ -n "$(ls -A -- "$dir" 2>/dev/null)" ]]
}

_datadir_gvr() {
    local dir="$1"
    _gvr_from_file "${dir}/genesis_validators_root.txt"
}

_genesis_artifacts_present() {
    [[ -f "${GENESIS_DIR}/genesis.ssz" ]] \
        && [[ -f "${GENESIS_DIR}/config.yaml" ]] \
        && [[ -f "${GENESIS_DIR}/genesis_validators_root.txt" ]]
}

_wipe_generator_output() {
    rm -rf -- "${GENESIS_DIR}/metadata" "${GENESIS_DIR}/parsed" "${GENESIS_DIR}/jwt"
    rm -f -- \
        "${GENESIS_DIR}/genesis.ssz" \
        "${GENESIS_DIR}/config.yaml" \
        "${GENESIS_DIR}/genesis.json" \
        "${GENESIS_DIR}/genesis_validators_root.txt" \
        "${GENESIS_DIR}/deploy_block.txt" \
        "${GENESIS_DIR}/generator.log"
    rm -f -- "${GENESIS_DIR}"/deposit_contract*.txt
}

# O_NOFOLLOW + O_EXCL temp, then replace. Do not use a PID-predictable tmp name.
_write_jwt_atomic() {
    JWT_DEST="$1" python3 -c '
import os, sys

dest = os.environ["JWT_DEST"]
data = sys.stdin.buffer.read().strip()
if len(data) != 64 or any(c not in b"0123456789abcdef" for c in data):
    sys.exit(1)

directory = os.path.dirname(os.path.abspath(dest))
if os.path.islink(directory) or not os.path.isdir(directory):
    sys.exit(2)
if os.path.lexists(dest) and os.path.islink(dest):
    sys.exit(2)

tmp = dest + ".tmp." + os.urandom(16).hex()
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
fd = -1
try:
    fd = os.open(tmp, flags, 0o600)
    os.write(fd, data)
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
'
}

make_jwt() {
    local jwt
    mkdir -p -- "$JWT_DIR"
    chmod 700 "$JWT_DIR"
    _refuse_symlink "$JWT_DIR" "jwt dir"
    jwt="${JWT_DIR}/jwt.hex"
    _refuse_symlink "$jwt" "jwt"
    if ! openssl rand -hex 32 | tr -d '\n' | _write_jwt_atomic "$jwt"; then
        die_infra "failed to write JWT secret"
    fi
    if [[ -L "$jwt" ]]; then
        die_usage "refusing symlink jwt: ${jwt}"
    fi
    chmod 600 "$jwt"
}

_chmod_secret() {
    local path="$1"
    if [[ -f "$path" && ! -L "$path" ]]; then
        chmod 600 "$path"
    fi
}

# Empty jwtsecret makes the generator skip openssl/echo (and the set -x leak).
_preseed_generator_jwt() {
    local gjwt="${GENESIS_DIR}/jwt"
    local secret="${gjwt}/jwtsecret"
    mkdir -p -- "$gjwt"
    chmod 700 "$gjwt"
    _refuse_symlink "$gjwt" "generator jwt dir"
    _refuse_symlink "$secret" "jwtsecret"
    : >"$secret"
    chmod 600 "$secret"
}

_lockdown_generator_secrets() {
    local gjwt="${GENESIS_DIR}/jwt"
    _chmod_secret "${gjwt}/jwtsecret"
    _chmod_secret "${GENESIS_DIR}/jwtsecret"
    _chmod_secret "${GENESIS_DIR}/metadata/mnemonics.yaml"
    _chmod_secret "${GENESIS_DIR}/mnemonics.yaml"
    _chmod_secret "${GENESIS_DIR}/values.env"
    if [[ -d "$gjwt" && ! -L "$gjwt" ]]; then
        chmod 700 "$gjwt"
    fi
}

# Drop xtrace JWT/mnemonic from a captured generator log (do not replay raw).
_scrub_generator_log() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        return 0
    fi
    MNEMONIC="${MNEMONIC-}" python3 -c '
import os, re, sys
path = sys.argv[1]
try:
    text = open(path, "r", encoding="utf-8", errors="replace").read()
except OSError:
    sys.exit(0)
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
os.chmod(path, 0o600)
' "$path"
}

render_values_env() {
    local ts dest
    mkdir -p -- "$GENESIS_DIR"
    chmod 700 "$GENESIS_DIR"
    _refuse_symlink "$GENESIS_DIR" "genesis dir"
    dest="${GENESIS_DIR}/values.env"
    _refuse_symlink "$dest" "values.env"
    ts="$(date +%s)"
    # FULU_FORK_EPOCH is 2^64-1 as a string; arithmetic expansion overflows signed 64-bit.
    cat >"$dest" <<EOF
PRESET_BASE=mainnet
CHAIN_ID=${CHAIN_ID}
DEPOSIT_CONTRACT_ADDRESS=${DEPOSIT_CONTRACT_ADDRESS}
EL_AND_CL_MNEMONIC="${MNEMONIC}"
CL_EXEC_BLOCK=0
SLOT_DURATION_MS=12000
GENESIS_TIMESTAMP=${ts}
GENESIS_DELAY=${GENESIS_DELAY}
NUMBER_OF_VALIDATORS=${NUM_VALIDATORS}
GENESIS_FORK_VERSION=${GENESIS_FORK_VERSION}
ALTAIR_FORK_VERSION=${ALTAIR_FORK_VERSION}
ALTAIR_FORK_EPOCH=0
BELLATRIX_FORK_VERSION=${BELLATRIX_FORK_VERSION}
BELLATRIX_FORK_EPOCH=0
CAPELLA_FORK_VERSION=${CAPELLA_FORK_VERSION}
CAPELLA_FORK_EPOCH=0
DENEB_FORK_VERSION=${DENEB_FORK_VERSION}
DENEB_FORK_EPOCH=0
ELECTRA_FORK_VERSION=${ELECTRA_FORK_VERSION}
ELECTRA_FORK_EPOCH=${ELECTRA_FORK_EPOCH}
FULU_FORK_VERSION=${FULU_FORK_VERSION}
FULU_FORK_EPOCH=${FULU_FORK_EPOCH}
BPO_1_EPOCH=${BPO_1_EPOCH}
BPO_2_EPOCH=${BPO_2_EPOCH}
WITHDRAWAL_TYPE=0x01
WITHDRAWAL_ADDRESS=${DEV_ACCOUNT}
EL_PREMINE_ADDRS='{"${DEV_ACCOUNT}": {"balance": "1000000000ETH"}}'
EOF
    chmod 600 "$dest"
}

run_generator() {
    local log
    if [[ ! -f "${GENESIS_DIR}/values.env" ]]; then
        die_infra "values.env not found at ${GENESIS_DIR}/values.env"
    fi
    _wipe_generator_output
    mkdir -p -- "$GENESIS_DIR"
    chmod 700 "$GENESIS_DIR"
    _preseed_generator_jwt
    log="${GENESIS_DIR}/generator.log"
    : >"$log"
    chmod 600 "$log"
    log_info "running genesis generator"
    # Capture xtrace; 6.2.1 set -x would otherwise print echo -n 0x<jwtsecret>.
    if ! docker_run_as_user --rm \
        -v "${GENESIS_DIR}:/data" \
        -v "${GENESIS_DIR}/values.env:/config/values.env" \
        -- \
        "$IMG_GENESIS" \
        all >"$log" 2>&1; then
        _scrub_generator_log "$log"
        _lockdown_generator_secrets
        die_infra "genesis generator failed"
    fi
    _scrub_generator_log "$log"
    _lockdown_generator_secrets
}

copy_metadata() {
    local meta="${GENESIS_DIR}/metadata"
    local f
    local -a deposits
    if [[ ! -d "$meta" ]]; then
        die_infra "generator metadata directory missing: ${meta}"
    fi
    for f in genesis.ssz config.yaml genesis.json genesis_validators_root.txt; do
        if [[ ! -f "${meta}/${f}" ]]; then
            die_infra "generator did not emit metadata/${f}"
        fi
        cp -- "${meta}/${f}" "${GENESIS_DIR}/${f}"
    done
    shopt -s nullglob
    deposits=("${meta}"/deposit_contract*.txt)
    shopt -u nullglob
    if [[ ${#deposits[@]} -eq 0 ]]; then
        die_infra "generator did not emit metadata/deposit_contract*.txt"
    fi
    cp -- "${deposits[@]}" "${GENESIS_DIR}/"
    printf '0\n' >"${GENESIS_DIR}/deploy_block.txt"
}

assert_generated_config() {
    local cfg="${GENESIS_DIR}/config.yaml"
    if [[ ! -f "$cfg" ]]; then
        die_infra "config.yaml not found at ${cfg}"
    fi
    if ! _yaml_has "SLOT_DURATION_MS" "12000" "$cfg"; then
        die_infra "generated config.yaml does not have SLOT_DURATION_MS: 12000"
    fi
    if ! _yaml_has "PRESET_BASE" "mainnet" "$cfg"; then
        die_infra "generated config.yaml does not have PRESET_BASE: mainnet"
    fi
    if ! _yaml_has "ELECTRA_FORK_EPOCH" "0" "$cfg"; then
        die_infra "generated config.yaml does not have ELECTRA_FORK_EPOCH: 0"
    fi
}

genesis_is_stale() {
    local genesis_gvr="" raw dir dir_gvr label
    _GENESIS_STALE_REASON=""
    if raw="$(_gvr_from_file "${GENESIS_DIR}/genesis_validators_root.txt")"; then
        genesis_gvr="$(_normalize_gvr "$raw")"
    fi
    for dir in "$EL_DATA_DIR" "$CL_DATA_DIR"; do
        if [[ "$dir" == "$EL_DATA_DIR" ]]; then
            label="EL"
        else
            label="CL"
        fi
        if ! _datadir_present "$dir"; then
            continue
        fi
        dir_gvr=""
        if raw="$(_datadir_gvr "$dir")"; then
            dir_gvr="$(_normalize_gvr "$raw")"
        fi
        if [[ -z "$genesis_gvr" || -z "$dir_gvr" || "$dir_gvr" != "$genesis_gvr" ]]; then
            _GENESIS_STALE_REASON="${label} datadir GVR does not match genesis (${dir}); re-run with --force"
            return 0
        fi
    done
    return 1
}

print_genesis_plan() {
    log_info "genesis plan:"
    log_info "  1. make_jwt"
    log_info "  2. render_values_env"
    log_info "  3. run_generator"
    log_info "  4. copy_metadata"
    log_info "  5. assert_generated_config"
}

main() {
    parse_common_flags "$@"
    require_chain_1337
    require_cmd openssl
    require_cmd python3

    if [[ -L "$DATA_DIR" ]]; then
        die_usage "refusing symlink purge root: ${DATA_DIR}"
    fi

    if genesis_is_stale && [[ "$FORCE" != "1" ]]; then
        die_usage "${_GENESIS_STALE_REASON}"
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        print_genesis_plan
        if [[ "$FORCE" != "1" ]] && _genesis_artifacts_present; then
            log_info "would no-op (genesis.ssz present)"
        else
            log_info "would generate genesis via ${IMG_GENESIS}"
        fi
        log_success "dry-run complete"
        return 0
    fi

    if [[ "$FORCE" != "1" ]] && _genesis_artifacts_present; then
        assert_generated_config
        if [[ ! -f "${JWT_DIR}/jwt.hex" ]]; then
            make_jwt
        fi
        log_success "genesis already present"
        return 0
    fi

    require_cmd "$DOCKER"
    mkdir -p -- "$JWT_DIR" "$GENESIS_DIR"
    chmod 700 "$JWT_DIR" "$GENESIS_DIR"
    make_jwt
    render_values_env
    run_generator
    copy_metadata
    _lockdown_generator_secrets
    assert_generated_config
    log_success "genesis ready"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
