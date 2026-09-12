#!/usr/bin/env bash
# All NUM_VALIDATORS keystores in whole-set form under data/keys/valtools/.

set -euo pipefail

# Process env wins over devnet.env (CHAIN_ID=1). Capture before common.sh
# sources the file, which would otherwise overwrite.
_OV_CHAIN_ID=0
_KEEP_CHAIN_ID=""
if [[ "${CHAIN_ID+x}" == "x" ]]; then
    _OV_CHAIN_ID=1
    _KEEP_CHAIN_ID="$CHAIN_ID"
fi

_KEYS_STAGE_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_KEYS_STAGE_DIR}/lib/common.sh"

if [[ "$_OV_CHAIN_ID" -eq 1 ]]; then
    CHAIN_ID="$_KEEP_CHAIN_ID"
    export CHAIN_ID
fi
unset _OV_CHAIN_ID _KEEP_CHAIN_ID

# Fallback if the genesis-generator binary rejects --validators-mnemonic.
_IMG_VAL_TOOLS_FALLBACK="protolambda/eth2-val-tools:0.2.2@sha256:46147228f291266148a6a21a2b9541367ad5f70e619d79cd5393459baf539f58"

_bind_keys_paths() {
    VALTOOLS_DIR="${KEYS_DIR}/valtools"
    VALTOOLS_LOG="${KEYS_DIR}/valtools.log"
    MANIFEST_JSON="${KEYS_DIR}/manifest.json"
}

_bind_keys_paths

_refuse_symlink() {
    local path="$1"
    local what="$2"
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink ${what}: ${path}"
    fi
}

_require_positive_int() {
    local name="$1"
    local val="$2"
    case "$val" in
        '' | *[!0-9]*)
            die_usage "${name} must be a positive integer (got ${val:-empty})"
            ;;
    esac
    if [[ "$val" -lt 1 ]]; then
        die_usage "${name} must be a positive integer (got ${val})"
    fi
}

# Drop the mnemonic from a captured val-tools log (do not replay raw).
_scrub_keys_log() {
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

_keystore_list_json() {
    local dir="${VALTOOLS_DIR}/validators"
    local -a names=()
    local p
    shopt -s nullglob
    for p in "$dir"/0x*; do
        if [[ -d "$p" && -f "${p}/voting-keystore.json" ]]; then
            names+=("$(basename -- "$p")")
        fi
    done
    shopt -u nullglob
    if [[ ${#names[@]} -eq 0 ]]; then
        printf '[]\n'
        return 0
    fi
    printf '%s\n' "${names[@]}" | jq -R . | jq -s .
}

_keystore_count() {
    _keystore_list_json | jq length
}

keys_exist() {
    local got
    if [[ ! -d "${VALTOOLS_DIR}/validators" || -L "${VALTOOLS_DIR}/validators" ]]; then
        return 1
    fi
    got="$(_keystore_count)"
    [[ "$got" -eq "$NUM_VALIDATORS" ]]
}

assert_key_count() {
    local got
    got="$(_keystore_count)"
    if [[ "$got" -ne "$NUM_VALIDATORS" ]]; then
        die_infra "keystore count ${got} != ${NUM_VALIDATORS}"
    fi
}

assert_kdf_strength() {
    local dir="${VALTOOLS_DIR}/validators"
    local -a files=()
    local p
    if [[ ! -d "$dir" || -L "$dir" ]]; then
        die_infra "validators directory missing: ${dir}"
    fi
    shopt -s nullglob
    for p in "$dir"/0x*/voting-keystore.json; do
        if [[ -L "$p" ]]; then
            shopt -u nullglob
            die_infra "keystore is a symlink: ${p}"
        fi
        if [[ ! -f "$p" ]]; then
            shopt -u nullglob
            die_infra "keystore is not a regular file: ${p}"
        fi
        files+=("$p")
    done
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then
        die_infra "no keystores found for KDF check"
    fi
    if ! jq -n -e --argjson want "${#files[@]}" '
        [inputs]
        | if length != $want then error("unreadable or empty keystore") else . end
        | map(
            .crypto.kdf.params.c
            | if type != "number" then error("missing or non-numeric KDF c")
              elif . < 10000 then error("KDF c below 10000")
              else . end
          )
    ' -- "${files[@]}" >/dev/null; then
        die_infra "keystore KDF too weak or unreadable"
    fi
}

manifest_has_n_rows() {
    local got
    if [[ ! -f "$MANIFEST_JSON" || -L "$MANIFEST_JSON" ]]; then
        return 1
    fi
    got="$(jq -r '.validators|length' "$MANIFEST_JSON" 2>/dev/null)" || return 1
    case "$got" in
        '' | *[!0-9]*)
            return 1
            ;;
    esac
    [[ "$got" -eq "$NUM_VALIDATORS" ]]
}

_run_val_tools_pubkeys() {
    local img="$1"
    local entrypoint="$2"
    "$DOCKER" run --rm \
        --entrypoint "$entrypoint" \
        -- \
        "$img" \
        pubkeys \
        --validators-mnemonic="$MNEMONIC" \
        --source-min=0 \
        --source-max="$NUM_VALIDATORS" \
        2>&1
}

_collect_pubkeys() {
    local raw filtered
    raw=""
    raw="$(_run_val_tools_pubkeys "$IMG_GENESIS" "/usr/local/bin/eth2-val-tools")" || raw=""
    filtered="$(printf '%s\n' "$raw" | grep -E '^0x[0-9a-f]{96}$' || true)"
    if [[ -n "$filtered" ]]; then
        printf '%s\n' "$filtered"
        return 0
    fi
    # Fallback image ENTRYPOINT is ./eth2-val-tools under WORKDIR /app.
    raw=""
    raw="$(_run_val_tools_pubkeys "$_IMG_VAL_TOOLS_FALLBACK" "/app/eth2-val-tools")" || raw=""
    filtered="$(printf '%s\n' "$raw" | grep -E '^0x[0-9a-f]{96}$' || true)"
    if [[ -n "$filtered" ]]; then
        printf '%s\n' "$filtered"
        return 0
    fi
    die_infra "pubkeys failed"
}

# O_NOFOLLOW + O_EXCL temp, then replace. Do not use a PID-predictable tmp name.
_write_manifest_atomic() {
    MANIFEST_DEST="$1" python3 -c '
import os, sys

dest = os.environ["MANIFEST_DEST"]
data = sys.stdin.buffer.read()
if not data:
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

build_manifest() {
    local filtered n_lines n_uniq generated_at
    umask 077
    mkdir -p -- "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"
    _refuse_symlink "$KEYS_DIR" "keys dir"
    _refuse_symlink "$MANIFEST_JSON" "manifest"
    log_info "building key manifest"
    filtered="$(_collect_pubkeys)"
    n_lines="$(printf '%s\n' "$filtered" | grep -cE '^0x[0-9a-f]{96}$' || true)"
    n_uniq="$(printf '%s\n' "$filtered" | sort -u | grep -cE '^0x[0-9a-f]{96}$' || true)"
    if [[ "$n_lines" -ne "$NUM_VALIDATORS" ]]; then
        die_infra "pubkeys count ${n_lines} != ${NUM_VALIDATORS}"
    fi
    if [[ "$n_uniq" -ne "$n_lines" ]]; then
        die_infra "duplicated pubkeys"
    fi
    generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    if ! printf '%s\n' "$filtered" | jq -Rn --arg generated_at "$generated_at" '
        {
          schema_version: 1,
          generated_at: $generated_at,
          validators: ([inputs] | to_entries | map({
            index: .key,
            pubkey: .value,
            keystore_path: ("valtools/validators/" + .value + "/voting-keystore.json")
          }))
        }
    ' | _write_manifest_atomic "$MANIFEST_JSON"; then
        die_infra "manifest json encode failed"
    fi
    chmod 600 "$MANIFEST_JSON"
}

assert_manifest_rows() {
    local got
    if [[ ! -f "$MANIFEST_JSON" || -L "$MANIFEST_JSON" ]]; then
        die_infra "manifest missing: ${MANIFEST_JSON}"
    fi
    if ! jq -e --argjson n "$NUM_VALIDATORS" '
        .schema_version == 1
        and (.generated_at | type == "string" and length > 0)
        and (.validators | type == "array")
        and (.validators | length) == $n
        and ([.validators[].index] == [range($n)])
        and ((.validators | map(.pubkey) | unique | length) == $n)
        and all(
              .validators[];
              (.pubkey | type == "string" and test("^0x[0-9a-f]{96}$"))
              and (.keystore_path == ("valtools/validators/" + .pubkey + "/voting-keystore.json"))
            )
    ' "$MANIFEST_JSON" >/dev/null; then
        die_infra "manifest rows invalid"
    fi
    got="$(jq '.validators|length' "$MANIFEST_JSON")"
    if [[ "$got" -ne "$NUM_VALIDATORS" ]]; then
        die_infra "manifest row count ${got} != ${NUM_VALIDATORS}"
    fi
}

_normalize_valtools_tree() {
    if [[ ! -d "$VALTOOLS_DIR" || -L "$VALTOOLS_DIR" ]]; then
        die_infra "valtools output missing: ${VALTOOLS_DIR}"
    fi
    if [[ -L "${VALTOOLS_DIR}/keys" ]]; then
        die_infra "refusing symlink valtools/keys: ${VALTOOLS_DIR}/keys"
    fi
    if [[ ! -d "${VALTOOLS_DIR}/keys" ]]; then
        die_infra "val-tools did not emit keys/"
    fi
    if [[ -e "${VALTOOLS_DIR}/validators" ]]; then
        die_infra "valtools/validators already exists"
    fi
    mv -- "${VALTOOLS_DIR}/keys" "${VALTOOLS_DIR}/validators"
    if [[ ! -d "${VALTOOLS_DIR}/secrets" || -L "${VALTOOLS_DIR}/secrets" ]]; then
        die_infra "val-tools did not emit secrets/"
    fi
}

_prune_unused_client_trees() {
    rm -rf -- \
        "${VALTOOLS_DIR}/nimbus-keys" \
        "${VALTOOLS_DIR}/teku-keys" \
        "${VALTOOLS_DIR}/teku-secrets" \
        "${VALTOOLS_DIR}/lodestar-secrets" \
        "${VALTOOLS_DIR}/prysm"
}

_lockdown_keys() {
    if [[ -d "$KEYS_DIR" && ! -L "$KEYS_DIR" ]]; then
        chmod 700 "$KEYS_DIR"
    fi
    if [[ ! -d "$VALTOOLS_DIR" || -L "$VALTOOLS_DIR" ]]; then
        return 0
    fi
    chmod 700 "$VALTOOLS_DIR"
    find "$VALTOOLS_DIR" -type d -exec chmod 700 {} +
    find "$VALTOOLS_DIR" -type f -exec chmod 600 {} +
}

generate_keystores() {
    local log
    mkdir -p -- "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"
    _refuse_symlink "$KEYS_DIR" "keys dir"
    _refuse_symlink "$VALTOOLS_DIR" "valtools dir"
    if [[ -z "$VALTOOLS_DIR" || "$VALTOOLS_DIR" == "/" ]]; then
        die_infra "refusing to wipe empty valtools path"
    fi
    # out-loc must be absent; eth2-val-tools errors if it exists. Do not pre-create valtools/.
    rm -rf -- "$VALTOOLS_DIR"
    log="$VALTOOLS_LOG"
    _refuse_symlink "$log" "valtools log"
    : >"$log"
    chmod 600 "$log"
    log_info "generating validator keystores"
    # genesis-generator 6.2.1 ENTRYPOINT is /work/entrypoint.sh; invoke the bundled binary.
    # --source-max is exclusive: pass NUM_VALIDATORS (not N-1). Bind keys-only (JWT stays off).
    if ! docker_run_as_user --rm \
        -v "${KEYS_DIR}:/data/keys" \
        --entrypoint /usr/local/bin/eth2-val-tools \
        -- \
        "$IMG_GENESIS" \
        keystores \
        --source-mnemonic "$MNEMONIC" \
        --source-min 0 \
        --source-max "$NUM_VALIDATORS" \
        --out-loc /data/keys/valtools \
        >"$log" 2>&1; then
        _scrub_keys_log "$log"
        _lockdown_keys
        die_infra "keystores failed"
    fi
    _scrub_keys_log "$log"
    _normalize_valtools_tree
    _prune_unused_client_trees
    _lockdown_keys
}

print_keys_plan() {
    log_info "keys plan:"
    log_info "  1. generate_keystores"
    log_info "  2. assert_key_count"
    log_info "  3. assert_kdf_strength"
    log_info "  4. build_manifest"
    log_info "  5. assert_manifest_rows"
}

main() {
    parse_common_flags "$@"
    _bind_keys_paths
    require_chain_1337
    require_cmd jq
    require_cmd python3
    _require_positive_int "NUM_VALIDATORS" "${NUM_VALIDATORS:-}"

    if [[ -L "$DATA_DIR" ]]; then
        die_usage "refusing symlink purge root: ${DATA_DIR}"
    fi

    validate_data_exists "config.yaml" "${GENESIS_DIR}/config.yaml" "01-genesis.sh"

    _refuse_symlink "$KEYS_DIR" "keys dir"
    _refuse_symlink "$VALTOOLS_DIR" "valtools dir"

    if [[ "$DRY_RUN" == "1" ]]; then
        print_keys_plan
        if [[ "$FORCE" != "1" ]] && keys_exist; then
            log_info "would no-op (validator keys present)"
        else
            log_info "would generate keystores via ${IMG_GENESIS}"
        fi
        if [[ "$FORCE" != "1" ]] && manifest_has_n_rows; then
            log_info "would skip manifest.json (already has ${NUM_VALIDATORS} rows)"
        else
            log_info "would build manifest.json via ${IMG_GENESIS}"
        fi
        log_success "dry-run complete"
        return 0
    fi

    mkdir -p -- "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"

    if [[ "$FORCE" == "1" ]] || ! keys_exist; then
        require_cmd "$DOCKER"
        generate_keystores
    else
        _lockdown_keys
        log_info "validator keys already present"
    fi
    assert_key_count
    assert_kdf_strength

    if [[ "$FORCE" == "1" ]] || ! manifest_has_n_rows; then
        require_cmd "$DOCKER"
        build_manifest
    else
        log_info "skipping manifest.json (already has ${NUM_VALIDATORS} rows)"
    fi
    assert_manifest_rows
    log_success "validator keys ready"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
