#!/usr/bin/env bash
# All NUM_VALIDATORS keystores under data/keys/valtools/, then a disjoint
# split: data/keys/vc/ [0, N-K) and data/keys/rvc/ [N-K, N).

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
    VC_DIR="${KEYS_DIR}/vc"
    RVC_DIR="${KEYS_DIR}/rvc"
    RVC_PASSWORDS="${RVC_DIR}/passwords.txt"
    RVC_PUBKEYS="${RVC_DIR}/pubkeys.txt"
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
# Exit 2 on a dest/dir symlink (do not write through); 1 on empty/IO.
_atomic_replace_stdin() {
    ATOMIC_DEST="$1" python3 -c '
import os, sys

dest = os.environ["ATOMIC_DEST"]
data = sys.stdin.buffer.read()
if not data:
    sys.exit(1)

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

_write_manifest_atomic() {
    _atomic_replace_stdin "$1"
}

_write_file_atomic() {
    local dest="$1"
    local parent rc=0
    parent="$(dirname -- "$dest")"
    _refuse_symlink "$parent" "atomic dest dir"
    _refuse_symlink "$dest" "atomic dest"
    _atomic_replace_stdin "$dest" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
        die_usage "refusing symlink dest: ${dest}"
    fi
    if [[ "$rc" -ne 0 ]]; then
        die_infra "atomic write failed: ${dest}"
    fi
}

# Copy src -> dest without following either path. Dest is tmp+replace.
_copy_file_nofollow() {
    local src="$1"
    local dest="$2"
    local parent rc=0
    parent="$(dirname -- "$dest")"
    _refuse_symlink "$src" "copy source"
    _refuse_symlink "$parent" "copy dest dir"
    _refuse_symlink "$dest" "copy dest"
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
directory = os.path.dirname(os.path.abspath(dest))
fail_if_symlink(directory)
if not os.path.isdir(directory):
    raise SystemExit(1)
fail_if_symlink(dest, missing_ok=True)

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
        die_usage "refusing symlink file: ${src} -> ${dest}"
    fi
    if [[ "$rc" -ne 0 ]]; then
        die_infra "failed to copy ${dest}"
    fi
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

_require_split_bounds() {
    local n k
    _require_positive_int "RVC_KEYS" "${RVC_KEYS:-}"
    n="$NUM_VALIDATORS"
    k="$RVC_KEYS"
    if [[ "$k" -ge "$n" ]]; then
        die_usage "RVC_KEYS must be < NUM_VALIDATORS (got ${k} >= ${n})"
    fi
}

# VC count and RVC start index are both N-K.
_rvc_start_index() {
    local n k
    n="$NUM_VALIDATORS"
    k="$RVC_KEYS"
    printf '%s\n' "$((n - k))"
}

normalize_pubkey() {
    local pk="${1-}"
    pk="${pk#0x}"
    pk="${pk#0X}"
    printf '%s\n' "$pk" | tr '[:upper:]' '[:lower:]'
}

_wipe_keys_subset() {
    local path="$1"
    local what="$2"
    if [[ -z "$path" || "$path" == "/" ]]; then
        die_infra "refusing to wipe empty ${what} path"
    fi
    _refuse_symlink "$path" "$what"
    if [[ -e "$path" && ! -d "$path" ]]; then
        die_infra "${what} exists and is not a directory: ${path}"
    fi
    rm -rf -- "$path"
}

_lockdown_tree() {
    local dir="$1"
    if [[ ! -d "$dir" || -L "$dir" ]]; then
        return 0
    fi
    chmod 700 "$dir"
    find "$dir" -type d -exec chmod 700 {} +
    find "$dir" -type f -exec chmod 600 {} +
}

_install_file() {
    local mode="$1"
    local src="$2"
    local dest="$3"
    local parent
    parent="$(dirname -- "$dest")"
    # GNU install -D creates parents; BSD install has no -D (and -D is a dest db).
    mkdir -p -- "$parent"
    _refuse_symlink "$parent" "install dest dir"
    _copy_file_nofollow "$src" "$dest"
    chmod "$mode" "$dest"
}

_vc_keystore_count() {
    local p n=0
    shopt -s nullglob
    for p in "${VC_DIR}/validators"/0x*/voting-keystore.json; do
        if [[ -f "$p" && ! -L "$p" ]]; then
            n=$((n + 1))
        fi
    done
    shopt -u nullglob
    printf '%s\n' "$n"
}

_vc_secret_count() {
    local p n=0
    shopt -s nullglob
    for p in "${VC_DIR}/secrets"/0x*; do
        if [[ -f "$p" && ! -L "$p" ]]; then
            n=$((n + 1))
        fi
    done
    shopt -u nullglob
    printf '%s\n' "$n"
}

_rvc_keystore_count() {
    local f base n=0
    shopt -s nullglob
    for f in "${RVC_DIR}"/keystore-0x*.json; do
        if [[ -f "$f" && ! -L "$f" ]]; then
            base="$(basename -- "$f")"
            if printf '%s\n' "$base" | grep -qE '^keystore-0x[0-9a-f]{96}\.json$'; then
                n=$((n + 1))
            fi
        fi
    done
    shopt -u nullglob
    printf '%s\n' "$n"
}

vc_subset_ready() {
    local want got
    want="$(_rvc_start_index)"
    if [[ ! -d "${VC_DIR}/validators" || -L "${VC_DIR}/validators" ]]; then
        return 1
    fi
    if [[ ! -d "${VC_DIR}/secrets" || -L "${VC_DIR}/secrets" ]]; then
        return 1
    fi
    got="$(_vc_keystore_count)"
    if [[ "$got" -ne "$want" ]]; then
        return 1
    fi
    got="$(_vc_secret_count)"
    [[ "$got" -eq "$want" ]]
}

rvc_subset_ready() {
    local got
    if [[ ! -d "$RVC_DIR" || -L "$RVC_DIR" ]]; then
        return 1
    fi
    if [[ ! -f "$RVC_PASSWORDS" || -L "$RVC_PASSWORDS" ]]; then
        return 1
    fi
    if [[ ! -f "$RVC_PUBKEYS" || -L "$RVC_PUBKEYS" ]]; then
        return 1
    fi
    got="$(_rvc_keystore_count)"
    if [[ "$got" -ne "$RVC_KEYS" ]]; then
        return 1
    fi
    got="$(grep -cE '^0x[0-9a-f]{96}$' "$RVC_PUBKEYS" || true)"
    if [[ "$got" -ne "$RVC_KEYS" ]]; then
        return 1
    fi
    got="$(grep -cE '=' "$RVC_PASSWORDS" || true)"
    [[ "$got" -eq "$RVC_KEYS" ]]
}

_iter_vc_dir_pubkeys() {
    local d base
    shopt -s nullglob
    for d in "${VC_DIR}/validators"/0x*; do
        if [[ -d "$d" && ! -L "$d" && -f "${d}/voting-keystore.json" && ! -L "${d}/voting-keystore.json" ]]; then
            base="$(basename -- "$d")"
            normalize_pubkey "$base"
        fi
    done
    shopt -u nullglob
}

_iter_rvc_keystore_pubkeys() {
    local f base pk
    shopt -s nullglob
    for f in "${RVC_DIR}"/keystore-0x*.json; do
        if [[ -f "$f" && ! -L "$f" ]]; then
            base="$(basename -- "$f")"
            pk="${base#keystore-}"
            pk="${pk%.json}"
            if printf '%s\n' "$base" | grep -qE '^keystore-0x[0-9a-f]{96}\.json$'; then
                normalize_pubkey "$pk"
            fi
        fi
    done
    shopt -u nullglob
}

_write_norm_sorted() {
    local src="$1"
    local dest="$2"
    if [[ ! -f "$src" ]]; then
        : >"$dest"
        return 0
    fi
    grep -E '^[0-9a-f]{96}$' "$src" | LC_ALL=C sort -u >"$dest" || true
}

write_password_file() {
    local pubkey="$1"
    local password="$2"
    if [[ -z "$pubkey" ]]; then
        die_infra "empty pubkey for passwords.txt"
    fi
    if [[ "$pubkey" == "*" ]]; then
        die_infra "refusing wildcard password entry"
    fi
    if [[ -z "$password" ]]; then
        die_infra "empty password for ${pubkey}"
    fi
    case "$password" in
        *$'\n'*)
            die_infra "password contains newline for ${pubkey}"
            ;;
    esac
    _RVC_PW_BODY="${_RVC_PW_BODY-}${pubkey}=${password}"$'\n'
}

write_pubkeys_file() {
    local pubkey="$1"
    local norm
    norm="$(normalize_pubkey "$pubkey")"
    if ! printf '%s\n' "$norm" | grep -qE '^[0-9a-f]{96}$'; then
        die_infra "invalid pubkey for pubkeys.txt"
    fi
    _RVC_PUB_BODY="${_RVC_PUB_BODY-}0x${norm}"$'\n'
}

flatten_rvc_subset() {
    local start row pk rel src dest secret password pw_out pub_out
    umask 077
    start="$(_rvc_start_index)"
    _wipe_keys_subset "$RVC_DIR" "rvc dir"
    mkdir -p -- "$RVC_DIR"
    _refuse_symlink "$RVC_DIR" "rvc dir"
    chmod 700 "$RVC_DIR"
    _RVC_PW_BODY=""
    _RVC_PUB_BODY=""

    while IFS= read -r row; do
        [[ -n "$row" ]] || continue
        pk="$(printf '%s\n' "$row" | jq -r '.pubkey')"
        rel="$(printf '%s\n' "$row" | jq -r '.keystore_path')"
        pk="0x$(normalize_pubkey "$pk")"
        src="${KEYS_DIR}/${rel}"
        dest="${RVC_DIR}/keystore-${pk}.json"
        secret="${VALTOOLS_DIR}/secrets/${pk}"
        if [[ -L "$src" ]]; then
            die_infra "keystore is a symlink: ${src}"
        fi
        if [[ ! -f "$src" ]]; then
            die_infra "missing valtools keystore: ${src}"
        fi
        if [[ -L "$secret" ]]; then
            die_infra "secret is a symlink: ${secret}"
        fi
        if [[ ! -f "$secret" ]]; then
            die_infra "missing valtools secret: ${secret}"
        fi
        _refuse_symlink "$dest" "rvc keystore dest"
        _copy_file_nofollow "$src" "$dest"
        password="$(<"$secret")"
        write_password_file "$pk" "$password"
        password=""
        write_pubkeys_file "$pk"
    done < <(jq -c --argjson start "$start" '.validators[] | select(.index >= $start)' "$MANIFEST_JSON")

    pw_out="$_RVC_PW_BODY"
    pub_out="$_RVC_PUB_BODY"
    _RVC_PW_BODY=""
    _RVC_PUB_BODY=""
    printf '%s' "$pw_out" | _write_file_atomic "$RVC_PASSWORDS"
    pw_out=""
    printf '%s' "$pub_out" | _write_file_atomic "$RVC_PUBKEYS"
    pub_out=""
    chmod 600 "$RVC_PASSWORDS" "$RVC_PUBKEYS"
}

split_keys() {
    local start row pk rel src dest secret
    umask 077
    log_info "splitting validator keys into vc and rvc subsets"
    _refuse_symlink "$KEYS_DIR" "keys dir"
    _refuse_symlink "$VALTOOLS_DIR" "valtools dir"
    start="$(_rvc_start_index)"
    _wipe_keys_subset "$VC_DIR" "vc dir"
    mkdir -p -- "${VC_DIR}/validators" "${VC_DIR}/secrets"
    chmod 700 "$VC_DIR" "${VC_DIR}/validators" "${VC_DIR}/secrets"

    while IFS= read -r row; do
        [[ -n "$row" ]] || continue
        pk="$(printf '%s\n' "$row" | jq -r '.pubkey')"
        rel="$(printf '%s\n' "$row" | jq -r '.keystore_path')"
        pk="0x$(normalize_pubkey "$pk")"
        src="${KEYS_DIR}/${rel}"
        dest="${VC_DIR}/validators/${pk}/voting-keystore.json"
        secret="${VALTOOLS_DIR}/secrets/${pk}"
        if [[ -L "$src" ]]; then
            die_infra "keystore is a symlink: ${src}"
        fi
        if [[ ! -f "$src" ]]; then
            die_infra "missing valtools keystore: ${src}"
        fi
        if [[ -L "$secret" ]]; then
            die_infra "secret is a symlink: ${secret}"
        fi
        if [[ ! -f "$secret" ]]; then
            die_infra "missing valtools secret: ${secret}"
        fi
        _install_file 600 "$src" "$dest"
        _install_file 600 "$secret" "${VC_DIR}/secrets/${pk}"
    done < <(jq -c --argjson start "$start" '.validators[] | select(.index < $start)' "$MANIFEST_JSON")

    flatten_rvc_subset
}

assert_disjoint_keysets() {
    local work start n_vc n_rvc n_overlap n_pw n_pub n_pub_all n_ks n_pw_uniq
    local want_vc f base ks_pk key val line pk
    umask 077
    want_vc="$(_rvc_start_index)"
    start="$(_rvc_start_index)"
    if [[ ! -d "$KEYS_DIR" || -L "$KEYS_DIR" ]]; then
        die_infra "keys dir missing: ${KEYS_DIR}"
    fi
    work="$(mktemp -d "${KEYS_DIR}/.assert.XXXXXX")"
    chmod 700 "$work"

    _iter_vc_dir_pubkeys >"$work/vc.raw" || true
    _iter_rvc_keystore_pubkeys >"$work/rvc.raw" || true
    _write_norm_sorted "$work/vc.raw" "$work/vc"
    _write_norm_sorted "$work/rvc.raw" "$work/rvc"

    jq -r '.validators[].pubkey' "$MANIFEST_JSON" >"$work/man.in"
    : >"$work/man.raw"
    while IFS= read -r pk; do
        [[ -n "$pk" ]] || continue
        normalize_pubkey "$pk"
    done <"$work/man.in" >"$work/man.raw"
    _write_norm_sorted "$work/man.raw" "$work/manifest"

    jq -r --argjson start "$start" '.validators[] | select(.index >= $start) | .pubkey' "$MANIFEST_JSON" >"$work/tail.in"
    : >"$work/tail.raw"
    while IFS= read -r pk; do
        [[ -n "$pk" ]] || continue
        normalize_pubkey "$pk"
    done <"$work/tail.in" >"$work/tail.raw"
    _write_norm_sorted "$work/tail.raw" "$work/tail"

    n_vc="$(grep -cE '^[0-9a-f]{96}$' "$work/vc" || true)"
    n_rvc="$(grep -cE '^[0-9a-f]{96}$' "$work/rvc" || true)"

    if [[ "$n_vc" -ne "$want_vc" || "$n_rvc" -ne "$RVC_KEYS" ]]; then
        rm -rf -- "$work"
        die_infra "key subset counts vc=${n_vc} rvc=${n_rvc} (want vc=${want_vc} rvc=${RVC_KEYS})"
    fi

    comm -12 "$work/vc" "$work/rvc" >"$work/overlap" || true
    n_overlap="$(grep -cE '^[0-9a-f]{96}$' "$work/overlap" || true)"
    if [[ "$n_overlap" -ne 0 ]]; then
        rm -rf -- "$work"
        die_infra "vc and rvc pubkey sets intersect (vc=${n_vc} rvc=${n_rvc})"
    fi

    LC_ALL=C sort -u "$work/vc" "$work/rvc" >"$work/union"
    comm -3 "$work/union" "$work/manifest" >"$work/union_diff" || true
    if [[ -s "$work/union_diff" ]]; then
        rm -rf -- "$work"
        die_infra "vc ∪ rvc != manifest (vc=${n_vc} rvc=${n_rvc})"
    fi

    comm -3 "$work/rvc" "$work/tail" >"$work/tail_diff" || true
    if [[ -s "$work/tail_diff" ]]; then
        rm -rf -- "$work"
        die_infra "rvc set != manifest index>=N-K tail (vc=${n_vc} rvc=${n_rvc})"
    fi

    n_ks=0
    shopt -s nullglob
    for f in "${RVC_DIR}"/keystore-0x*.json; do
        base="$(basename -- "$f")"
        if ! printf '%s\n' "$base" | grep -qE '^keystore-0x[0-9a-f]{96}\.json$'; then
            shopt -u nullglob
            rm -rf -- "$work"
            die_infra "unexpected rvc keystore name ${base} (vc=${n_vc} rvc=${n_rvc})"
        fi
        if [[ -L "$f" || ! -f "$f" ]]; then
            shopt -u nullglob
            rm -rf -- "$work"
            die_infra "rvc keystore is not a regular file (vc=${n_vc} rvc=${n_rvc})"
        fi
        if ! jq -e '.crypto.kdf' "$f" >/dev/null; then
            shopt -u nullglob
            rm -rf -- "$work"
            die_infra "rvc keystore missing .crypto.kdf (vc=${n_vc} rvc=${n_rvc})"
        fi
        n_ks=$((n_ks + 1))
    done
    shopt -u nullglob
    if [[ "$n_ks" -ne "$RVC_KEYS" ]]; then
        rm -rf -- "$work"
        die_infra "rvc keystore count ${n_ks} != ${RVC_KEYS} (vc=${n_vc} rvc=${n_rvc})"
    fi

    if [[ ! -f "$RVC_PASSWORDS" || -L "$RVC_PASSWORDS" ]]; then
        rm -rf -- "$work"
        die_infra "passwords.txt missing (vc=${n_vc} rvc=${n_rvc})"
    fi
    if [[ -z "$(find "$RVC_PASSWORDS" -perm 600 -type f 2>/dev/null)" ]]; then
        rm -rf -- "$work"
        die_infra "passwords.txt must be mode 0600 (vc=${n_vc} rvc=${n_rvc})"
    fi

    : >"$work/pw.raw"
    n_pw=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -n "$line" ]] || continue
        case "$line" in
            *=*)
                ;;
            *)
                rm -rf -- "$work"
                die_infra "passwords.txt line missing '=' (vc=${n_vc} rvc=${n_rvc})"
                ;;
        esac
        key="${line%%=*}"
        val="${line#*=}"
        if [[ "$key" == "*" ]]; then
            rm -rf -- "$work"
            die_infra "refusing wildcard password entry (vc=${n_vc} rvc=${n_rvc})"
        fi
        if [[ -z "$val" ]]; then
            rm -rf -- "$work"
            die_infra "empty password value (vc=${n_vc} rvc=${n_rvc})"
        fi
        normalize_pubkey "$key" >>"$work/pw.raw"
        n_pw=$((n_pw + 1))
    done <"$RVC_PASSWORDS"
    _write_norm_sorted "$work/pw.raw" "$work/pw"

    if [[ "$n_pw" -ne "$RVC_KEYS" ]]; then
        rm -rf -- "$work"
        die_infra "passwords.txt line count ${n_pw} != ${RVC_KEYS} (vc=${n_vc} rvc=${n_rvc})"
    fi
    n_pw_uniq="$(grep -cE '^[0-9a-f]{96}$' "$work/pw" || true)"
    if [[ "$n_pw_uniq" -ne "$n_pw" ]]; then
        rm -rf -- "$work"
        die_infra "passwords.txt has duplicate pubkeys (vc=${n_vc} rvc=${n_rvc})"
    fi

    : >"$work/ks_pk.raw"
    shopt -s nullglob
    for f in "${RVC_DIR}"/keystore-0x*.json; do
        if [[ -f "$f" && ! -L "$f" ]]; then
            ks_pk="$(jq -r '.pubkey // empty' "$f")"
            if [[ -z "$ks_pk" ]]; then
                shopt -u nullglob
                rm -rf -- "$work"
                die_infra "rvc keystore missing .pubkey (vc=${n_vc} rvc=${n_rvc})"
            fi
            normalize_pubkey "$ks_pk" >>"$work/ks_pk.raw"
        fi
    done
    shopt -u nullglob
    _write_norm_sorted "$work/ks_pk.raw" "$work/ks_pk"

    comm -3 "$work/pw" "$work/ks_pk" >"$work/pw_diff" || true
    if [[ -s "$work/pw_diff" ]]; then
        rm -rf -- "$work"
        die_infra "passwords.txt is not a bijection with rvc keystores (vc=${n_vc} rvc=${n_rvc})"
    fi
    comm -3 "$work/pw" "$work/rvc" >"$work/pw_fn_diff" || true
    if [[ -s "$work/pw_fn_diff" ]]; then
        rm -rf -- "$work"
        die_infra "passwords.txt does not match rvc filenames (vc=${n_vc} rvc=${n_rvc})"
    fi

    if [[ ! -f "$RVC_PUBKEYS" || -L "$RVC_PUBKEYS" ]]; then
        rm -rf -- "$work"
        die_infra "pubkeys.txt missing (vc=${n_vc} rvc=${n_rvc})"
    fi
    n_pub="$(grep -cE '^0x[0-9a-f]{96}$' "$RVC_PUBKEYS" || true)"
    if [[ "$n_pub" -ne "$RVC_KEYS" ]]; then
        rm -rf -- "$work"
        die_infra "pubkeys.txt line count ${n_pub} != ${RVC_KEYS} (vc=${n_vc} rvc=${n_rvc})"
    fi
    n_pub_all="$(grep -cE '.' "$RVC_PUBKEYS" || true)"
    if [[ "$n_pub_all" -ne "$n_pub" ]]; then
        rm -rf -- "$work"
        die_infra "pubkeys.txt has non 0x-prefixed lines (vc=${n_vc} rvc=${n_rvc})"
    fi
    : >"$work/pubtxt.raw"
    while IFS= read -r pk; do
        [[ -n "$pk" ]] || continue
        normalize_pubkey "$pk"
    done <"$RVC_PUBKEYS" >"$work/pubtxt.raw"
    _write_norm_sorted "$work/pubtxt.raw" "$work/pubtxt"
    comm -3 "$work/pubtxt" "$work/rvc" >"$work/pub_diff" || true
    if [[ -s "$work/pub_diff" ]]; then
        rm -rf -- "$work"
        die_infra "pubkeys.txt != rvc set (vc=${n_vc} rvc=${n_rvc})"
    fi

    while IFS= read -r pk; do
        [[ -n "$pk" ]] || continue
        if [[ ! -f "${VC_DIR}/secrets/0x${pk}" || -L "${VC_DIR}/secrets/0x${pk}" ]]; then
            rm -rf -- "$work"
            die_infra "missing vc secret for 0x${pk} (vc=${n_vc} rvc=${n_rvc})"
        fi
    done <"$work/vc"

    rm -rf -- "$work"
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
    _lockdown_tree "$VALTOOLS_DIR"
    _lockdown_tree "$VC_DIR"
    _lockdown_tree "$RVC_DIR"
    if [[ -f "$MANIFEST_JSON" && ! -L "$MANIFEST_JSON" ]]; then
        chmod 600 "$MANIFEST_JSON"
    fi
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
    if [[ -z "$VC_DIR" || "$VC_DIR" == "/" || -z "$RVC_DIR" || "$RVC_DIR" == "/" ]]; then
        die_infra "refusing to wipe empty vc/rvc path"
    fi
    _refuse_symlink "$VC_DIR" "vc dir"
    _refuse_symlink "$RVC_DIR" "rvc dir"
    # out-loc must be absent; eth2-val-tools errors if it exists. Do not pre-create valtools/.
    # Wipe subsets with valtools so a crash cannot leave stale vc/rvc beside new secrets.
    rm -rf -- "$VALTOOLS_DIR"
    rm -rf -- "$VC_DIR" "$RVC_DIR"
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
    log_info "  6. split_keys"
    log_info "  7. assert_disjoint_keysets"
}

main() {
    parse_common_flags "$@"
    _bind_keys_paths
    require_chain_1337
    require_cmd jq
    require_cmd python3
    _require_positive_int "NUM_VALIDATORS" "${NUM_VALIDATORS:-}"
    _require_split_bounds

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
        if [[ "$FORCE" != "1" ]] && keys_exist && vc_subset_ready && rvc_subset_ready; then
            log_info "would skip vc/ and rvc/ (already present)"
        else
            log_info "would split keys into vc/ and rvc/"
        fi
        log_success "dry-run complete"
        return 0
    fi

    mkdir -p -- "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"

    local need_split=0
    if [[ "$FORCE" == "1" ]] || ! keys_exist; then
        require_cmd "$DOCKER"
        generate_keystores
        need_split=1
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

    if [[ "$need_split" -eq 1 ]] || ! vc_subset_ready || ! rvc_subset_ready; then
        split_keys
    else
        log_info "skipping vc/ and rvc/ (already present)"
    fi
    _lockdown_keys
    assert_disjoint_keysets
    log_success "validator keys ready"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
