#!/usr/bin/env bash
# Render RVC config from the live BN, start the native binary, wait for /health.

set -euo pipefail

# Process env wins over devnet.env (CHAIN_ID=1, RVC_METRICS_PORT, …).
# Capture before common.sh sources the file, which would otherwise overwrite.
_OV_CHAIN_ID=0
_OV_METRICS=0
_KEEP_CHAIN_ID=""
_KEEP_METRICS=""
if [[ "${CHAIN_ID+x}" == "x" ]]; then
    _OV_CHAIN_ID=1
    _KEEP_CHAIN_ID="$CHAIN_ID"
fi
if [[ "${RVC_METRICS_PORT+x}" == "x" ]]; then
    _OV_METRICS=1
    _KEEP_METRICS="$RVC_METRICS_PORT"
fi

_ATTACH_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_ATTACH_DIR}/lib/common.sh"

if [[ "$_OV_CHAIN_ID" -eq 1 ]]; then
    CHAIN_ID="$_KEEP_CHAIN_ID"
    export CHAIN_ID
fi
if [[ "$_OV_METRICS" -eq 1 ]]; then
    RVC_METRICS_PORT="$_KEEP_METRICS"
    export RVC_METRICS_PORT
fi
unset _OV_CHAIN_ID _OV_METRICS _KEEP_CHAIN_ID _KEEP_METRICS

# Stub tests override RVC_BIN. Relative paths resolve against the repo root,
# never CWD. This script never builds the binary.
RVC_BIN="${RVC_BIN:-target/release/rvc}"
ATTACH_TIMEOUT="${ATTACH_TIMEOUT:-120}"
RVC_PID=""
_REPO_ROOT=""

_refuse_symlink() {
    local path="$1"
    local what="$2"
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink ${what}: ${path}"
    fi
}

_require_uint() {
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

_require_split_bounds() {
    _require_uint "NUM_VALIDATORS" "${NUM_VALIDATORS:-}"
    _require_uint "RVC_KEYS" "${RVC_KEYS:-}"
    if [[ "$RVC_KEYS" -ge "$NUM_VALIDATORS" ]]; then
        die_usage "RVC_KEYS must be < NUM_VALIDATORS (got ${RVC_KEYS} >= ${NUM_VALIDATORS})"
    fi
}

_rvc_start_index() {
    printf '%s' "$((NUM_VALIDATORS - RVC_KEYS))"
}

_rvc_health_url() {
    _require_uint "RVC_METRICS_PORT" "${RVC_METRICS_PORT:-}"
    printf 'http://127.0.0.1:%s/health' "${RVC_METRICS_PORT}"
}

_rvc_endpoint() {
    _require_uint "RVC_METRICS_PORT" "${RVC_METRICS_PORT:-}"
    printf 'http://127.0.0.1:%s' "${RVC_METRICS_PORT}"
}

_normalize_gvr() {
    local s="$1"
    s="$(printf '%s' "$s" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
    s="${s#0x}"
    printf '%s' "$s"
}

_pidfile_pid() {
    local pidfile="${RVC_DIR}/rvc.pid"
    local pid
    if [[ -L "$pidfile" ]]; then
        return 1
    fi
    if [[ ! -f "$pidfile" ]]; then
        return 1
    fi
    pid="$(tr -d '[:space:]' <"$pidfile")"
    case "$pid" in
        '' | *[!0-9]* | 0 | 1)
            return 1
            ;;
    esac
    printf '%s' "$pid"
}

_pid_alive() {
    local pid="${1:-}"
    local st
    case "$pid" in
        '' | *[!0-9]* | 0 | 1 | "$$")
            return 1
            ;;
    esac
    kill -0 "$pid" 2>/dev/null || return 1
    # kill -0 succeeds on zombies; refuse STAT=Z so a dead stub cannot
    # pair with leftover /health 200.
    st="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
    st="$(printf '%s' "$st" | tr -d '[:space:]')"
    case "$st" in
        '' | Z*)
            wait "$pid" 2>/dev/null || true
            return 1
            ;;
    esac
    return 0
}

_repo_root() {
    if [[ -n "${_REPO_ROOT}" ]]; then
        printf '%s' "${_REPO_ROOT}"
        return 0
    fi
    _REPO_ROOT="$(cd -P -- "${SCRIPT_DIR}/../.." >/dev/null && pwd -P)" \
        || die_infra "cannot resolve repository root"
    printf '%s' "${_REPO_ROOT}"
}

# Resolve RVC_BIN to an absolute path against the repo root (not CWD).
_resolve_rvc_bin() {
    local bin="${RVC_BIN:-target/release/rvc}"
    local root
    root="$(_repo_root)"
    case "$bin" in
        /*) ;;
        *)
            bin="${root}/${bin#./}"
            ;;
    esac
    bin="$(
        CHECK_BIN="$bin" python3 -c 'import os; print(os.path.normpath(os.environ["CHECK_BIN"]))'
    )" || die_infra "cannot normalize RVC_BIN"
    case "$bin" in
        /*) ;;
        *)
            die_usage "RVC_BIN must resolve to an absolute path (got ${bin})"
            ;;
    esac
    if [[ ! -e "$bin" ]]; then
        die_infra "RVC binary not found at ${bin} (this script never builds it)"
    fi
    if [[ -L "$bin" ]]; then
        die_usage "refusing symlink RVC_BIN: ${bin}"
    fi
    if [[ ! -f "$bin" ]]; then
        die_usage "RVC_BIN is not a regular file: ${bin}"
    fi
    if [[ ! -x "$bin" ]]; then
        die_usage "RVC_BIN is not executable: ${bin}"
    fi
    RVC_BIN="$bin"
}

# True iff pid is live and is the binary we spawned (exe/argv/comm vs RVC_BIN).
_pid_is_our_rvc() {
    local pid="${1:-}"
    _pid_alive "$pid" || return 1
    CHECK_PID="$pid" CHECK_BIN="$RVC_BIN" python3 - <<'PY'
import os, subprocess, sys

pid = int(os.environ["CHECK_PID"])
want = os.path.normpath(os.environ["CHECK_BIN"])
base = os.path.basename(want)
if pid <= 1:
    raise SystemExit(1)

def ok():
    raise SystemExit(0)

try:
    waited, _status = os.waitpid(pid, os.WNOHANG)
    if waited == pid:
        raise SystemExit(1)
except OSError:
    pass

def is_zombie():
    try:
        st = open("/proc/%d/stat" % pid, encoding="utf-8").read()
        comm_end = st.rfind(")")
        if comm_end != -1 and comm_end + 2 < len(st) and st[comm_end + 2] == "Z":
            return True
    except OSError:
        pass
    for col in ("stat=", "state="):
        try:
            out = subprocess.check_output(
                ["ps", "-p", str(pid), "-o", col],
                stderr=subprocess.DEVNULL,
            )
            token = out.decode("utf-8", "replace").strip().split()
            if token and token[0].startswith("Z"):
                return True
        except (OSError, subprocess.CalledProcessError):
            continue
    return False

if is_zombie():
    raise SystemExit(1)

try:
    exe = os.readlink("/proc/%d/exe" % pid)
    exe = exe.split(" (deleted)")[0]
    if os.path.normpath(exe) == want:
        ok()
    if os.path.exists(want) and os.path.exists(exe):
        if os.path.realpath(exe) == os.path.realpath(want):
            ok()
except OSError:
    pass

parts = []
try:
    raw = open("/proc/%d/cmdline" % pid, "rb").read().split(b"\0")
    parts = [p.decode("utf-8", "replace") for p in raw if p]
except OSError:
    try:
        out = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "command="],
            stderr=subprocess.DEVNULL,
        )
        parts = out.decode("utf-8", "replace").split()
    except (OSError, subprocess.CalledProcessError):
        parts = []

for p in parts:
    n = os.path.normpath(p)
    if n == want or os.path.basename(n) == base:
        ok()
    if want and want in p:
        ok()

try:
    comm = subprocess.check_output(
        ["ps", "-p", str(pid), "-o", "comm="],
        stderr=subprocess.DEVNULL,
    ).decode("utf-8", "replace").strip()
    if comm == base or (base and comm == base[:15]):
        ok()
except (OSError, subprocess.CalledProcessError):
    pass

raise SystemExit(1)
PY
}

_nofollow_truncate() {
    local path="$1"
    local rc=0
    if [[ -z "$path" ]]; then
        die_usage "_nofollow_truncate requires a path"
    fi
    _refuse_symlink "$(dirname -- "$path")" "rvc.log parent"
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
        die_usage "refusing symlink rvc.log: ${path}"
    fi
    if [[ "$rc" -ne 0 ]]; then
        die_infra "cannot create ${path}"
    fi
}

# Copy allowing empty source; refuses source/dest/parent symlinks (O_NOFOLLOW).
_nofollow_copy() {
    local src="$1"
    local dest="$2"
    local rc=0
    if [[ -z "$src" || -z "$dest" ]]; then
        die_usage "_nofollow_copy requires SRC and DEST"
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
fail_if_symlink(os.path.dirname(os.path.abspath(src)))
fail_if_symlink(os.path.dirname(os.path.abspath(dest)))
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

tmp = dest + ".tmp." + os.urandom(16).hex()
fd = -1
try:
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    if data:
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
        die_usage "refusing symlink rvc.log: ${src} -> ${dest}"
    fi
    if [[ "$rc" -ne 0 ]]; then
        die_infra "failed to copy ${dest}"
    fi
    chmod 600 "$dest" || true
}

parse_attach_flags() {
    local -a rest
    rest=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --docker | --docker=*)
                die_usage "attach-rvc.sh --docker is not implemented (Phase 6 / DN-15)"
                ;;
            --timeout)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--timeout requires a positive integer"
                fi
                ATTACH_TIMEOUT="$2"
                shift 2
                ;;
            --timeout=*)
                ATTACH_TIMEOUT="${1#--timeout=}"
                shift
                ;;
            *)
                rest+=("$1")
                shift
                ;;
        esac
    done
    _require_uint "--timeout" "${ATTACH_TIMEOUT:-}"
    if [[ ${#rest[@]} -eq 0 ]]; then
        parse_common_flags
    else
        parse_common_flags "${rest[@]}"
    fi
}

# Compare an existing slashing DB GVR to the local genesis file (A3-9).
# Missing DB is fine (--init-slashing-db). Mismatched or unreadable ⇒ 2.
assert_slashing_db_gvr() {
    local db="${RVC_DIR}/slashing_protection.sqlite"
    local expected got rc=0
    local genesis="${GENESIS_DIR}/genesis_validators_root.txt"

    if [[ ! -e "$db" ]]; then
        return 0
    fi
    if [[ -L "$db" ]]; then
        die_usage "refusing symlink slashing DB: ${db}; purge ${db}"
    fi
    if [[ ! -f "$db" ]]; then
        die_usage "unreadable slashing protection DB at ${db}; purge ${db}"
    fi
    if [[ ! -f "$genesis" ]]; then
        die_infra "genesis_validators_root.txt not found at ${genesis}; run 01-genesis.sh --force"
    fi
    expected="$(_normalize_gvr "$(tr -d '[:space:]' <"$genesis")")"
    got="$(
        python3 -c '
import os, sqlite3, stat, sys

path = sys.argv[1]
try:
    st = os.lstat(path)
except OSError:
    raise SystemExit(1)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
    raise SystemExit(1)
try:
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        row = con.execute(
            "SELECT value FROM metadata WHERE key = ?",
            ("genesis_validators_root",),
        ).fetchone()
    finally:
        con.close()
except Exception:
    raise SystemExit(1)
if not row or row[0] is None:
    raise SystemExit(1)
text = str(row[0]).strip()
if not text:
    raise SystemExit(1)
sys.stdout.write(text)
' "$db"
    )" || rc=$?
    if [[ "$rc" -ne 0 || -z "$got" ]]; then
        die_usage "unreadable slashing protection DB at ${db}; purge ${db}"
    fi
    got="$(_normalize_gvr "$got")"
    if [[ -z "$expected" || "$got" != "$expected" ]]; then
        die_usage "stale slashing protection DB at ${db} (genesis_validators_root mismatch); purge ${db}"
    fi
}

_validate_inputs() {
    local pubkeys n_pub
    _refuse_symlink "$DATA_DIR" "data dir"
    _require_split_bounds
    validate_data_exists "manifest.json" "${KEYS_DIR}/manifest.json" "02-keys.sh"
    _refuse_symlink "${KEYS_DIR}/rvc" "rvc keys dir"
    if [[ ! -d "${KEYS_DIR}/rvc" ]]; then
        die_usage "data/keys/rvc not found at ${KEYS_DIR}/rvc (produced by 02-keys.sh)"
    fi
    validate_data_exists "passwords.txt" "${KEYS_DIR}/rvc/passwords.txt" "02-keys.sh"
    pubkeys="${KEYS_DIR}/rvc/pubkeys.txt"
    validate_data_exists "pubkeys.txt" "$pubkeys" "02-keys.sh"
    n_pub="$(grep -cE '^0x[0-9a-f]{96}$' "$pubkeys" || true)"
    if [[ "$n_pub" -ne "$RVC_KEYS" ]]; then
        die_usage "pubkeys.txt has ${n_pub} entries, expected ${RVC_KEYS} (produced by 02-keys.sh)"
    fi
    validate_data_exists "genesis_validators_root.txt" \
        "${GENESIS_DIR}/genesis_validators_root.txt" "01-genesis.sh"
    assert_slashing_db_gvr
}

_probe_bn() {
    local genesis_json spec_json gvr head versions
    genesis_json="$(bn_genesis_json)"
    gvr="$(printf '%s\n' "$genesis_json" | parse_genesis_validators_root)"
    assert_gvr_matches_local "$gvr"
    spec_json="$(bn_spec_json)"
    versions="$(printf '%s\n' "$spec_json" | parse_fork_versions)"
    head="$(bn_head_fork_version)"
    set -f
    # Word-split the newline-separated schedule. Globbing is off.
    # shellcheck disable=SC2086
    assert_fork_in_schedule "$head" $versions
    set +f
}

# True iff pid is the process listening on RVC_METRICS_PORT (binds /health to us).
_health_owned_by_pid() {
    local pid="${1:-}"
    _pid_alive "$pid" || return 1
    CHECK_PID="$pid" CHECK_PORT="${RVC_METRICS_PORT}" python3 - <<'PY'
import os, subprocess, sys

pid = int(os.environ["CHECK_PID"])
port = int(os.environ["CHECK_PORT"])
pids = set()

try:
    out = subprocess.check_output(
        ["lsof", "-nP", "-t", "-iTCP:%d" % port, "-sTCP:LISTEN"],
        stderr=subprocess.DEVNULL,
    )
    for tok in out.decode("utf-8", "replace").split():
        if tok.isdigit():
            pids.add(int(tok))
except (OSError, subprocess.CalledProcessError):
    pass

if pid not in pids:
    hex_port = "%04X" % port
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = open(table, encoding="utf-8").read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 10 or cols[3] != "0A":
                continue
            local = cols[1]
            if ":" not in local:
                continue
            if local.rsplit(":", 1)[-1].upper() == hex_port:
                inodes.add(cols[9])
    if inodes:
        try:
            for name in os.listdir("/proc"):
                if not name.isdigit():
                    continue
                fd_dir = "/proc/%s/fd" % name
                try:
                    fds = os.listdir(fd_dir)
                except OSError:
                    continue
                for fd in fds:
                    try:
                        tgt = os.readlink(os.path.join(fd_dir, fd))
                    except OSError:
                        continue
                    if tgt.startswith("socket:[") and tgt[8:-1] in inodes:
                        pids.add(int(name))
        except OSError:
            pass

if pid in pids:
    raise SystemExit(0)
raise SystemExit(1)
PY
}

is_rvc_attached() {
    local pid url
    pid="$(_pidfile_pid)" || return 1
    _pid_is_our_rvc "$pid" || return 1
    url="$(_rvc_health_url)"
    "$CURL" -sS --fail --max-time 2 -- "$url" >/dev/null 2>&1 || return 1
    _health_owned_by_pid "$pid"
}

_kill_rvc() {
    local pidfile="${RVC_DIR}/rvc.pid"
    local pid=""
    pid="$(_pidfile_pid)" || pid=""
    if [[ -n "$pid" ]]; then
        if _pid_is_our_rvc "$pid"; then
            log_info "killing rvc pid ${pid}"
            kill -KILL "$pid" 2>/dev/null || true
            while _pid_alive "$pid"; do
                sleep 1
            done
        else
            log_warn "stale pidfile pid ${pid} is not our rvc; skip kill"
        fi
    fi
    if [[ -f "$pidfile" && ! -L "$pidfile" ]]; then
        rm -f -- "$pidfile"
    fi
    RVC_PID=""
}

_copy_rvc_log() {
    local log="${RVC_DIR}/rvc.log"
    local dest_dir dest
    dest_dir="$(resolve_run_dir)/logs"
    dest="${dest_dir}/rvc.log"
    mkdir -p -- "$dest_dir"
    _refuse_symlink "$dest_dir" "log dir"
    _refuse_symlink "$dest" "copied rvc.log"
    if [[ -L "$log" ]]; then
        die_usage "refusing symlink rvc.log: ${log}"
    fi
    if [[ -f "$log" ]]; then
        _nofollow_copy "$log" "$dest"
    fi
}

_fail_timeout() {
    _kill_rvc
    _copy_rvc_log
    die_notready "RVC /health did not become ready within ${ATTACH_TIMEOUT}s"
}

_wait_attempts() {
    local a
    a=$((ATTACH_TIMEOUT / 2))
    if [[ "$a" -lt 1 ]]; then
        a=1
    fi
    printf '%s' "$a"
}

spawn_rvc() {
    local config="${RVC_DIR}/config.toml"
    local log="${RVC_DIR}/rvc.log"
    local pidfile="${RVC_DIR}/rvc.pid"

    validate_data_exists "config.toml" "$config" "attach-rvc.sh"
    _refuse_symlink "$RVC_DIR" "rvc dir"
    mkdir -p -- "$RVC_DIR"
    umask 077
    _nofollow_truncate "$log"
    if [[ -L "$log" ]]; then
        die_usage "refusing symlink rvc.log: ${log}"
    fi
    if [[ -L "$pidfile" ]]; then
        die_usage "refusing symlink pidfile: ${pidfile}"
    fi

    # Capture stdout/stderr into rvc.log. A pipeline `tee` would own $! and
    # die when this script exits, SIGPIPE-ing a live RVC. MNEMONIC is dropped
    # so the child cannot inherit the dev mnemonic from devnet.env.
    env -u MNEMONIC \
        "$RVC_BIN" start -c "$config" --init-slashing-db --metrics-address 127.0.0.1 \
        >>"$log" 2>&1 &
    RVC_PID=$!
    printf '%s\n' "$RVC_PID" >"$pidfile"
    chmod 600 "$pidfile"
    log_info "spawned rvc pid ${RVC_PID}"
}

write_rvc_json() {
    local out tmp pid pubkeys config_path endpoint start_idx
    out="${RUN_DIR}/rvc.json"
    tmp="${out}.tmp.$$"
    pid="${RVC_PID:-}"
    if [[ -z "$pid" ]]; then
        pid="$(_pidfile_pid)" || pid=""
    fi
    case "$pid" in
        '' | *[!0-9]*)
            die_infra "rvc pid is missing; cannot write rvc.json"
            ;;
    esac
    pubkeys="${KEYS_DIR}/rvc/pubkeys.txt"
    config_path="${RVC_DIR}/config.toml"
    endpoint="$(_rvc_endpoint)"
    start_idx="$(_rvc_start_index)"
    _refuse_symlink "$out" "rvc.json"
    _refuse_symlink "$(dirname -- "$out")" "run dir"
    RVC_JSON_OUT="$out" \
        RVC_JSON_TMP="$tmp" \
        RVC_JSON_ENDPOINT="$endpoint" \
        RVC_JSON_PID="$pid" \
        RVC_JSON_START="$start_idx" \
        RVC_JSON_END="$NUM_VALIDATORS" \
        RVC_JSON_CONFIG="$config_path" \
        RVC_JSON_PUBKEYS="$pubkeys" \
        python3 - <<'PY' || die_infra "failed to write rvc.json"
import json, os, sys
from datetime import datetime, timezone

out = os.environ["RVC_JSON_OUT"]
tmp = os.environ["RVC_JSON_TMP"]
pub_path = os.environ["RVC_JSON_PUBKEYS"]
pubkeys = []
with open(pub_path, encoding="utf-8") as fh:
    for raw in fh:
        line = raw.strip()
        if not line:
            continue
        pubkeys.append(line)

doc = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "endpoint": os.environ["RVC_JSON_ENDPOINT"],
    "pid": int(os.environ["RVC_JSON_PID"]),
    "key_range": [int(os.environ["RVC_JSON_START"]), int(os.environ["RVC_JSON_END"])],
    "pubkeys": pubkeys,
    "config_path": os.environ["RVC_JSON_CONFIG"],
}
try:
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except OSError:
    raise SystemExit(1)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, allow_nan=False, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, out)
    tmp = ""
finally:
    if tmp:
        try:
            os.unlink(tmp)
        except OSError:
            pass
os.chmod(out, 0o600)
PY
}

_copy_run_tomls() {
    local dest="${RUN_DIR}/rvc"
    _refuse_symlink "$dest" "run rvc dir"
    mkdir -p -- "$dest"
    chmod 700 "$dest" || true
    _copy_600 "${RVC_DIR}/config.toml" "${dest}/config.toml"
    _copy_600 "${RVC_DIR}/validators.toml" "${dest}/validators.toml"
}

_inventory_attach_rows() {
    inventory_append pid rvc "${RVC_DIR}/rvc.pid"
    inventory_append slashing_db slashing_protection.sqlite \
        "${RVC_DIR}/slashing_protection.sqlite"
}

print_attach_plan() {
    log_info "attach plan:"
    log_info "  1. probe BN genesis / fork schedule"
    log_info "  2. render_rvc_config"
    log_info "  3. inventory_append pidfile + slashing DB"
    log_info "  4. spawn_rvc"
    log_info "  5. wait_for_service /health"
    log_info "  6. write rvc.json"
}

main() {
    parse_attach_flags "$@"
    require_chain_1337
    if [[ -z "${RUN_DIR:-}" ]]; then
        die_usage "--run-dir is required"
    fi
    resolve_run_dir >/dev/null
    require_cmd python3
    require_cmd jq
    require_cmd "$CURL"
    resolve_profile "${PROFILE:-fast}"
    _resolve_rvc_bin
    unset MNEMONIC || true

    _validate_inputs

    if [[ "$DRY_RUN" == "1" ]]; then
        print_attach_plan
        log_success "dry-run complete"
        return 0
    fi

    _probe_bn

    if [[ "$FORCE" == "1" ]]; then
        _kill_rvc
    elif is_rvc_attached; then
        log_info "already attached"
        log_success "rvc already attached"
        return 0
    fi

    render_rvc_config
    # ADR-009: inventory the pidfile path and slashing DB before spawn fills them.
    _inventory_attach_rows
    spawn_rvc
    if ! wait_for_service "$(_rvc_health_url)" "$(_wait_attempts)"; then
        _fail_timeout
    fi
    if ! _pid_is_our_rvc "${RVC_PID}"; then
        _fail_timeout
    fi
    if ! _health_owned_by_pid "${RVC_PID}"; then
        _fail_timeout
    fi
    disown "$RVC_PID" 2>/dev/null || true
    write_rvc_json
    _copy_run_tomls
    log_success "rvc attached"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
