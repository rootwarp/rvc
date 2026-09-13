#!/usr/bin/env bash
# Mint the run id, sequence up → attach → soak → report → down, own the exit code.

set -euo pipefail

_RUN_SH_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"

# Process env wins over sourced devnet.env (CHAIN_ID, RVC_KEYS, unpinned IMG_*, …).
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "required command not found: python3" >&2
    exit 2
fi
_OV_RESTORE="$(
    DEVNET_ENV="${_RUN_SH_DIR}/devnet.env" python3 - <<'PY'
import os, re, shlex

path = os.environ["DEVNET_ENV"]
ident = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
lines = []
with open(path, encoding="utf-8") as fh:
    for raw in fh:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if not ident.fullmatch(key) or key not in os.environ:
            continue
        lines.append("export %s=%s" % (key, shlex.quote(os.environ[key])))
print("\n".join(lines))
PY
)"

# shellcheck disable=SC1091
source "${_RUN_SH_DIR}/lib/common.sh"

if [[ -n "$_OV_RESTORE" ]]; then
    eval "$_OV_RESTORE"
fi
unset _OV_RESTORE

KEEP="${KEEP:-0}"
DOCKER_ATTACH="${DOCKER_ATTACH:-0}"
STRICT="${STRICT:-0}"
STAGES_SET=""
RUN_ID="${RUN_ID:-}"
_RUN_ID_FLAG=0
_EPOCHS_FLAG=""
_CLI_FAIL_UNDER=()
_STAGES_JSON='{}'
_STOP=0
_DID_DOWN=0
_CLEANED=0
_REUSE_RUN_JSON=0
EXIT_CODE=0
_REPO_ROOT=""

_repo_root() {
    if [[ -n "${_REPO_ROOT}" ]]; then
        printf '%s' "${_REPO_ROOT}"
        return 0
    fi
    _REPO_ROOT="$(cd -P -- "${SCRIPT_DIR}/../.." >/dev/null && pwd -P)" \
        || die_infra "cannot resolve repository root"
    printf '%s' "${_REPO_ROOT}"
}

# Resolve RVC_BIN against the repo root, never CWD. Missing ⇒ usage 2; never built here.
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
        die_usage "RVC binary not found at ${bin}; cargo build --release"
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

_rvc_version() {
    local out=""
    out="$("$RVC_BIN" --version 2>/dev/null | head -n 1 | tr -d '\r')" || out=""
    printf '%s' "$out"
}

_git_short_sha() {
    local root sha
    root="$(_repo_root)"
    sha="$(git -C "$root" rev-parse --short HEAD 2>/dev/null || true)"
    if [[ -z "$sha" ]]; then
        sha="unknown"
    fi
    printf '%s' "$sha"
}

mint_run_id() {
    local ts sha
    ts="$(date -u +"%Y%m%dT%H%M%SZ")"
    sha="$(_git_short_sha)"
    printf '%s-%s' "$ts" "$sha"
}

_require_run_id_ident() {
    local id="${1:-}"
    case "$id" in
        "" | .* | -* | *[!A-Za-z0-9._-]* | *..*)
            die_usage "invalid --run-id: ${id:-<empty>}"
            ;;
    esac
}

_assert_run_dir_under_runs() {
    local runs_canon
    if [[ -z "${RUNS_DIR:-}" || -z "${RUN_ID:-}" ]]; then
        die_usage "invalid --run-id: ${RUN_ID:-<empty>}"
    fi
    if [[ -L "$RUNS_DIR" ]]; then
        die_usage "refusing symlink RUNS_DIR: ${RUNS_DIR}"
    fi
    runs_canon="$(cd -P -- "$RUNS_DIR" >/dev/null && pwd -P)" \
        || die_usage "cannot resolve RUNS_DIR"
    if [[ "$RUN_DIR" != "${runs_canon}/${RUN_ID}" ]]; then
        die_usage "invalid --run-id: ${RUN_ID}"
    fi
}

record_exit() {
    local rc="${1:-0}"
    case "$rc" in
        '' | *[!0-9]*)
            rc=1
            ;;
    esac
    if [[ "$EXIT_CODE" -eq 0 && "$rc" -ne 0 ]]; then
        EXIT_CODE="$rc"
    fi
}

_sha256_hex() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    else
        sha256sum | awk '{print $1}'
    fi
}

# sha256 input: chain params, image digests, key split, profile flags — not rvc_version.
_fingerprint_payload() {
    jq -S -c -n \
        --arg chain_id "${CHAIN_ID:-}" \
        --arg network_id "${NETWORK_ID:-}" \
        --arg num_validators "${NUM_VALIDATORS:-}" \
        --arg rvc_keys "${RVC_KEYS:-}" \
        --arg genesis_delay "${GENESIS_DELAY:-}" \
        --arg deposit "${DEPOSIT_CONTRACT_ADDRESS:-}" \
        --arg genesis_fork "${GENESIS_FORK_VERSION:-}" \
        --arg altair_fork "${ALTAIR_FORK_VERSION:-}" \
        --arg bellatrix_fork "${BELLATRIX_FORK_VERSION:-}" \
        --arg capella_fork "${CAPELLA_FORK_VERSION:-}" \
        --arg deneb_fork "${DENEB_FORK_VERSION:-}" \
        --arg electra_fork "${ELECTRA_FORK_VERSION:-}" \
        --arg electra_epoch "${ELECTRA_FORK_EPOCH:-}" \
        --arg fulu_fork "${FULU_FORK_VERSION:-}" \
        --arg fulu_epoch "${FULU_FORK_EPOCH:-}" \
        --arg bpo1 "${BPO_1_EPOCH:-}" \
        --arg bpo2 "${BPO_2_EPOCH:-}" \
        --arg img_geth "${IMG_GETH:-}" \
        --arg img_lighthouse "${IMG_LIGHTHOUSE:-}" \
        --arg img_genesis "${IMG_GENESIS:-}" \
        --arg profile "${PROFILE:-}" \
        --arg epochs "${EPOCHS:-}" \
        --arg doppelganger "${DOPPELGANGER:-}" \
        --arg fail_under "${FAIL_UNDER:-}" \
        --arg soak_start_offset_epochs "${SOAK_START_OFFSET_EPOCHS:-0}" \
        '{
            chain: {
                ALTAIR_FORK_VERSION: $altair_fork,
                BELLATRIX_FORK_VERSION: $bellatrix_fork,
                BPO_1_EPOCH: $bpo1,
                BPO_2_EPOCH: $bpo2,
                CAPELLA_FORK_VERSION: $capella_fork,
                CHAIN_ID: $chain_id,
                DEPOSIT_CONTRACT_ADDRESS: $deposit,
                DENEB_FORK_VERSION: $deneb_fork,
                ELECTRA_FORK_EPOCH: $electra_epoch,
                ELECTRA_FORK_VERSION: $electra_fork,
                FULU_FORK_EPOCH: $fulu_epoch,
                FULU_FORK_VERSION: $fulu_fork,
                GENESIS_DELAY: $genesis_delay,
                GENESIS_FORK_VERSION: $genesis_fork,
                NETWORK_ID: $network_id,
                NUM_VALIDATORS: $num_validators
            },
            images: {
                genesis: $img_genesis,
                geth: $img_geth,
                lighthouse: $img_lighthouse
            },
            key_split: {
                NUM_VALIDATORS: $num_validators,
                RVC_KEYS: $rvc_keys
            },
            profile: {
                doppelganger: $doppelganger,
                epochs: $epochs,
                fail_under: $fail_under,
                name: $profile,
                soak_start_offset_epochs: $soak_start_offset_epochs
            }
        }'
}

_compute_fingerprint() {
    local payload
    payload="$(_fingerprint_payload)" || return 1
    printf '%s' "$payload" | _sha256_hex
}

_pubkeys_json() {
    local rvc="${RUN_DIR:-}/rvc.json"
    local f="${KEYS_DIR}/rvc/pubkeys.txt"
    local p=""
    if [[ -n "${RUN_DIR:-}" && -f "$rvc" && ! -L "$rvc" ]]; then
        p="$(jq -c '.pubkeys // empty' "$rvc" 2>/dev/null || true)"
        if [[ -n "$p" && "$p" != "null" && "$p" != "[]" ]]; then
            printf '%s' "$p"
            return 0
        fi
    fi
    if [[ -f "$f" && ! -L "$f" ]]; then
        jq -R -s -c 'split("\n") | map(select(length > 0))' "$f"
    else
        printf '%s' '[]'
    fi
}

_gvr_value() {
    local f="${GENESIS_DIR}/genesis_validators_root.txt"
    if [[ -f "$f" && ! -L "$f" ]]; then
        tr -d '[:space:]' <"$f"
    fi
}

_key_range_json() {
    local rvc="${RUN_DIR:-}/rvc.json"
    local n="${NUM_VALIDATORS:-0}"
    local k="${RVC_KEYS:-0}"
    local start kr=""
    if [[ -n "${RUN_DIR:-}" && -f "$rvc" && ! -L "$rvc" ]]; then
        kr="$(jq -c '.key_range // empty' "$rvc" 2>/dev/null || true)"
        if [[ -n "$kr" && "$kr" != "null" ]]; then
            printf '%s' "$kr"
            return 0
        fi
    fi
    case "$n" in
        '' | *[!0-9]*)
            n=0
            ;;
    esac
    case "$k" in
        '' | *[!0-9]*)
            k=0
            ;;
    esac
    start=$((n - k))
    if [[ "$start" -lt 0 ]]; then
        start=0
    fi
    jq -nc --argjson start "$start" --argjson end "$n" '[$start, $end]'
}

record_stage() {
    local name="$1"
    local seconds="$2"
    local rc="$3"
    case "$seconds" in
        '' | *[!0-9]*)
            seconds=0
            ;;
    esac
    case "$rc" in
        '' | *[!0-9]*)
            rc=1
            ;;
    esac
    _STAGES_JSON="$(
        jq -c --arg n "$name" --argjson s "$seconds" --argjson e "$rc" \
            '.[$n] = {exit_code: $e, seconds: $s}' <<<"$_STAGES_JSON"
    )"
}

dump_stage_logs() {
    if [[ -z "${RUN_DIR:-}" ]]; then
        return 0
    fi
    capture_container_logs "$GETH_CONTAINER" || true
    capture_container_logs "$BEACON_CONTAINER" || true
    capture_container_logs "$VALIDATOR_CONTAINER" || true
}

want_stage() {
    local name="$1"
    if [[ -z "$STAGES_SET" ]]; then
        case "$name" in
            down)
                return 1
                ;;
            *)
                return 0
                ;;
        esac
    fi
    case ",${STAGES_SET}," in
        *",${name},"*)
            return 0
            ;;
    esac
    return 1
}

_stage_script() {
    local name="$1"
    case "$name" in
        up) printf '%s' "up.sh" ;;
        attach) printf '%s' "attach-rvc.sh" ;;
        soak) printf '%s' "soak.sh" ;;
        report) printf '%s' "report.sh" ;;
        down) printf '%s' "down.sh" ;;
        *)
            die_usage "unknown stage: ${name} (expected up|attach|soak|report|down)"
            ;;
    esac
}

run_verb() {
    local name="$1"
    local script path start rc=0 item rest
    local -a args=()

    script="$(_stage_script "$name")"
    path="${DEVNET_STAGE_DIR}/${script}"
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink stage: ${path}"
    fi
    if [[ ! -f "$path" ]]; then
        die_usage "stage not found: ${path}"
    fi
    if [[ ! -x "$path" ]]; then
        die_usage "stage not executable: ${path}"
    fi

    args+=(--run-dir "$RUN_DIR")
    if [[ -n "${PROFILE:-}" ]]; then
        args+=(--profile "$PROFILE")
    fi
    if [[ "$FORCE" == "1" ]]; then
        args+=(--force)
    fi
    if [[ "$INTERACTIVE" == "1" ]]; then
        args+=(--interactive)
    fi
    case "$name" in
        attach)
            if [[ "$DOCKER_ATTACH" == "1" ]]; then
                args+=(--docker)
            fi
            ;;
        soak)
            args+=(--epochs "$EPOCHS")
            ;;
        report)
            if [[ "$STRICT" == "1" ]]; then
                args+=(--strict)
            fi
            if [[ -n "${FAIL_UNDER:-}" ]]; then
                rest="${FAIL_UNDER}"
                while [[ -n "$rest" ]]; do
                    item="${rest%%,*}"
                    rest="${rest#"$item"}"
                    rest="${rest#,}"
                    if [[ -n "$item" ]]; then
                        args+=(--fail-under "$item")
                    fi
                done
            fi
            ;;
        down)
            args+=(--data)
            ;;
    esac

    log_info "running ${script}"
    start="$SECONDS"
    set +e
    "$path" "${args[@]}" </dev/null
    rc=$?
    set -e
    record_exit "$rc"
    record_stage "$name" "$((SECONDS - start))" "$rc" || true
    if [[ "$name" == "down" ]]; then
        _DID_DOWN=1
    fi
    if [[ "$rc" -ne 0 ]]; then
        dump_stage_logs || true
        if [[ "$name" != "soak" ]]; then
            _STOP=1
        fi
    fi
    return 0
}

write_run_json_start() {
    local dest="${RUN_DIR}/run.json"
    local generated_at git_sha rvc_version fingerprint gvr
    local pubkeys key_range
    local -a _pipe
    local jq_rc=0 write_rc=0

    if [[ -L "$dest" ]]; then
        die_usage "refusing symlink run.json: ${dest}"
    fi
    generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    git_sha="$(_git_short_sha)"
    rvc_version="$(_rvc_version)"
    fingerprint="$(_compute_fingerprint)" || die_infra "failed to compute run fingerprint"
    gvr="$(_gvr_value)"
    pubkeys="$(_pubkeys_json)"
    key_range="$(_key_range_json)"

    set +e
    jq -S -n \
        --arg generated_at "$generated_at" \
        --arg run_id "$RUN_ID" \
        --arg git_sha "$git_sha" \
        --arg rvc_version "$rvc_version" \
        --arg profile "$PROFILE" \
        --argjson epochs "$EPOCHS" \
        --argjson key_range "$key_range" \
        --argjson pubkeys "$pubkeys" \
        --arg gvr "$gvr" \
        --arg img_geth "${IMG_GETH:-}" \
        --arg img_lighthouse "${IMG_LIGHTHOUSE:-}" \
        --arg img_genesis "${IMG_GENESIS:-}" \
        --arg fingerprint "$fingerprint" \
        --arg fail_under "${FAIL_UNDER:-}" \
        --argjson soak_start_offset_epochs "${SOAK_START_OFFSET_EPOCHS:-0}" \
        '{
            epochs: $epochs,
            fail_under: $fail_under,
            fingerprint: $fingerprint,
            generated_at: $generated_at,
            genesis_validators_root: $gvr,
            git_sha: $git_sha,
            images: {
                genesis: $img_genesis,
                geth: $img_geth,
                lighthouse: $img_lighthouse
            },
            key_range: $key_range,
            profile: $profile,
            pubkeys: $pubkeys,
            run_id: $run_id,
            rvc_version: $rvc_version,
            schema_version: 1,
            soak_start_offset_epochs: $soak_start_offset_epochs
        }' | _atomic_replace_stdin "$dest"
    _pipe=("${PIPESTATUS[@]}" 1)
    set -e
    jq_rc="${_pipe[0]}"
    write_rc="${_pipe[1]}"
    if [[ "$write_rc" -eq 2 ]]; then
        die_usage "refusing symlink run.json: ${dest}"
    fi
    if [[ "$jq_rc" -ne 0 || "$write_rc" -ne 0 ]]; then
        die_infra "failed to write ${dest}"
    fi
    chmod 600 "$dest" || die_infra "failed to chmod ${dest}"
}

_window_json() {
    local samples="${RUN_DIR}/samples.jsonl"
    local client="${RUN_DIR}/client.json"
    local window=""
    if [[ -f "$client" && ! -L "$client" ]]; then
        window="$(jq -c '
            .window
            | if type == "object"
                and (.start_slot | type == "number")
                and (.end_slot | type == "number")
              then
                {
                    end_slot: .end_slot,
                    epochs: (.epochs // 0),
                    slots: (.slots // (.end_slot - .start_slot)),
                    start_slot: .start_slot
                }
              else empty end
        ' "$client" 2>/dev/null || true)"
    fi
    if [[ -z "$window" && -f "$samples" && ! -L "$samples" ]]; then
        window="$(
            jq -s -c --argjson epochs "${EPOCHS:-0}" '
                [.[].slot | select(type == "number")]
                | if length < 2 then empty
                  else {
                      end_slot: .[-1],
                      epochs: $epochs,
                      slots: (.[-1] - .[0]),
                      start_slot: .[0]
                  }
                  end
            ' "$samples" 2>/dev/null || true
        )"
    fi
    printf '%s' "$window"
}

_verdict_value() {
    local vf="${RUN_DIR}/verdict.json"
    local v=""
    if [[ -f "$vf" && ! -L "$vf" ]]; then
        v="$(jq -r '.verdict // empty' "$vf" 2>/dev/null || true)"
    fi
    if [[ -n "$v" && "$v" != "null" ]]; then
        printf '%s' "$v"
        return 0
    fi
    if [[ "$EXIT_CODE" -eq 0 ]]; then
        printf 'pass'
    else
        printf 'fail'
    fi
}

# Merge pubkeys/GVR/key_range from data/ or rvc.json. Never write empty pubkeys/GVR.
_snapshot_run_identity() {
    local dest="${RUN_DIR:-}/run.json"
    local pubkeys gvr key_range
    local -a _pipe
    local jq_rc=0 write_rc=0

    if [[ -z "${RUN_DIR:-}" || ! -d "${RUN_DIR:-}" ]]; then
        return 0
    fi
    if [[ -L "$dest" || ! -f "$dest" ]]; then
        return 0
    fi

    pubkeys="$(_pubkeys_json)"
    gvr="$(_gvr_value)"
    key_range="$(_key_range_json)"

    set +e
    jq -S \
        --argjson pubkeys "$pubkeys" \
        --arg gvr "$gvr" \
        --argjson key_range "$key_range" \
        '.
         + (if ($pubkeys | type == "array") and ($pubkeys | length) > 0
            then {pubkeys: $pubkeys} else {} end)
         + (if $gvr != "" then {genesis_validators_root: $gvr} else {} end)
         + {key_range: $key_range}' \
        "$dest" | _atomic_replace_stdin "$dest"
    _pipe=("${PIPESTATUS[@]}" 1)
    set -e
    jq_rc="${_pipe[0]}"
    write_rc="${_pipe[1]}"
    if [[ "$write_rc" -eq 2 ]]; then
        log_warn "refusing symlink run.json: ${dest}"
        return 0
    fi
    if [[ "$jq_rc" -ne 0 || "$write_rc" -ne 0 ]]; then
        log_warn "failed to snapshot run identity into ${dest}"
        return 0
    fi
    chmod 600 "$dest" || true
}

write_run_json_end() {
    local dest="${RUN_DIR}/run.json"
    local window verdict
    local -a _pipe
    local jq_rc=0 write_rc=0
    local extra='{}'

    if [[ -z "${RUN_DIR:-}" || ! -d "${RUN_DIR:-}" ]]; then
        return 0
    fi
    if [[ -L "$dest" ]]; then
        log_warn "refusing symlink run.json: ${dest}"
        return 0
    fi
    if [[ ! -f "$dest" ]]; then
        return 0
    fi

    window="$(_window_json)"
    verdict="$(_verdict_value)"
    if [[ -n "$window" ]]; then
        extra="$(jq -nc --argjson window "$window" '{window: $window}')"
    fi

    set +e
    jq -S \
        --argjson stages "$_STAGES_JSON" \
        --arg verdict "$verdict" \
        --argjson extra "$extra" \
        '. + {stages: $stages, verdict: $verdict} + $extra' \
        "$dest" | _atomic_replace_stdin "$dest"
    _pipe=("${PIPESTATUS[@]}" 1)
    set -e
    jq_rc="${_pipe[0]}"
    write_rc="${_pipe[1]}"
    if [[ "$write_rc" -eq 2 ]]; then
        log_warn "refusing symlink run.json: ${dest}"
        return 0
    fi
    if [[ "$jq_rc" -ne 0 || "$write_rc" -ne 0 ]]; then
        log_warn "failed to rewrite ${dest}"
        return 0
    fi
    chmod 600 "$dest" || true
}

_run_down() {
    local start rc=0 path
    if [[ "${_DID_DOWN}" -eq 1 ]]; then
        return 0
    fi
    _DID_DOWN=1
    path="${DEVNET_STAGE_DIR}/down.sh"
    if [[ -L "$path" || ! -f "$path" || ! -x "$path" ]]; then
        log_warn "down.sh missing or not executable at ${path}"
        record_exit 1
        return 0
    fi
    log_info "running down.sh"
    start="$SECONDS"
    set +e
    "$path" --run-dir "$RUN_DIR" --data </dev/null
    rc=$?
    set -e
    record_exit "$rc"
    record_stage "down" "$((SECONDS - start))" "$rc" || true
    return 0
}

_on_exit() {
    local rc="$?"
    if [[ "${_CLEANED}" -eq 1 ]]; then
        return 0
    fi
    _CLEANED=1
    trap - EXIT
    record_exit "$rc"
    if [[ "$KEEP" != "1" && "${_DID_DOWN}" != "1" && -n "${RUN_DIR:-}" ]]; then
        _run_down || true
    fi
    write_run_json_end || true
    exit "$EXIT_CODE"
}

parse_run_flags() {
    local -a rest
    rest=()
    KEEP=0
    DOCKER_ATTACH=0
    STRICT=0
    STAGES_SET=""
    RUN_ID=""
    _RUN_ID_FLAG=0
    _EPOCHS_FLAG=""
    _CLI_FAIL_UNDER=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --keep)
                KEEP=1
                shift
                ;;
            --docker | --docker=*)
                DOCKER_ATTACH=1
                shift
                ;;
            --strict)
                STRICT=1
                shift
                ;;
            --stages)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--stages requires a comma-separated list"
                fi
                STAGES_SET="$2"
                shift 2
                ;;
            --stages=*)
                STAGES_SET="${1#--stages=}"
                if [[ -z "$STAGES_SET" ]]; then
                    die_usage "--stages requires a comma-separated list"
                fi
                shift
                ;;
            --run-id)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--run-id requires an id"
                fi
                RUN_ID="$2"
                _RUN_ID_FLAG=1
                shift 2
                ;;
            --run-id=*)
                RUN_ID="${1#--run-id=}"
                if [[ -z "$RUN_ID" ]]; then
                    die_usage "--run-id requires an id"
                fi
                _RUN_ID_FLAG=1
                shift
                ;;
            --epochs)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--epochs requires a positive integer"
                fi
                _EPOCHS_FLAG="$2"
                shift 2
                ;;
            --epochs=*)
                _EPOCHS_FLAG="${1#--epochs=}"
                if [[ -z "$_EPOCHS_FLAG" ]]; then
                    die_usage "--epochs requires a positive integer"
                fi
                shift
                ;;
            --fail-under)
                if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
                    die_usage "--fail-under requires METRIC=VALUE"
                fi
                _CLI_FAIL_UNDER+=("$2")
                shift 2
                ;;
            --fail-under=*)
                if [[ -z "${1#--fail-under=}" ]]; then
                    die_usage "--fail-under requires METRIC=VALUE"
                fi
                _CLI_FAIL_UNDER+=("${1#--fail-under=}")
                shift
                ;;
            *)
                rest+=("$1")
                shift
                ;;
        esac
    done
    export KEEP DOCKER_ATTACH STRICT
    if [[ ${#rest[@]} -eq 0 ]]; then
        parse_common_flags
    else
        parse_common_flags "${rest[@]}"
    fi
}

_normalize_stages() {
    local raw="${STAGES_SET}"
    raw="${raw// /,}"
    while [[ "$raw" == *,,* ]]; do
        raw="${raw//,,/,}"
    done
    raw="${raw#,}"
    raw="${raw%,}"
    STAGES_SET="$raw"
    if [[ -z "$STAGES_SET" ]]; then
        return 0
    fi
    local rest item
    rest="$STAGES_SET"
    while [[ -n "$rest" ]]; do
        item="${rest%%,*}"
        rest="${rest#"$item"}"
        rest="${rest#,}"
        case "$item" in
            up | attach | soak | report | down) ;;
            "")
                continue
                ;;
            *)
                die_usage "unknown stage: ${item} (expected up|attach|soak|report|down)"
                ;;
        esac
    done
}

_require_epochs_flag() {
    if [[ -z "$_EPOCHS_FLAG" ]]; then
        return 0
    fi
    case "$_EPOCHS_FLAG" in
        '' | *[!0-9]* | 0)
            die_usage "--epochs requires a positive integer (got ${_EPOCHS_FLAG})"
            ;;
    esac
    EPOCHS="$_EPOCHS_FLAG"
    export EPOCHS
}

print_run_plan() {
    log_info "run plan:"
    log_info "  profile: ${PROFILE}"
    log_info "  epochs: ${EPOCHS}"
    log_info "  soak start offset epochs: ${SOAK_START_OFFSET_EPOCHS:-0}"
    log_info "  1. up.sh"
    log_info "  2. attach-rvc.sh"
    log_info "  3. soak.sh"
    log_info "  4. report.sh"
    log_info "  5. down.sh"
    if [[ "$KEEP" == "1" ]]; then
        log_info "  keep: on (skip teardown)"
    fi
}

main() {
    local joined="" item

    parse_run_flags "$@"
    require_chain_1337
    require_cmd jq
    require_cmd python3

    if [[ -z "${PROFILE:-}" ]]; then
        die_usage "--profile is required (fast|safe)"
    fi
    resolve_profile "$PROFILE"
    _require_epochs_flag
    if [[ ${#_CLI_FAIL_UNDER[@]} -gt 0 ]]; then
        joined=""
        for item in "${_CLI_FAIL_UNDER[@]}"; do
            if [[ -z "$joined" ]]; then
                joined="$item"
            else
                joined="${joined},${item}"
            fi
        done
        FAIL_UNDER="$joined"
        export FAIL_UNDER
    fi

    _normalize_stages
    if [[ -n "$STAGES_SET" && "$_RUN_ID_FLAG" -ne 1 ]]; then
        die_usage "--stages requires --run-id"
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        print_run_plan
        log_success "dry-run complete"
        return 0
    fi

    _resolve_rvc_bin

    if [[ "$_RUN_ID_FLAG" -eq 1 ]]; then
        _require_run_id_ident "$RUN_ID"
    else
        RUN_ID="$(mint_run_id)"
    fi
    export RUN_ID
    RUN_DIR="${RUNS_DIR:?}/${RUN_ID}"
    export RUN_DIR
    mkdir -p -- "$RUN_DIR" || die_usage "cannot create run dir: ${RUN_DIR}"
    resolve_run_dir >/dev/null
    _assert_run_dir_under_runs

    if [[ -n "$STAGES_SET" && -f "${RUN_DIR}/run.json" && ! -L "${RUN_DIR}/run.json" ]]; then
        _REUSE_RUN_JSON=1
    fi

    mkdir -p -- "${RUN_DIR}/logs"
    if [[ "$_REUSE_RUN_JSON" -ne 1 ]]; then
        write_run_json_start
    fi

    trap _on_exit EXIT

    if want_stage up; then
        run_verb up
        if [[ "$_STOP" -eq 0 ]]; then
            _snapshot_run_identity
        fi
    fi
    if [[ "$_STOP" -eq 0 ]] && want_stage attach; then
        run_verb attach
        if [[ "$_STOP" -eq 0 ]]; then
            _snapshot_run_identity
        fi
    fi
    if [[ "$_STOP" -eq 0 ]] && want_stage soak; then
        run_verb soak
    fi
    if [[ "$_STOP" -eq 0 ]] && want_stage report; then
        _snapshot_run_identity
        run_verb report
    fi
    if want_stage down; then
        run_verb down
    fi

    if [[ "$EXIT_CODE" -eq 0 ]]; then
        log_success "run ${RUN_ID} ok"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
