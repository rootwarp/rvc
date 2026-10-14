#!/usr/bin/env bash
# Sequence 00-preflight → 01-genesis → 02-keys → 03-chain. Idempotent; no prompts.

set -euo pipefail

_UP_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"

# Process env wins over sourced devnet.env (CHAIN_ID=1, unpinned IMG_*, …).
# Snapshot every key the file assigns that is already set, then re-export
# after source so child stages see the override (00-preflight pin/chain-id).
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "required command not found: python3" >&2
    exit 2
fi
_OV_RESTORE="$(
    DEVNET_ENV="${_UP_DIR}/devnet.env" python3 - <<'PY'
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
source "${_UP_DIR}/lib/common.sh"

if [[ -n "$_OV_RESTORE" ]]; then
    eval "$_OV_RESTORE"
fi
unset _OV_RESTORE

print_up_plan() {
    log_info "stage plan:"
    log_info "  1. 00-preflight.sh"
    log_info "  2. 01-genesis.sh"
    log_info "  3. 02-keys.sh"
    log_info "  4. 03-chain.sh"
}

run_stage() {
    local name="$1"
    local path="${DEVNET_STAGE_DIR}/${name}"
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink stage: ${path}"
    fi
    if [[ ! -f "$path" ]]; then
        die_usage "stage not found: ${path}"
    fi
    if [[ ! -x "$path" ]]; then
        die_usage "stage not executable: ${path}"
    fi
    log_info "running ${name}"
    set --
    if [[ "$FORCE" == "1" ]]; then
        set -- "$@" --force
    fi
    if [[ "$INTERACTIVE" == "1" ]]; then
        set -- "$@" --interactive
    fi
    if [[ -n "${RUN_DIR:-}" ]]; then
        set -- "$@" --run-dir "$RUN_DIR"
    fi
    if [[ -n "${PROFILE:-}" ]]; then
        set -- "$@" --profile "$PROFILE"
    fi
    # Propagate the child's code unchanged (PRD §4). Do not remap via die_*.
    "$path" "$@" || exit $?
}

main() {
    parse_common_flags "$@"

    if [[ "$DRY_RUN" == "1" ]]; then
        print_up_plan
        log_success "dry-run complete"
        return 0
    fi

    run_stage "00-preflight.sh"
    run_stage "01-genesis.sh"
    run_stage "02-keys.sh"
    run_stage "03-chain.sh"
    log_success "devnet up"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
