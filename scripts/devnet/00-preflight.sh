#!/usr/bin/env bash
# Host, tooling, pin and chain-id gate. Owns the image pull later stages consume.

set -euo pipefail

# Process env wins over devnet.env (CHAIN_ID=1 / unpinned IMG_*). Capture
# before common.sh sources the file, which would otherwise overwrite.
_OV_CHAIN_ID=0
_OV_IMG_GETH=0
_OV_IMG_LIGHTHOUSE=0
_OV_IMG_GENESIS=0
_KEEP_CHAIN_ID=""
_KEEP_IMG_GETH=""
_KEEP_IMG_LIGHTHOUSE=""
_KEEP_IMG_GENESIS=""
if [[ "${CHAIN_ID+x}" == "x" ]]; then
    _OV_CHAIN_ID=1
    _KEEP_CHAIN_ID="$CHAIN_ID"
fi
if [[ "${IMG_GETH+x}" == "x" ]]; then
    _OV_IMG_GETH=1
    _KEEP_IMG_GETH="$IMG_GETH"
fi
if [[ "${IMG_LIGHTHOUSE+x}" == "x" ]]; then
    _OV_IMG_LIGHTHOUSE=1
    _KEEP_IMG_LIGHTHOUSE="$IMG_LIGHTHOUSE"
fi
if [[ "${IMG_GENESIS+x}" == "x" ]]; then
    _OV_IMG_GENESIS=1
    _KEEP_IMG_GENESIS="$IMG_GENESIS"
fi

_PREFLIGHT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
# shellcheck disable=SC1091
source "${_PREFLIGHT_DIR}/lib/common.sh"

if [[ "$_OV_CHAIN_ID" -eq 1 ]]; then
    CHAIN_ID="$_KEEP_CHAIN_ID"
    export CHAIN_ID
fi
if [[ "$_OV_IMG_GETH" -eq 1 ]]; then
    IMG_GETH="$_KEEP_IMG_GETH"
    export IMG_GETH
fi
if [[ "$_OV_IMG_LIGHTHOUSE" -eq 1 ]]; then
    IMG_LIGHTHOUSE="$_KEEP_IMG_LIGHTHOUSE"
    export IMG_LIGHTHOUSE
fi
if [[ "$_OV_IMG_GENESIS" -eq 1 ]]; then
    IMG_GENESIS="$_KEEP_IMG_GENESIS"
    export IMG_GENESIS
fi
unset _OV_CHAIN_ID _OV_IMG_GETH _OV_IMG_LIGHTHOUSE _OV_IMG_GENESIS
unset _KEEP_CHAIN_ID _KEEP_IMG_GETH _KEEP_IMG_LIGHTHOUSE _KEEP_IMG_GENESIS

# Same shape as test_devnet_env.IMG_PIN_RE / 1.1a.
_IMG_PIN_RE='^[a-z0-9./-]+:[^@]+@sha256:[0-9a-f]{64}$'

_require_uint() {
    local name="$1"
    local val="$2"
    case "$val" in
        '' | *[!0-9]*)
            die_usage "${name} must be a non-negative integer (got ${val:-empty})"
            ;;
    esac
}

check_tools() {
    local tool
    for tool in "$DOCKER" "$CURL" jq openssl python3; do
        require_cmd "$tool"
    done
}

check_daemon() {
    # Swallow daemon stderr: the remedy is one line, not the raw client dump.
    if ! "$DOCKER" info >/dev/null 2>&1; then
        die_usage "Docker daemon is not running. Start Docker and retry."
    fi
}

_cpu_count() {
    python3 -c 'import os; print(os.cpu_count() or 0)'
}

_ram_gib() {
    python3 -c 'import os; print((os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")) // (1024 ** 3))'
}

_free_gib() {
    PREFLIGHT_STATVFS_PATH="$1" python3 -c \
        'import os; s = os.statvfs(os.environ["PREFLIGHT_STATVFS_PATH"]); print((s.f_bavail * s.f_frsize) // (1024 ** 3))'
}

# Host first (F9 RAM is the Mac, not Docker Desktop). Dual-check daemon
# NCPU/MemTotal when those fields parse so a starved VM cannot pass.
check_resources() {
    local min_cpus min_ram_gib min_free_gib
    local ncpu mem_gib path avail_gib
    local raw parsed vm_cpus vm_ram_gib
    min_cpus="${PREFLIGHT_MIN_CPUS:-4}"
    min_ram_gib="${PREFLIGHT_MIN_RAM_GIB:-8}"
    min_free_gib="${PREFLIGHT_MIN_FREE_GIB:-20}"
    _require_uint "PREFLIGHT_MIN_CPUS" "$min_cpus"
    _require_uint "PREFLIGHT_MIN_RAM_GIB" "$min_ram_gib"
    _require_uint "PREFLIGHT_MIN_FREE_GIB" "$min_free_gib"

    ncpu="$(_cpu_count)" || die_usage "cannot determine CPU count"
    _require_uint "host CPUs" "$ncpu"
    if [[ "$ncpu" -lt "$min_cpus" ]]; then
        die_usage "need >= ${min_cpus} CPUs (host has ${ncpu})"
    fi

    mem_gib="$(_ram_gib)" || die_usage "cannot determine RAM"
    _require_uint "host RAM GiB" "$mem_gib"
    if [[ "$mem_gib" -lt "$min_ram_gib" ]]; then
        die_usage "need >= ${min_ram_gib} GiB RAM (host has ${mem_gib} GiB)"
    fi

    path="$DATA_DIR"
    if [[ ! -e "$path" ]]; then
        path="$(dirname "$path")"
    fi
    avail_gib="$(_free_gib "$path")" || die_usage "cannot determine free disk for ${DATA_DIR}"
    _require_uint "free disk GiB" "$avail_gib"
    if [[ "$avail_gib" -lt "$min_free_gib" ]]; then
        die_usage "need >= ${min_free_gib} GiB free under ${DATA_DIR} (have ${avail_gib} GiB)"
    fi

    raw="$("$DOCKER" info --format '{{.NCPU}} {{.MemTotal}}' 2>/dev/null)" || raw=""
    parsed="$(PREFLIGHT_DOCKER_INFO="$raw" python3 -c '
import os
raw = os.environ.get("PREFLIGHT_DOCKER_INFO", "").split()
if len(raw) != 2 or not raw[0].isdigit() or not raw[1].isdigit():
    raise SystemExit(0)
print("%s %s" % (raw[0], int(raw[1]) // (1024 ** 3)))
')" || parsed=""
    if [[ -n "$parsed" ]]; then
        vm_cpus="${parsed%% *}"
        vm_ram_gib="${parsed##* }"
        _require_uint "docker NCPU" "$vm_cpus"
        _require_uint "docker MemTotal GiB" "$vm_ram_gib"
        if [[ "$vm_cpus" -lt "$min_cpus" ]]; then
            die_usage "need >= ${min_cpus} CPUs (docker VM has ${vm_cpus})"
        fi
        if [[ "$vm_ram_gib" -lt "$min_ram_gib" ]]; then
            die_usage "need >= ${min_ram_gib} GiB RAM (docker VM has ${vm_ram_gib} GiB)"
        fi
        log_info "resources: host ${ncpu} CPU / ${mem_gib} GiB RAM, docker VM ${vm_cpus} CPU / ${vm_ram_gib} GiB RAM, ${avail_gib} GiB free under ${DATA_DIR}"
    else
        log_info "resources: ${ncpu} CPU, ${mem_gib} GiB RAM, ${avail_gib} GiB free under ${DATA_DIR}"
    fi
}

_write_probe() {
    PREFLIGHT_WRITE_PROBE="$1" python3 -c '
import os, sys
probe = os.environ["PREFLIGHT_WRITE_PROBE"]
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
fd = -1
try:
    fd = os.open(probe, flags, 0o600)
except OSError:
    sys.exit(1)
try:
    os.close(fd)
    fd = -1
    os.unlink(probe)
except OSError:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(probe)
    except OSError:
        pass
    sys.exit(1)
'
}

check_write_access() {
    local uid probe path
    uid="$(id -u)"
    if [[ -L "$DATA_DIR" ]]; then
        die_usage "refusing symlink purge root: ${DATA_DIR}"
    fi
    if [[ -e "$DATA_DIR" ]]; then
        if [[ ! -d "$DATA_DIR" ]]; then
            die_usage "purge root is not a directory: ${DATA_DIR}"
        fi
        probe="${DATA_DIR}/.preflight-write-$$"
        if [[ -L "$probe" ]]; then
            die_usage "refusing symlink write probe: ${probe}"
        fi
        if ! _write_probe "$probe"; then
            die_usage "purge root not writable by uid ${uid}: ${DATA_DIR}"
        fi
        return 0
    fi
    path="$(dirname "$DATA_DIR")"
    if [[ -L "$path" ]]; then
        die_usage "refusing symlink purge root parent: ${path}"
    fi
    if [[ ! -w "$path" ]]; then
        die_usage "purge root not writable by uid ${uid}: ${DATA_DIR}"
    fi
}

check_pins() {
    local var img
    for var in IMG_GETH IMG_LIGHTHOUSE IMG_GENESIS; do
        img="${!var}"
        # shellcheck disable=SC2254
        if [[ ! "$img" =~ $_IMG_PIN_RE ]]; then
            die_usage "${var} is not pinned by @sha256: (${img:-unset})"
        fi
    done
}

print_check_plan() {
    log_info "check plan:"
    log_info "  1. require_chain_1337"
    log_info "  2. check_tools"
    log_info "  3. check_daemon"
    log_info "  4. check_resources"
    log_info "  5. check_write_access"
    log_info "  6. check_pins"
    log_info "  7. pull_images"
}

pull_images() {
    local var img present
    for var in IMG_GETH IMG_LIGHTHOUSE IMG_GENESIS; do
        img="${!var}"
        present=0
        if [[ "$FORCE" != "1" ]] && "$DOCKER" image inspect -- "$img" >/dev/null 2>&1; then
            present=1
        fi
        if [[ "$DRY_RUN" == "1" ]]; then
            if [[ "$present" -eq 1 ]]; then
                log_info "would skip pull (present): ${var}"
            else
                log_info "would pull ${var}=${img}"
            fi
            continue
        fi
        if [[ "$present" -eq 1 ]]; then
            log_info "image already present: ${var}"
            continue
        fi
        log_info "pulling ${var}=${img}"
        if ! "$DOCKER" pull -- "$img"; then
            die_infra "failed to pull ${var}=${img}"
        fi
    done
}

main() {
    parse_common_flags "$@"
    require_chain_1337

    if [[ "$DRY_RUN" == "1" ]]; then
        print_check_plan
        check_tools
        check_pins
        pull_images
        log_success "dry-run complete"
        return 0
    fi

    check_tools
    check_daemon
    check_resources
    check_write_access
    check_pins
    pull_images
    log_success "preflight ok"
}

main "$@"
