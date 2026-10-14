#!/usr/bin/env bash
# Restore-and-diff verification for the untracked-orphans archive (ARCH-1a / C10).
# Compares a restored branch tip or tarball against MANIFEST.md per-file SHA-256.
# When verifying a tarball, also pins the tarball blob SHA-256 from the MANIFEST header.
#
# Usage:
#   verify-archive.sh                      # verify default branch + default tarball
#   verify-archive.sh --tarball PATH
#   verify-archive.sh --branch REF
#   verify-archive.sh --dir PATH           # restore root containing only archived content
#   verify-archive.sh --manifest PATH
#
# Exit 0 with "files=<N> differences=0" when clean; non-zero otherwise.
# Any file under the restored root that is not in the MANIFEST is EXTRA (fail).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DEFAULT_MANIFEST="${SCRIPT_DIR}/MANIFEST.md"
DEFAULT_TARBALL="${SCRIPT_DIR}/untracked-orphans-2026-08-12.tar.gz"
DEFAULT_BRANCH="archive/untracked-orphans-2026-08-12"

MANIFEST="${DEFAULT_MANIFEST}"
MODE=""
TARGET=""
RUN_DEFAULT=1

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?}"
      shift 2
      ;;
    --tarball)
      MODE="tarball"
      TARGET="${2:?}"
      RUN_DEFAULT=0
      shift 2
      ;;
    --branch)
      MODE="branch"
      TARGET="${2:?}"
      RUN_DEFAULT=0
      shift 2
      ;;
    --dir)
      MODE="dir"
      TARGET="${2:?}"
      RUN_DEFAULT=0
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ ! -f "${MANIFEST}" ]]; then
  echo "error: manifest not found: ${MANIFEST}" >&2
  exit 1
fi

# Parse expected path -> sha from MANIFEST table rows: | `sha` | `path` |
parse_manifest() {
  local manifest="$1"
  # shellcheck disable=SC2016
  awk '
    /^\| `[0-9a-f]{64}` \| `/ {
      sha = $2
      gsub(/`/, "", sha)
      line = $0
      sub(/^\| `[^`]+` \| `/, "", line)
      sub(/` \|[[:space:]]*$/, "", line)
      if (sha ~ /^[0-9a-f]{64}$/ && line != "") {
        print sha "\t" line
      }
    }
  ' "${manifest}"
}

# MANIFEST header: | Tarball SHA-256 | `hex` |
parse_tarball_sha() {
  local manifest="$1"
  # Portable awk (no gawk match groups): strip to first backticked 64-hex field.
  awk '
    /^\| Tarball SHA-256 \|/ {
      line = $0
      sub(/^[^`]*`/, "", line)
      sub(/`.*/, "", line)
      if (line ~ /^[0-9a-fA-F]{64}$/) {
        print tolower(line)
        exit
      }
    }
  ' "${manifest}"
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

# Compare restored root against expected map.
# Any file under restored_root not listed in MANIFEST is EXTRA.
verify_tree() {
  local restored_root="$1"
  local label="$2"
  local expected_file="$3"

  local diffs=0
  local files=0
  local path expected actual
  local expected_paths
  expected_paths="$(mktemp)"
  cut -f2 "${expected_file}" | sort -u > "${expected_paths}"

  echo "verify: ${label}"
  echo "  restored_root=${restored_root}"

  while IFS=$'\t' read -r expected path; do
    files=$((files + 1))
    local full="${restored_root}/${path}"
    if [[ ! -f "${full}" ]]; then
      echo "  MISSING: ${path}"
      diffs=$((diffs + 1))
      continue
    fi
    actual="$(sha256_file "${full}")"
    if [[ "${actual}" != "${expected}" ]]; then
      echo "  HASH_MISMATCH: ${path}"
      echo "    expected=${expected}"
      echo "    actual=${actual}"
      diffs=$((diffs + 1))
    fi
  done < "${expected_file}"

  # EXTRA: every regular file under restored_root must be in the MANIFEST set
  local f rel
  while IFS= read -r -d '' f; do
    rel="${f#"${restored_root}/"}"
    if ! grep -Fqx "${rel}" "${expected_paths}"; then
      echo "  EXTRA: ${rel}"
      diffs=$((diffs + 1))
    fi
  done < <(find "${restored_root}" -type f -print0 | sort -z)

  rm -f "${expected_paths}"

  echo "  files=${files} differences=${diffs}"
  FILES="${files}"
  DIFFS="${diffs}"
  [[ "${diffs}" -eq 0 ]]
}

restore_tarball() {
  local tarball="$1"
  local dest="$2"
  mkdir -p "${dest}"
  tar -xzf "${tarball}" -C "${dest}"
}

restore_branch() {
  local ref="$1"
  local dest="$2"
  mkdir -p "${dest}"
  local paths=(
    "crates/rvc-signer"
    "crates/rvc-keygen"
    "crates/rvc/src/main.rs"
    "crates/rvc/src/commands"
  )
  local p objtype
  for p in "${paths[@]}"; do
    if ! git -C "${REPO_ROOT}" cat-file -e "${ref}:${p}" 2>/dev/null; then
      echo "error: path missing from ${ref}: ${p}" >&2
      return 1
    fi
    objtype="$(git -C "${REPO_ROOT}" cat-file -t "${ref}:${p}")"
    if [[ "${objtype}" == "blob" ]]; then
      mkdir -p "$(dirname "${dest}/${p}")"
      git -C "${REPO_ROOT}" show "${ref}:${p}" > "${dest}/${p}"
    else
      git -C "${REPO_ROOT}" archive "${ref}" "${p}" | tar -x -C "${dest}"
    fi
  done
}

# Pin tarball blob to MANIFEST header (required for --tarball / default tarball mode).
check_tarball_blob_sha() {
  local tarball="$1"
  local expected_sha
  expected_sha="$(parse_tarball_sha "${MANIFEST}")"
  if [[ -z "${expected_sha}" ]]; then
    echo "error: MANIFEST missing Tarball SHA-256 header field" >&2
    return 1
  fi
  local actual_sha
  actual_sha="$(sha256_file "${tarball}")"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "  TARBALL_SHA_MISMATCH: ${tarball}"
    echo "    expected=${expected_sha}"
    echo "    actual=${actual_sha}"
    return 1
  fi
  echo "  tarball_sha=${actual_sha} (matches MANIFEST)"
  return 0
}

EXPECTED_TMP="$(mktemp)"
parse_manifest "${MANIFEST}" > "${EXPECTED_TMP}"
EXPECTED_COUNT="$(wc -l < "${EXPECTED_TMP}" | tr -d ' ')"
if [[ "${EXPECTED_COUNT}" -eq 0 ]]; then
  echo "error: no per-file hashes parsed from ${MANIFEST}" >&2
  rm -f "${EXPECTED_TMP}"
  exit 1
fi

SCRATCH_BASE="$(mktemp -d "${TMPDIR:-/tmp}/verify-orphans.XXXXXX")"
cleanup() {
  rm -rf "${SCRATCH_BASE}"
  rm -f "${EXPECTED_TMP}"
}
trap cleanup EXIT

TOTAL_DIFFS=0
TOTAL_FILES=0
FAILED=0

run_one() {
  local mode="$1"
  local target="$2"
  local scratch="${SCRATCH_BASE}/${mode}-$$"
  mkdir -p "${scratch}"
  case "${mode}" in
    tarball)
      if [[ ! -f "${target}" ]]; then
        echo "error: tarball not found: ${target}" >&2
        FAILED=1
        return
      fi
      echo "verify: tarball-blob:${target}"
      if ! check_tarball_blob_sha "${target}"; then
        FAILED=1
        TOTAL_DIFFS=$((TOTAL_DIFFS + 1))
        return
      fi
      restore_tarball "${target}" "${scratch}"
      ;;
    branch)
      if ! git -C "${REPO_ROOT}" rev-parse --verify "${target}" >/dev/null 2>&1; then
        echo "error: branch/ref not found: ${target}" >&2
        FAILED=1
        return
      fi
      restore_branch "${target}" "${scratch}"
      ;;
    dir)
      if [[ ! -d "${target}" ]]; then
        echo "error: directory not found: ${target}" >&2
        FAILED=1
        return
      fi
      # --dir must point at a restore root of archived content only (not a full repo).
      scratch="${target}"
      ;;
    *)
      echo "error: unknown mode ${mode}" >&2
      FAILED=1
      return
      ;;
  esac

  FILES=0
  DIFFS=0
  if verify_tree "${scratch}" "${mode}:${target}" "${EXPECTED_TMP}"; then
    :
  else
    FAILED=1
  fi
  TOTAL_FILES="${FILES}"
  TOTAL_DIFFS=$((TOTAL_DIFFS + DIFFS))
}

if [[ "${RUN_DEFAULT}" -eq 1 ]]; then
  run_one tarball "${DEFAULT_TARBALL}"
  run_one branch "${DEFAULT_BRANCH}"
else
  run_one "${MODE}" "${TARGET}"
fi

echo "files=${TOTAL_FILES} differences=${TOTAL_DIFFS}"
if [[ "${FAILED}" -ne 0 ]] || [[ "${TOTAL_DIFFS}" -ne 0 ]]; then
  exit 1
fi
exit 0
