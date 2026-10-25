#!/usr/bin/env bash
# Scan git history with gitleaks in git mode.
#
# Usage: gitleaks_range_scan.sh <config> <base-sha|--history> [gitleaks flags...]
#
# Git mode reads each added hunk whole, so no no-git chunk boundary applies.
# The scan covers merge-base(<base-sha>, HEAD)..HEAD, so a force push still
# scans the pushed commits. A base that the clone does not have (a new branch
# sends all zeros) scans the full history of all refs, as --history does.
# -m shows merge resolutions, and --text shows files marked -diff.
# Gitleaks 8.21.2 can exit 0 after "failed to scan Git repository", so this
# script fails on that message or on a "[git] " error line.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <config> <base-sha|--history> [gitleaks flags...]" >&2
  exit 2
fi
config=$1
base=$2
shift 2
gitleaks=${GITLEAKS_BIN:-gitleaks}
git_opts="-m --text"
full_history="--all --full-history"

if [[ "$base" == "--history" ]]; then
  log_opts="$git_opts $full_history"
  echo "scanning the full history of all refs in git mode"
elif [[ ! "$base" =~ ^[0-9a-f]{40}$ ]]; then
  echo "base must be a full 40-hex commit SHA or --history, got '${base}'" >&2
  exit 2
elif git cat-file -e "${base}^{commit}" 2>/dev/null \
  && merge_base=$(git merge-base "$base" HEAD 2>/dev/null); then
  log_opts="$git_opts ${merge_base}..HEAD"
  echo "scanning commits ${merge_base}..HEAD in git mode"
else
  log_opts="$git_opts $full_history"
  echo "base ${base} has no common ancestor with HEAD in this clone. Fallback: full history in git mode."
fi

stderr_log=$(mktemp)
trap 'rm -f "$stderr_log"' EXIT

set +e
"$gitleaks" detect --source . "--log-opts=${log_opts}" \
  --config "$config" --ignore-gitleaks-allow --redact --no-banner --exit-code 1 "$@" \
  2>"$stderr_log"
code=$?
set -e
cat "$stderr_log" >&2

if grep -qE 'failed to scan|\[git\] ' "$stderr_log"; then
  echo "gitleaks did not read the whole git log (see the errors above). The scan fails." >&2
  exit 1
fi
exit "$code"
