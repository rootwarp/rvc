#!/usr/bin/env bash
# Prove the source-tree gitleaks config still reports a secret on a line that
# contains the word false, and that the running-guide exception is one path
# plus one exact secret.
#
# Scans use --source . from inside the tree. Gitleaks then reports paths
# relative to that directory, which is what the anchored allowlist matches.
# An absolute --source would report absolute paths and miss ^docs/...$.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
gitleaks=${GITLEAKS_BIN:-gitleaks}
config="$root/.gitleaks.toml"

if ! command -v "$gitleaks" >/dev/null 2>&1; then
  echo "gitleaks is not on PATH (set GITLEAKS_BIN to override)" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

scan() {
  local src=$1
  local report=$2
  local code
  set +e
  (
    cd "$src" || exit 2
    "$gitleaks" detect --no-git --source . --config "$config" \
      --ignore-gitleaks-allow \
      --report-format json --report-path "$report" --no-banner --exit-code 1 >/dev/null
  )
  code=$?
  set -e
  printf '%s' "$code"
}

# A keyworded secret on the same line as `verify=false` must be a finding.
# The token is assembled here so this script is not itself a source finding.
part_a='k7Qm9pL2xV8nR4'
part_b='wT6yH3cB5dF1aE0sZ'
secret="${part_a}${part_b}"
mkdir -p "$tmp/false-line"
printf 'fn main() {\n    let api_key = "%s"; // verify=false\n}\n' "$secret" > "$tmp/false-line/sample.rs"
false_report=$tmp/false.json
false_code=$(scan "$tmp/false-line" "$false_report")
if [[ "$false_code" -eq 0 ]]; then
  echo "canary secret on a verify=false line was not detected" >&2
  exit 1
fi
python3 - "$false_report" "$secret" << 'PY'
import json, sys
findings = json.load(open(sys.argv[1]))
secrets = {f.get("Secret") for f in findings}
if sys.argv[2] not in secrets:
    raise SystemExit("verify=false canary secret missing from findings")
PY

sample='0x97f1d3a731...db22c6bb'

# The same captured value outside docs/running-guide.md must still be a finding.
mkdir -p "$tmp/other"
printf 'api_key=%s\n' "$sample" > "$tmp/other/note.md"
other_code=$(scan "$tmp/other" "$tmp/other.json")
if [[ "$other_code" -eq 0 ]]; then
  echo "running-guide sample secret was allowed outside docs/running-guide.md" >&2
  exit 1
fi

# That exact value on the running-guide path is the one allowed finding.
mkdir -p "$tmp/guide/docs"
printf 'api_key=%s\n' "$sample" > "$tmp/guide/docs/running-guide.md"
guide_code=$(scan "$tmp/guide" "$tmp/guide.json")
if [[ "$guide_code" -ne 0 ]]; then
  echo "exact running-guide sample secret was not allowed on docs/running-guide.md" >&2
  python3 - "$tmp/guide.json" << 'PY'
import json, sys
for f in json.load(open(sys.argv[1])):
    print(f.get("File"), f.get("RuleID"), f.get("StartLine"))
PY
  exit 1
fi

# A different secret on that same path must still be a finding.
mkdir -p "$tmp/guide-other/docs"
printf 'api_key=%s\n' "$secret" > "$tmp/guide-other/docs/running-guide.md"
other_on_path=$(scan "$tmp/guide-other" "$tmp/guide-other.json")
if [[ "$other_on_path" -eq 0 ]]; then
  echo "a different secret was allowed on docs/running-guide.md" >&2
  exit 1
fi

echo "gitleaks verify=false canary: detected; running-guide allow is path plus exact value"
