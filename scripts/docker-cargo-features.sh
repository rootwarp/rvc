#!/bin/sh
# Allow-list cargo features for the production image build (#602).
#
# Usage: docker-cargo-features.sh <rvc|signer> <features>
# <features> may be empty, space-separated, or comma-separated.
# Prints one space-separated list on stdout. Exits 1 if any token is outside
# the allow-list (including test-utils and package/feature paths).
set -eu
# Disable globbing so a stray `*` / `?` in FEATURES cannot expand against the
# builder filesystem while we word-split the allow-list tokens.
set -f

target="${1:?usage: docker-cargo-features.sh rvc|signer FEATURES}"
raw="${2-}"

case "$target" in
  rvc) allowed="gcp-trace gcp-secret" ;;
  signer) allowed="dvt" ;;
  *)
    echo "unknown image target: $target" >&2
    exit 1
    ;;
esac

normalized=$(printf '%s' "$raw" | tr ',' ' ')

out=""
for feat in $normalized; do
  ok=0
  for allow in $allowed; do
    if [ "$feat" = "$allow" ]; then
      ok=1
      break
    fi
  done
  if [ "$ok" -ne 1 ]; then
    echo "cargo feature '$feat' is not allow-listed for $target (allowed: $allowed)" >&2
    exit 1
  fi
  case " $out " in
    *" $feat "*) ;;
    *) out="${out:+$out }$feat" ;;
  esac
done

printf '%s\n' "$out"
