#!/usr/bin/env bash
# Fetch pinned consensus-specs / ssz-specs archives, sha256-verify, then extract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCK="${VECTORS_LOCK:-$REPO_ROOT/crates/rvc-spec-vectors/vectors.lock}"
VECTORS_DIR="${VECTORS_DIR:-$REPO_ROOT/crates/rvc-spec-vectors/vectors}"
PRESET="${PRESET:-minimal}"

# bash 3.2: unquoted regex on the RHS of =~.
TAG_RE='^[A-Za-z0-9._-]+$'
FILE_RE='^[A-Za-z0-9._-]+(\.tar\.gz)?$'
SHA_RE='^[0-9a-f]{64}$'

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

basename_from_url() {
    local url="$1"
    local path="${url#file://}"
    path="${path%%\?*}"
    printf '%s\n' "${path##*/}"
}

lock_value() {
    local key="$1"
    awk -F= -v k="$key" '
        $1 == k {
            print substr($0, index($0, "=") + 1)
            found = 1
        }
        END { exit !found }
    ' "$LOCK"
}

lookup_archive() {
    local name="$1" tag="$2" out rc
    set +e
    out="$(awk -v n="$name" -v t="$tag" '
        $1 == "archive" && $2 == n && $3 == t { print; c++ }
        END { if (c > 1) exit 2; if (!c) exit 1 }
    ' "$LOCK")"
    rc=$?
    set -e
    if [[ "$rc" -eq 2 ]]; then
        die "duplicate archive entry '$name' '$tag' in $LOCK
hint: keep a single \`archive $name $tag <url> <sha256>\` line"
    fi
    if [[ "$rc" -ne 0 ]]; then
        return 1
    fi
    printf '%s\n' "$out"
}

known_tags() {
    awk '$1 == "archive" { print $3 }' "$LOCK" | sort -u | paste -sd' ' -
}

require_tag() {
    local what="$1" tag="$2"
    if [[ -z "$tag" || "$tag" == "." || "$tag" == ".." || ! "$tag" =~ $TAG_RE ]]; then
        die "invalid $what '$tag' in $LOCK
hint: tags must match $TAG_RE (no slashes) so they cannot escape the cache directory"
    fi
}

require_sha() {
    local sha="$1"
    sha="$(printf '%s' "$sha" | tr 'A-F' 'a-f')"
    if [[ ! "$sha" =~ $SHA_RE ]]; then
        die "invalid sha256 '$sha' in $LOCK
hint: each archive line needs a 64-character hex digest"
    fi
}

require_github_url() {
    local url="$1"
    local prefix rest tag file
    case "$url" in
        https://github.com/ethereum/consensus-specs/releases/download/*)
            prefix='https://github.com/ethereum/consensus-specs/releases/download/'
            ;;
        https://github.com/ethereum/ssz-specs/releases/download/*)
            prefix='https://github.com/ethereum/ssz-specs/releases/download/'
            ;;
        *)
            die "rejected URL '$url'
hint: use https://github.com/ethereum/{consensus-specs,ssz-specs}/releases/download/<tag>/<file>"
            ;;
    esac
    rest="${url#"$prefix"}"
    # Prefix globs must not accept traversal or extra segments (302 to another repo).
    case "$rest" in
        "" | *%* | *\\* | *'?'* | *'#'* | *'..'* | */*/*)
            die "rejected URL '$url'
hint: github download URLs must be .../download/<tag>/<file> with no '..', encoding, or extra path"
            ;;
    esac
    case "$rest" in
        */*) ;;
        *)
            die "rejected URL '$url'
hint: github download URLs must be .../download/<tag>/<file>"
            ;;
    esac
    tag="${rest%%/*}"
    file="${rest#*/}"
    require_tag "url tag" "$tag"
    if [[ -z "$file" || ! "$file" =~ $FILE_RE ]]; then
        die "rejected URL '$url'
hint: filename must match $FILE_RE"
    fi
}

require_url() {
    local url="$1"
    case "$url" in
        file:///*)
            local src="${url#file://}"
            src="${src%%\?*}"
            [[ "$src" == /* ]] || die "file URL must be an absolute path: $url"
            ;;
        https://github.com/ethereum/consensus-specs/releases/download/*)
            require_github_url "$url"
            ;;
        https://github.com/ethereum/ssz-specs/releases/download/*)
            require_github_url "$url"
            ;;
        *)
            die "rejected URL '$url'
hint: use https://github.com/ethereum/{consensus-specs,ssz-specs}/releases/download/<tag>/<file> or a lowercase file:/// absolute path"
            ;;
    esac
}

require_archive_line() {
    local line="$1" nf
    nf="$(printf '%s\n' "$line" | awk '{ print NF }')"
    [[ "$nf" -eq 5 ]] || die "malformed archive line in $LOCK (want: archive name tag url sha256)
line: $line"
}

# Tags become cache path segments; after mkdir, the resolved dir must stay in-tree.
assert_under_cache() {
    local dir="$1" root child
    mkdir -p "$VECTORS_DIR" "$dir"
    root="$(cd "$VECTORS_DIR" && pwd -P)"
    child="$(cd "$dir" && pwd -P)"
    case "$child" in
        "$root" | "$root"/*) ;;
        *)
            die "refusing path '$dir' (resolves to $child) outside cache $root"
            ;;
    esac
}

file_digest() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$file" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$file" | awk '{ print $1 }'
    else
        die "need sha256sum or shasum to verify $file"
    fi
}

# Darwin sha256sum -c treats empty/short checksums as success, so compare 64-hex values.
verify_file() {
    local file="$1" expected="$2" actual
    expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
    if [[ ! "$expected" =~ $SHA_RE ]]; then
        printf 'error: invalid sha256 (want 64 hex chars): %s\n' "$expected" >&2
        printf '  file: %s\n' "$file" >&2
        return 1
    fi
    actual="$(file_digest "$file" | tr 'A-F' 'a-f')"
    if [[ ! "$actual" =~ $SHA_RE ]]; then
        printf 'error: could not hash %s\n' "$file" >&2
        return 1
    fi
    if [[ "$actual" != "$expected" ]]; then
        printf 'error: digest mismatch: %s\n' "$file" >&2
        printf '  expected: %s\n' "$expected" >&2
        printf '  actual:   %s\n' "$actual" >&2
        return 1
    fi
}

download() {
    local url="$1" dest="$2"
    require_url "$url"
    case "$url" in
        file://*)
            local src="${url#file://}"
            src="${src%%\?*}"
            if [[ -L "$src" || ! -f "$src" ]]; then
                die "file URL must be a regular file (not a symlink): $src"
            fi
            cp -- "$src" "$dest"
            ;;
        *)
            command -v curl >/dev/null 2>&1 || die "curl is required to download $url"
            curl --proto '=https' --proto-redir '=https' -fSL --retry 3 --retry-delay 1 \
                --connect-timeout 30 -o "$dest" -- "$url" || die "download failed: $url"
            ;;
    esac
}

ensure_archive() {
    local tag="$1" url="$2" sha="$3"
    local dir="$VECTORS_DIR/$tag"
    local base archive part
    base="$(basename_from_url "$url")"
    archive="$dir/$base"
    part="$archive.part"
    assert_under_cache "$dir"

    if [[ -f "$archive" ]]; then
        if verify_file "$archive" "$sha"; then
            echo "cache hit: $archive (sha256 match, skip download)"
            return 0
        fi
        printf "hint: rm -f -- '%s' and re-run to re-download\n" "$archive" >&2
        return 1
    fi

    echo "downloading: $url"
    rm -f -- "$part"
    download "$url" "$part"
    if ! verify_file "$part" "$sha"; then
        rm -f -- "$part"
        return 1
    fi
    mv -- "$part" "$archive"
}

extract_archive() {
    local tag="$1" url="$2" sha="$3"
    local dir="$VECTORS_DIR/$tag"
    local base archive stamp
    base="$(basename_from_url "$url")"
    archive="$dir/$base"
    stamp="$dir/.extracted.$base"
    assert_under_cache "$dir"

    if [[ -f "$stamp" ]] && [[ "$(tr -d ' \t\n' < "$stamp" | tr 'A-F' 'a-f')" == "$sha" ]]; then
        echo "already extracted: $dir ($base)"
        return 0
    fi

    echo "extracting: $archive -> $dir"
    tar -xzf "$archive" -C "$dir"
    printf '%s\n' "$sha" >"$stamp"
}

emit_work() {
    local line="$1" tag url sha
    require_archive_line "$line"
    tag="$(printf '%s\n' "$line" | awk '{ print $3 }')"
    url="$(printf '%s\n' "$line" | awk '{ print $4 }')"
    sha="$(printf '%s\n' "$line" | awk '{ print $5 }' | tr 'A-F' 'a-f')"
    require_tag "archive tag" "$tag"
    require_url "$url"
    require_sha "$sha"
    printf '%s %s %s\n' "$tag" "$url" "$sha"
}

[[ -f "$LOCK" ]] || die "lock file not found: $LOCK"

case "$PRESET" in
    minimal | mainnet) ;;
    *) die "PRESET must be minimal or mainnet (got '$PRESET')" ;;
esac

SPEC_TAG="$(lock_value SPEC_TAG)" \
    || die "missing SPEC_TAG in $LOCK
hint: add a line \`SPEC_TAG=<tag>\` matching an \`archive $PRESET <tag> <url> <sha256>\` entry"
require_tag SPEC_TAG "$SPEC_TAG"

SSZ_SPECS_TAG="$(lock_value SSZ_SPECS_TAG)" \
    || die "missing SSZ_SPECS_TAG in $LOCK
hint: add a line \`SSZ_SPECS_TAG=<tag>\` matching an \`archive ssz <tag> <url> <sha256>\` entry"
require_tag SSZ_SPECS_TAG "$SSZ_SPECS_TAG"

preset_line="$(lookup_archive "$PRESET" "$SPEC_TAG")" \
    || die "unknown SPEC_TAG '$SPEC_TAG' in $LOCK (preset=$PRESET)
hint: add \`archive $PRESET $SPEC_TAG <url> <sha256>\` or pin SPEC_TAG to a listed tag (known: $(known_tags))"

ssz_line="$(lookup_archive ssz "$SSZ_SPECS_TAG")" \
    || die "unknown SSZ_SPECS_TAG '$SSZ_SPECS_TAG' in $LOCK
hint: add \`archive ssz $SSZ_SPECS_TAG <url> <sha256>\` (known: $(known_tags))"

work="$(mktemp)"
trap 'rm -f -- "$work"' EXIT
emit_work "$preset_line" >>"$work"
emit_work "$ssz_line" >>"$work"

while read -r tag url sha; do
    ensure_archive "$tag" "$url" "$sha"
done <"$work"

while read -r tag url sha; do
    extract_archive "$tag" "$url" "$sha"
done <"$work"
