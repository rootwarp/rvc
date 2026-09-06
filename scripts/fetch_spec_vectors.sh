#!/usr/bin/env bash
# Fetch pinned consensus-specs / ssz-specs archives, sha256-verify, then extract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${REPO_ROOT:-}" ]]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
fi
LOCK="${VECTORS_LOCK:-$REPO_ROOT/crates/rvc-spec-vectors/vectors.lock}"
VECTORS_DIR="${VECTORS_DIR:-$REPO_ROOT/crates/rvc-spec-vectors/vectors}"
PRESET="${PRESET:-minimal}"

# bash 3.2: unquoted regex on the RHS of =~.
TAG_RE='^[A-Za-z0-9._-]+$'
FILE_RE='^[A-Za-z0-9._-]+(\.tar\.gz)?$'
SHA_RE='^[0-9a-f]{64}$'
PY_RE='^[0-9]+\.[0-9]+\.[0-9]+$'
SCRIPT_RE='^scripts/[A-Za-z0-9._-]+\.py$'
OUTPUT_PREFIX='crates/rvc-spec-vectors/vectors-generated/'
ARGV_TOKEN_RE='^(--[A-Za-z0-9-]+|0x[0-9a-fA-F]+|[A-Za-z0-9._-]+)$'

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

# KEY=VALUE reader for a [[generated]] block file (same shape as SPEC_TAG=).
kv_from() {
    local file="$1" key="$2" out rc
    set +e
    out="$(awk -F= -v k="$key" '
        $1 == k {
            print substr($0, index($0, "=") + 1)
            c++
        }
        END { if (c > 1) exit 2; if (!c) exit 1 }
    ' "$file")"
    rc=$?
    set -e
    if [[ "$rc" -eq 2 ]]; then
        die "duplicate '$key' in generated entry
file: $file"
    fi
    if [[ "$rc" -ne 0 ]]; then
        return 1
    fi
    printf '%s' "$out"
}

require_generated_field() {
    local name="$1" val="$2"
    if [[ -z "$val" ]]; then
        die "generated entry missing or empty '$name' in $LOCK
hint: [[generated]] requires id, python, pip, script, argv, output, sha256 (empty field fails verify)"
    fi
}

require_relpath() {
    local what="$1" rel="$2"
    case "$rel" in
        "" | /* | *..*)
            die "invalid $what '$rel' in $LOCK
hint: $what must be a relative path without '..'"
            ;;
    esac
}

# Split [[generated]] KEY=VALUE blocks into temp files; print their paths.
split_generated_blocks() {
    local dest="$1"
    mkdir -p "$dest"
    awk -v dir="$dest" '
        /^\[\[generated\]\]$/ {
            if (out != "") close(out)
            n++
            out = sprintf("%s/%d", dir, n)
            print "" > out
            print out
            next
        }
        out != "" && $1 == "archive" { close(out); out = ""; next }
        out != "" && /^\[\[/ { close(out); out = ""; next }
        out != "" && /^[[:space:]]*#/ { next }
        out != "" && /^[[:space:]]*$/ { close(out); out = ""; next }
        out != "" { print > out }
        END { if (out != "") close(out) }
    ' "$LOCK"
}

recipe_mentions_forbidden() {
    local script="$1"
    grep -nE 'rvc|vectors-generated' -- "$script" >/dev/null 2>&1
}

assert_recipe_has_no_rsvc_path() {
    local script="$1"
    if recipe_mentions_forbidden "$script"; then
        printf 'error: recipe script references an rs-vc path or output: %s\n' "$script" >&2
        grep -nE 'rvc|vectors-generated' -- "$script" >&2 || true
        printf 'hint: ADR-005 — import eth-ssz-specs only; pass --out via argv\n' >&2
        exit 1
    fi
}

# pip=eth-ssz-specs==0.1.0 -r <id>/requirements.txt with hashes for the full wheel closure.
hashed_requirements_rel() {
    printf '%s%s/requirements.txt' "$OUTPUT_PREFIX" "$gen_id"
}

assert_hashed_requirements() {
    local rel req n
    rel="$(hashed_requirements_rel)"
    if [[ "$gen_pip" != "eth-ssz-specs==0.1.0 -r $rel" ]]; then
        die "invalid generated pip '$gen_pip' in $LOCK
hint: want \`eth-ssz-specs==0.1.0 -r $rel\` pinning the full wheel closure with --hash=sha256"
    fi
    require_relpath pip_requirements "$rel"
    req="$REPO_ROOT/$rel"
    [[ -f "$req" ]] || die "hashed requirements not found: $req
hint: pin eth-ssz-specs, pydantic, pydantic-core, and their wheels with --hash=sha256"
    grep -q '^eth-ssz-specs==0\.1\.0' "$req" \
        || die "hashed requirements must pin eth-ssz-specs==0.1.0: $req"
    grep -q '^pydantic==' "$req" \
        || die "hashed requirements must pin pydantic (full pip closure): $req"
    grep -q '^pydantic-core==' "$req" \
        || die "hashed requirements must pin pydantic-core (full pip closure): $req"
    n="$(grep -cE -- '--hash=sha256:[0-9a-f]{64}' "$req" || true)"
    if [[ "$n" -lt 2 ]]; then
        die "hashed requirements must include --hash=sha256 for every wheel in the closure (got $n): $req"
    fi
}

# Load one [[generated]] block; sets gen_* globals (bash 3.2 has no assoc arrays).
load_generated_entry() {
    local block="$1"
    gen_id="$(kv_from "$block" id || true)"
    gen_python="$(kv_from "$block" python || true)"
    gen_pip="$(kv_from "$block" pip || true)"
    gen_script="$(kv_from "$block" script || true)"
    gen_argv="$(kv_from "$block" argv || true)"
    gen_output="$(kv_from "$block" output || true)"
    gen_sha="$(kv_from "$block" sha256 || true)"

    require_generated_field id "$gen_id"
    require_generated_field python "$gen_python"
    require_generated_field pip "$gen_pip"
    require_generated_field script "$gen_script"
    require_generated_field argv "$gen_argv"
    require_generated_field output "$gen_output"
    require_generated_field sha256 "$gen_sha"

    if [[ ! "$gen_id" =~ $TAG_RE ]]; then
        die "invalid generated id '$gen_id' in $LOCK
hint: id must match $TAG_RE (no slashes)"
    fi
    if [[ ! "$gen_python" =~ $PY_RE ]]; then
        die "invalid generated python '$gen_python' in $LOCK
hint: record the exact patch version (e.g. 3.13.7); verify does not require the local interpreter to match"
    fi
    assert_hashed_requirements
    if [[ ! "$gen_script" =~ $SCRIPT_RE ]]; then
        die "invalid generated script '$gen_script' in $LOCK
hint: script must be scripts/<name>.py"
    fi
    require_relpath output "$gen_output"
    require_relpath script "$gen_script"
    if [[ "$gen_output" != "${OUTPUT_PREFIX}${gen_id}/roots.yaml" &&
        "$gen_output" != "${OUTPUT_PREFIX}${gen_id}/signing_roots.yaml" ]]; then
        die "generated output '$gen_output' must be ${OUTPUT_PREFIX}${gen_id}/roots.yaml or signing_roots.yaml"
    fi
    validate_generated_argv
    require_sha "$gen_sha"
}

# argv is space-separated tokens: --out <output> then optional --gloas-out <path>
# and --flag 0xhex pairs (4.0 / 5.13a).
validate_generated_argv() {
    local tok expected gloas_out
    expected="--out $gen_output"
    if [[ "$gen_argv" != "$expected" && "$gen_argv" != "$expected "* ]]; then
        die "generated argv '$gen_argv' must start with '--out $gen_output'"
    fi
    # shellcheck disable=SC2086
    set -- $gen_argv
    if [[ "$1" != "--out" || "$2" != "$gen_output" ]]; then
        die "generated argv '$gen_argv' must start with '--out $gen_output'"
    fi
    shift 2
    if [[ "${1:-}" == "--gloas-out" ]]; then
        gloas_out="${2:-}"
        [[ -n "$gloas_out" ]] || die "generated argv missing value for --gloas-out"
        require_relpath gloas-out "$gloas_out"
        case "$gloas_out" in
            "${OUTPUT_PREFIX}"*) ;;
            *)
                die "generated --gloas-out '$gloas_out' must start with $OUTPUT_PREFIX"
                ;;
        esac
        shift 2
    fi
    for tok in "$@"; do
        if [[ ! "$tok" =~ $ARGV_TOKEN_RE ]]; then
            die "invalid generated argv token '$tok' in $LOCK
hint: extra tokens must be --flags, 0x-prefixed hex (fork version / GVR), or a spec tag"
        fi
    done
}

foreach_generated() {
    local cb="$1" work blocks block
    work="$(mktemp -d)"
    blocks="$(split_generated_blocks "$work")" || {
        rm -rf -- "$work"
        die "failed to parse [[generated]] entries in $LOCK"
    }
    if [[ -z "$blocks" ]]; then
        rm -rf -- "$work"
        die "no [[generated]] entries in $LOCK
hint: add a [[generated]] block with id, python, pip, script, argv, output, sha256"
    fi
    while IFS= read -r block; do
        [[ -n "$block" ]] || continue
        load_generated_entry "$block"
        "$cb"
    done <<< "$blocks"
    rm -rf -- "$work"
}

verify_one_generated() {
    local script_path output_path
    script_path="$REPO_ROOT/$gen_script"
    output_path="$REPO_ROOT/$gen_output"
    [[ -f "$script_path" ]] || die "generated script not found: $script_path"
    assert_recipe_has_no_rsvc_path "$script_path"
    [[ -f "$output_path" ]] || die "generated output not found: $output_path"
    verify_file "$output_path" "$gen_sha" || die "generated digest mismatch for id '$gen_id'"
    echo "generated ok: $gen_id ($gen_output)"
}

regen_one_generated() {
    local script_path output_path venv wheeld req rel pyver f actual seen
    script_path="$REPO_ROOT/$gen_script"
    output_path="$REPO_ROOT/$gen_output"
    [[ -f "$script_path" ]] || die "generated script not found: $script_path"
    assert_recipe_has_no_rsvc_path "$script_path"

    command -v python3 >/dev/null 2>&1 || die "python3 is required for regen (need >= 3.12)"
    python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' \
        || die "python3 >= 3.12 is required (got $(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])'))"
    pyver="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
    echo "regen python: $pyver (lock records $gen_python)"
    if [[ "$pyver" != "$gen_python" ]]; then
        printf 'warning: local python %s differs from lock python %s (artifact must stay byte-identical)\n' \
            "$pyver" "$gen_python" >&2
    fi

    rel="$(hashed_requirements_rel)"
    req="$REPO_ROOT/$rel"

    venv="$(mktemp -d)"
    wheeld="$(mktemp -d)"
    if ! python3 -m venv "$venv"; then
        rm -rf -- "$venv" "$wheeld"
        die "python3 -m venv failed"
    fi
    if ! "$venv/bin/python" -m pip download --disable-pip-version-check \
        --require-hashes --only-binary :all: -d "$wheeld" -r "$req"; then
        rm -rf -- "$venv" "$wheeld"
        die "pip download --require-hashes failed: $rel"
    fi
    seen=0
    for f in "$wheeld"/*; do
        if [[ ! -e "$f" ]]; then
            continue
        fi
        if [[ ! -f "$f" ]]; then
            rm -rf -- "$venv" "$wheeld"
            die "non-file in pip download dir: $f"
        fi
        case "$f" in
            *.whl) ;;
            *)
                rm -rf -- "$venv" "$wheeld"
                die "refusing non-wheel download (unhashed install would follow): $f"
                ;;
        esac
        actual="$(file_digest "$f" | tr 'A-F' 'a-f')"
        if ! grep -qE -- "--hash=sha256:$actual" "$req"; then
            rm -rf -- "$venv" "$wheeld"
            die "unhashed wheel would be installed: $f ($actual)
hint: add --hash=sha256:$actual to $rel"
        fi
        seen=1
    done
    if [[ "$seen" -ne 1 ]]; then
        rm -rf -- "$venv" "$wheeld"
        die "pip download produced no wheels for $rel"
    fi
    if ! "$venv/bin/python" -m pip install --disable-pip-version-check -q \
        --require-hashes --only-binary :all: --no-index --find-links "$wheeld" -r "$req"; then
        rm -rf -- "$venv" "$wheeld"
        die "pip install --require-hashes --no-index failed: $rel"
    fi

    mkdir -p "$(dirname -- "$output_path")"
    # shellcheck disable=SC2086
    set -- $gen_argv
    if ! (
        cd "$REPO_ROOT"
        PYTHONHASHSEED=0 "$venv/bin/python" "$gen_script" "$@"
    ); then
        rm -rf -- "$venv" "$wheeld"
        die "recipe failed: $gen_script"
    fi
    rm -rf -- "$venv" "$wheeld"

    echo "wrote $gen_output (sha256 $(file_digest "$output_path"))"
}

verify_all_generated() {
    foreach_generated verify_one_generated
}

regen_all_generated() {
    foreach_generated regen_one_generated
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

download_and_verify() {
    local url="$1" dest="$2" sha="$3"
    echo "downloading: $url"
    rm -f -- "$dest"
    download "$url" "$dest"
    if ! verify_file "$dest" "$sha"; then
        rm -f -- "$dest"
        return 1
    fi
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
        # Pin is the lock digest, not a restored blob. One retry, then fail closed.
        echo "cache mismatch: removing $archive and re-downloading once" >&2
        rm -f -- "$archive"
    fi

    if ! download_and_verify "$url" "$part" "$sha"; then
        return 1
    fi
    mv -- "$part" "$archive"
}

# Drop stamps and extracted trees. `.extracted.<archive>.tar.gz` matches *.tar.gz,
# so delete stamps by prefix before the archive keep-list.
drop_non_archives() {
    local dir="$1"
    rm -f -- "$dir"/.extracted.*
    find "$dir" -mindepth 1 -maxdepth 1 ! -name '*.tar.gz' ! -name '*.tar.gz.part' \
        -exec rm -rf {} +
}

extract_archive() {
    local tag="$1" url="$2" sha="$3"
    local dir="$VECTORS_DIR/$tag"
    local base archive
    base="$(basename_from_url "$url")"
    archive="$dir/$base"
    assert_under_cache "$dir"
    [[ -f "$archive" ]] || die "archive missing after fetch: $archive"
    # Pin is the tarball digest, not a stamp or a previously extracted tree.
    verify_file "$archive" "$sha" || die "archive digest mismatch before extract: $archive"

    echo "extracting: $archive -> $dir"
    drop_non_archives "$dir"
    tar -xzf "$archive" -C "$dir"
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

cmd="${1:-fetch}"
case "$cmd" in
    verify)
        verify_all_generated
        exit 0
        ;;
    regen)
        regen_all_generated
        exit 0
        ;;
    fetch) ;;
    *)
        die "unknown command '$cmd' (want fetch, verify, or regen)"
        ;;
esac

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
