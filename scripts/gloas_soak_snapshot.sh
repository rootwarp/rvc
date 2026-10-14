#!/usr/bin/env bash
# Launch scripts/gloas_soak_snapshot.py from any working directory.
# Extra wrapper flags (--python) are not passed through.
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$SCRIPT_DIR/gloas_soak_snapshot.py"

usage() {
    cat <<EOF
Usage: $(basename "$0") [wrapper flags] [gloas_soak_snapshot.py flags…]

Cwd-independent launcher for gloas_soak_snapshot.py (Python 3.11+).
All unrecognized flags are forwarded. Exit codes are the Python
script's: 0 pass, 1 unavailable/error, 2 usage, 4 failed gate.

Always runs validator_perf --json --fail-under target_rate=0.99 unless
--perf-json is given. Writes one UTC-dated JSON into --out-dir; that
directory must be outside this repository.

Wrapper flags:
  --python PATH  Interpreter (default: \$PYTHON, else python3).
                 Falls back to uv run --script if the interpreter
                 is missing or older than 3.11.
  -h, --help     This text, then Python --help

Examples:
  # Live scrape + day's epoch window. Artifact lands in OUT_DIR only.
  $(basename "$0") \\
    --out-dir /var/lib/rvc/gloas-soak \\
    --metrics-url http://127.0.0.1:8080/metrics \\
    --from-epoch "\$FROM_EPOCH" --to-epoch "\$TO_EPOCH" \\
    --validators-config /etc/rvc/validators.toml \\
    --config /etc/rvc/config.toml

  # Offline: fixture scrape, no network
  $(basename "$0") \\
    --out-dir /var/lib/rvc/gloas-soak \\
    --metrics /path/to/metrics.txt \\
    --perf-json /path/to/validator_perf.json
EOF
}

if [[ ! -f "$PY" ]]; then
    echo "$(basename "$0"): gloas_soak_snapshot.py not found at $PY" >&2
    exit 1
fi

python_bin="${PYTHON:-python3}"
show_help=0
forward=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --python)
            if [[ $# -lt 2 ]]; then
                echo "$(basename "$0"): --python requires a path" >&2
                exit 2
            fi
            python_bin="$2"
            shift 2
            ;;
        --python=*)
            python_bin="${1#--python=}"
            if [[ -z "$python_bin" ]]; then
                echo "$(basename "$0"): --python requires a path" >&2
                exit 2
            fi
            shift
            ;;
        -h|--help)
            show_help=1
            forward+=("$1")
            shift
            ;;
        *)
            forward+=("$1")
            shift
            ;;
    esac
done

if [[ $show_help -eq 1 ]]; then
    usage
    echo
elif [[ ${#forward[@]} -eq 0 ]]; then
    usage >&2
    exit 2
fi

py_ok() {
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null
}

run_py() {
    if [[ ${#forward[@]} -gt 0 ]]; then
        exec "$1" "$PY" "${forward[@]}"
    else
        exec "$1" "$PY"
    fi
}

if command -v "$python_bin" >/dev/null 2>&1 && py_ok "$python_bin"; then
    run_py "$python_bin"
fi

if command -v uv >/dev/null 2>&1; then
    if [[ ${#forward[@]} -gt 0 ]]; then
        exec uv run --script "$PY" "${forward[@]}"
    else
        exec uv run --script "$PY"
    fi
fi

echo "$(basename "$0"): need Python 3.11+ (got '${python_bin}') or uv" >&2
exit 2
