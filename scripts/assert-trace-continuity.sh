#!/usr/bin/env bash
# assert-trace-continuity.sh — TRC-5c / #434.
#
# Continuity check over a Jaeger query document already written by
# scripts/trace-e2e.sh (GET /api/traces?service=rvc). This does not start a
# stack and does not re-run trace-e2e.
#
#   data[].spans[]                              operationName, startTime, duration
#   data[].processes[<processID>].serviceName   resource service.name
#
# service.name is the process serviceName. Span tags are ignored.
#
# The file must be exactly one JSON value (one Jaeger query object). A second
# value is malformed. Exit 0 only when some trace (grouped by traceID)
# contains both:
#   1. a span named slot.process
#   2. a signer span: signer.v2.sign_* (including sign_block_header and
#      sign_root), or the HTTP sign span (sign, sign.remote)
# and those spans have distinct process serviceName values, with the signer
# side exactly rvc-signer.
#
# A span traceID wins. If it is missing or empty, the enclosing trace's
# traceID is the group key. If neither is a non-empty string, that span has
# no trace group: the file exits non-zero (missing-trace-id). Spans are not
# joined on a shared sentinel.
#
# Argument: spans file. Default: $TRACE_E2E_SPANS_FILE, else
# <repo>/target/trace-e2e/spans.json.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat <<EOF
Usage: $(basename "$0") [spans-file]

Assert one Jaeger trace group contains slot.process and a signer span on
distinct process serviceName values, with the signer side exactly rvc-signer.

  spans-file   Jaeger GET /api/traces JSON. Default: \$TRACE_E2E_SPANS_FILE
               or ${ROOT}/target/trace-e2e/spans.json
EOF
}

fail() {
    local name="$1"
    shift
    printf 'assert-trace-continuity: FAIL %s: %s\n' "${name}" "$*" >&2
    exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -gt 1 ]]; then
    fail usage "expected at most one spans file argument"
fi

spans_file="${1:-${TRACE_E2E_SPANS_FILE:-${ROOT}/target/trace-e2e/spans.json}}"

if ! command -v jq >/dev/null 2>&1; then
    fail jq-missing "jq is required to read Jaeger query JSON"
fi

if [[ ! -e "${spans_file}" ]]; then
    fail missing-file "spans file not found: ${spans_file}; operationNames=(none); serviceNames=(none)"
fi

if [[ ! -f "${spans_file}" ]]; then
    fail malformed "spans path is not a regular file: ${spans_file}; operationNames=(none); serviceNames=(none)"
fi

if [[ ! -s "${spans_file}" ]]; then
    fail empty "spans file is empty: ${spans_file}; operationNames=(none); serviceNames=(none)"
fi

# Classifier prints "<status>\t<detail>" for exactly one JSON value.
# Span tags are not read. serviceName comes only from
# data[].processes[processID].serviceName. jq -s slurps the value stream
# so a second JSON value cannot be classified as its own document.
filter="$(cat <<'EOF'
def is_signer_op:
  type == "string" and (
    . == "sign"
    or . == "sign.remote"
    or startswith("signer.v2.sign_")
  );

def service_of($trace; $pid):
  if ($trace | type) != "object" then ""
  elif ($trace.processes | type) != "object" then ""
  elif (($trace.processes[$pid] // null) | type) != "object" then ""
  elif (($trace.processes[$pid].serviceName // null) | type) != "string" then ""
  else $trace.processes[$pid].serviceName
  end;

def nonempty_id:
  type == "string" and length > 0;

# Span traceID, else the enclosing trace's traceID. null when neither resolves.
def resolved_trace($trace; $span):
  if ($span.traceID | nonempty_id) then $span.traceID
  elif ($trace.traceID | nonempty_id) then $trace.traceID
  else null
  end;

def span_rows:
  [
    .data[]
    | select(type == "object")
    | . as $trace
    | ($trace.spans // [])
    | select(type == "array")
    | .[]
    | select(type == "object")
    | . as $span
    | {
        trace: resolved_trace($trace; $span),
        op: (
          if ($span.operationName | type) == "string" and ($span.operationName | length) > 0
          then $span.operationName
          else "(missing-operationName)"
          end
        ),
        svc: service_of($trace; ($span.processID // ""))
      }
  ];

def svc_label:
  if . == "" then "(missing-serviceName)" else . end;

def classify_document:
  if type != "object" then
    "malformed\tspans file is not a Jaeger query object; operationNames=(none); serviceNames=(none)"
  elif (.data | type) != "array" then
    "malformed\tspans file has no data array; operationNames=(none); serviceNames=(none)"
  else
    span_rows as $rows
    | if ($rows | length) == 0 then
        "empty\tspans file contains no spans; operationNames=(none); serviceNames=(none)"
      else
        ([$rows[].op] | unique | sort | join(",")) as $ops
        | ([$rows[].svc | svc_label] | unique | sort | join(",")) as $svcs
        | if any($rows[]; .trace == null) then
            "missing-trace-id\tspan has no traceID on the span or its enclosing trace; operationNames=\($ops); serviceNames=\($svcs)"
          else
            (
          $rows
          | group_by(.trace)
          | map(
              . as $g
              | {
                  slots: [$g[] | select(.op == "slot.process")],
                  signers: [$g[] | select(.op | is_signer_op)]
                }
              | .both = ((.slots | length) > 0 and (.signers | length) > 0)
              | .pass = (
                  any(.signers[]; .svc == "rvc-signer")
                  and any(.slots[]; .svc != "" and .svc != "rvc-signer")
                )
              | .distinct_pair = (
                  [
                    .slots[] as $slot
                    | .signers[] as $signer
                    | select(
                        $slot.svc != ""
                        and $signer.svc != ""
                        and $slot.svc != $signer.svc
                      )
                  ]
                  | length > 0
                )
            )
        ) as $groups
      | if any($groups[]; .pass) then
          "ok\toperationNames=\($ops); serviceNames=\($svcs)"
        elif any($groups[]; .both) | not then
          "missing-span\tno trace group contains both slot.process and a signer span; operationNames=\($ops); serviceNames=\($svcs)"
        elif any($groups[]; .distinct_pair) then
          "signer-service\tsigner span serviceName is not rvc-signer; operationNames=\($ops); serviceNames=\($svcs)"
        else
          "same-service\tboth span kinds share one serviceName; operationNames=\($ops); serviceNames=\($svcs)"
            end
        end
      end
  end;

if length != 1 then
  "malformed\tspans file contains more than one JSON value; operationNames=(none); serviceNames=(none)"
else
  .[0] | classify_document
end
EOF
)"

if ! jq_out="$(jq -s -r "${filter}" "${spans_file}" 2>&1)"; then
    fail malformed "spans file is not valid JSON (${spans_file}): ${jq_out}; operationNames=(none); serviceNames=(none)"
fi

status="${jq_out%%$'\t'*}"
detail="${jq_out#*$'\t'}"

case "${status}" in
    ok)
        printf 'assert-trace-continuity: ok %s\n' "${detail}"
        ;;
    missing-span | missing-trace-id | same-service | signer-service | empty | malformed)
        fail "${status}" "${detail}"
        ;;
    *)
        fail malformed "unrecognized classifier output from ${spans_file}: ${jq_out}"
        ;;
esac
