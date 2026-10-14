# P0 sign-off — oracles T1–T21 (TRC-5e / #436)

Checked on develop `8fab00400df79c4f111ec69e8e7cb4d633295710` (post-#484).
A row is green only when this tip was exercised or the merge that landed the
oracle is an ancestor of that commit. Parent phase #431 stays open.

GitHub issue bodies do not print the labels T17 and T18. They are the two
TRC-5c predicates that sit between T16 and the reserved T19–T21: one trace
group contains both span kinds, and the signer side is `service.name`
`rvc-signer`.

| Oracle | What it is | Status | Evidence |
|---|---|---|---|
| T1 | Pretty line inside a sampled span carries `trace_id` and `span_id`, and the rendered trace id matches `inject_trace_context` | green | TRC-2c / #414, merge `243661a151bcc96b4543a2d761013908ed3091d1`. Test `t1_sampled_span_line_carries_keys_matching_inject` in `crates/telemetry/src/format.rs`. |
| T2 | A line outside any span carries neither key | green | Same merge. Test `t2_outside_span_keys_absent`. |
| T3 | `sample_rate: 0.0` leaves both keys absent | green | Same merge. Test `t3_unsampled_keys_absent`. |
| T4 | No `init_tracing` ⇒ substring `00000000` never appears | green | Same merge. Test `t4_without_otel_never_emits_zeroed_ids`. |
| T5 | First event inside a fresh span already carries `trace_id` (VC and signer stacks) | green | VC: TRC-2d / #413, `798bbb46632975b7a90b783f2e7b128aa0ad2fed`. Signer: TRC-2i / #419, `83e5f91643f5f6c199585ecaac6ba0f9296b7701`. |
| T6 | JSON profile yields top-level `trace_id` and `span_id` | green | TRC-2c merge above. Test `t6_json_profile_top_level_trace_and_span_id`. |
| T7 | Gate 5 field-name conformance, including the covered-event row | green | TRC-2a / #411, `51627028f2b199b9b4c09f1af268833a1b73d245`. `crates/architecture-tests/tests/field_name_conformance.rs`. |
| T8 | Telemetry correlator keys match the observability registry | green | TRC-2e / #415, `676f1d087203a12db519ab4901aaafb2e2ee4a7e`. `telemetry_field_keys_match_registry`. |
| T9 | Sign span is exported when an endpoint is set, and not when it is absent | green | TRC-2h / #418, `611286dcb70ff3ea6274502332ef9126451da6b3`. `bin/rvc-signer/tests/t9_sign_export.rs`. |
| T10 | Seeded inbound `traceparent` parents the handler span | green | TRC-3a / #421, `b5bf5daf1c0b716ba775165741d2a4f398f58219`, plus handler tests in TRC-3c `ee2fe38fc0d354ad7d3c893e512ea7cf6a351bdd` and TRC-3d `935e6444edfd361befa2892bc13a3c75864bea5e`. |
| T11 | No `traceparent` ⇒ fresh non-zero root, no panic | green | TRC-3a merge above. `test_t11_sign_randao_reveal_without_traceparent_is_fresh_trace`. |
| T12 | HTTP outbound `traceparent` span id is `sign.remote` | green | TRC-3e / #425, `900b405d2b9b4181835609da2621848c7fe05759`. `crates/remote-signer-client/src/client_tests.rs`. |
| T13 | `set_parent_from_headers` still continues an inbound trace with `TraceIdLayer` installed | green | TRC-2e merge above. `crates/telemetry/tests/trace_id_emission.rs` (name does not end in `_root`). |
| T14 | Debug span-field test asserts the exact key-set of the duty-tracker spans | green | TRC-4a / #427 `72799245b6e7f3b3a8e0bab561c3585f2118e161` and TRC-4b / #428 `89cd9304941621eb6dbed623945ecf03fb6fed54`. `test_t14_epoch_span_exact_key_sets_at_debug`. |
| T15 | Block, attestation, and aggregation record `time_into_slot` when the phase fires | green | TRC-4c / #429, `438501d3c92274662462d722bf3d56d3e44cc65d`. Also seen on the part-2 trace below (2 / 4003 / 8003). |
| T16 | `time_into_slot_ms` appears nowhere in tracked production source | green | TRC-4d / #430, `84b5c5896dd9cc98bd8da427604bbc7f2439c8c2`. `t16_no_time_into_slot_ms_in_production_source`. |
| T17 | One trace group contains `slot.process` and a signer span | green | TRC-5c / #434, `4d821b48c5be62a8c104d26b62ed58afdd512926`. On this tip: fixture `continuity__pass.json` exits 0; `continuity__missing_span.json` exits non-zero (`missing-span`). Part-2 `target/trace-e2e/spans.json` exits 0 and names both `slot.process` and `signer.v2.sign_attestation_data`. |
| T18 | Those spans use distinct process `service.name` values, signer side exactly `rvc-signer` | green | Same TRC-5c merge. On this tip: `continuity__same_service.json` exits non-zero (`same-service`). Part-2 spans file reports `serviceNames=rvc,rvc-signer`. Jaeger trace `90bbcb5135671861a60ac8e363070de8` has `signer.v2.sign_attestation_data` on process `serviceName` `rvc-signer` and `slot.process` on `rvc`. |
| T19 | `crates/slashing/src/stage.rs` is byte-identical to A-12 pin `22aa3de5bf5ed0c03ed571694dc3a5652e460613` | green | Guard landed in TRC-1e / #404, `059dbb6af7c8342b894213704f9a4e31d2841b3d`. Re-checked on this tip (blob `205106ae71c9c66d5ae4ad423fc7dd31412f690d` at the pin and at HEAD). Command and empty result below. |
| T20 | Both benches within the noise `latency-baseline.md` describes | green | This closeout. Numbers in [`t20-final-trc-5e.md`](./t20-final-trc-5e.md). Info stays at or below no-subscriber; trace stays ~10³ higher. |
| T21 | gitleaks is green on an emitted trace-level sample that contains a real 32-hex `trace_id` | green | This closeout. Commands below. Source line 27 did not move. |

## T19

```text
$ git diff 22aa3de5bf5ed0c03ed571694dc3a5652e460613 -- crates/slashing/src/stage.rs
```

Empty (0 bytes). Not diffed against `0ae9a09`. `stage.rs` was not edited.

## T21

CI steps matched from `.github/workflows/ci.yml` (emit sample, then gitleaks
with `.gitleaks-emitted.toml`). gitleaks 8.21.2.

```text
$ cargo run -q -p rvc-crypto --example log_sample > emitted-sample/emitted-trace.log
2026-10-03T14:33:59.225746Z TRACE sign{slot=6400000 duty=attestation request_id=c56f4aaf-da74-4830-bad5-c65d49197dd8}: log_sample: computed signing root trace_id=624180e7a5ca190827cae8cb7ae9465c signing_root=0x0001020304...1c1d1e1f head=0x0001020304...1c1d1e1f
```

`trace_id=624180e7a5ca190827cae8cb7ae9465c` is 32 lowercase hex. It is generated
at runtime in `crates/crypto/examples/log_sample.rs` (16 random bytes). The
pubkey literal stays on line 27, so `.gitleaksignore`
(`crates/crypto/examples/log_sample.rs:generic-api-key:27`) was not regenerated.

```text
$ gitleaks detect --no-git --source emitted-sample --config .gitleaks-emitted.toml --redact --no-banner --exit-code 1
INF no leaks found
```

```text
$ gitleaks detect --no-git --source . --config .gitleaks.toml --redact --no-banner --exit-code 1
INF no leaks found
```

The CI content assertion on that emitted log also exited 0 (raw pubkey, raw
root, and `hunter2pw` absent; redacted pubkey, root, and URL present).

## Four-step recipe

Captured in [`docs/running-guide.md`](../../docs/running-guide.md) from
`./scripts/trace-e2e.sh --part 2` on this tip. Warn line
`trace_id=90bbcb5135671861a60ac8e363070de8`, that id returned by Jaeger, phase
`time_into_slot` values 2 / 4003 / 8003, and `signer.v2.sign_attestation_data`
under `rvc-signer`.
