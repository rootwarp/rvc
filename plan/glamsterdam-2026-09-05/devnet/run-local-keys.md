# [7.8] Devnet run — local keys, 100 post-fork epochs

**Issue:** [#327](https://github.com/rootwarp/rvc/issues/327)  
**Status:** **BLOCKED** (reachable Glamsterdam BN; no funded local keys)  
**Recorded (UTC):** 2026-09-29T05:29Z  
**rvc tip (assignment pin):** `a2905f65921d378aaaafee2065c926b10e82af55`  
**Operator:** Lane | Tester (standing authority from Ash | Lead)

## Verdict

Stopped before scorecard soak. Do **not** treat this as a scorecard PASS/FAIL — the 100-epoch local-keys run did not start.

| Gate | Result |
|------|--------|
| Reachable Glamsterdam public BN | **Yes** — `devnet-8` (Plataberget) |
| Prefer healthy post-fork (skip non-finality `devnet-9` for soak) | **Met** — `devnet-8` finalizing; `devnet-9` beacon **404** |
| Funded local keystores for rs-vc | **No** — blocker |
| `scripts/devnet_preflight.py` | **PASS** against live `devnet-8` BN |
| Cross activation / ≥100 post-fork epochs / `devnet_scorecard.py` | **Not run** |

## Probe — `ethpandaops/glamsterdam-devnets`

Public homepage / beacon / config probed at execution time (README status table is stale relative to live ingress):

| Network | Homepage | `beacon…/eth/v1/node/version` | Notes |
|---------|----------|-------------------------------|--------|
| devnet-6 | 404 | 404 | Listed "On" in repo README; ingress gone |
| devnet-7 | 404 | 404 | WIP in README; ingress gone |
| **devnet-8** (Plataberget) | **200** | **200** | **Only live public stack** |
| devnet-9 | — | 404 | Non-finality net; skipped for scorecard soak per issue |
| devnet-10 | 404 | 404 | |
| devnet-11 | 404 | 404 | |

Alias: `https://plataberget.ethpandaops.io` / `https://beacon.plataberget.ethpandaops.io` mirror `devnet-8`.

### Selected net: `devnet-8` / Plataberget

- Homepage: https://glamsterdam-devnet-8.ethpandaops.io  
- Notes: https://notes.ethereum.org/@ethpandaops/glamsterdam-devnet-8  
- Network config: https://config.glamsterdam-devnet-8.ethpandaops.io/cl/config.yaml  
- Beacon (public): https://beacon.glamsterdam-devnet-8.ethpandaops.io  
- Checkpoint sync: https://checkpoint-sync.glamsterdam-devnet-8.ethpandaops.io  

**Snapshot (≈ 2026-09-29T05:29Z UTC):**

- BN version: `Lighthouse/v8.2.2-73e4dc1/x86_64-linux`
- Syncing: `is_syncing=false`, `head_slot=336445`, `sync_distance=0`
- Finality: finalized epoch **10511**, current justified **10512** (healthy; not a non-finality profile)
- Genesis: `genesis_time=1786622400`, `genesis_validators_root=0xbb4a1a9e3f7f4e10edcd734e4acc3b5ffd4f830efe0af2748fa458cfee5d2658`
- From network `config.yaml`: `GLOAS_FORK_EPOCH=1536`, `GLOAS_FORK_VERSION=0x80733183`, `SLOT_DURATION_MS=12000`
- Head epoch ≈ `336445 // 32 = 10513` → **~8977 epochs post-Gloas** (far past activation; a fresh run would be **post-fork steady**, not a boundary cross)

## Preflight evidence

```text
$ uv run --script scripts/devnet_preflight.py \
    --network-config <devnet-8 config.yaml> \
    --beacon-url https://beacon.glamsterdam-devnet-8.ethpandaops.io -v
# stderr:
https://beacon.glamsterdam-devnet-8.ethpandaops.io:443: Lighthouse/v8.2.2-73e4dc1/x86_64-linux
AGGREGATE_DUE_BPS_GLOAS: 5000 (network-config)
# stdout (rvc fragment):
network = "custom"
genesis_time = 1786622400
genesis_validators_root = "0xbb4a1a9e3f7f4e10edcd734e4acc3b5ffd4f830efe0af2748fa458cfee5d2658"
# exit 0
```

Config vs BN spec/genesis agreed; fragment is ready for a `network = "custom"` rvc config once keys exist.

## Blocker — no funded local keys

Issue AC requires **funded** Glamsterdam-era keystores driven by rs-vc (not guessing; not double-signing genesis ranges).

Checked and **not** usable:

1. **Genesis mnemonic** in ethpandaops ansible is `secret_genesis_mnemonic` (SOPS). We do not have decrypt access. Even with it, genesis ranges are already assigned to live client VCs (`config…/api/v1/nodes/validator-ranges` covers tens of thousands of indices) — loading those keys into a second VC would risk **slashing**.
2. **Host ethereum keys** on `home.rootwarp.dev`: only **Hoodi** keystores under `/Users/nil-00/ethereum/hoodi/validator_keys` — wrong network.
3. **Vault / workspace**: no Glamsterdam / Plataberget / `devnet-8` keystore tree found.
4. **Public notes / homepage**: no published community mnemonic or spare funded range for third-party VCs.
5. **Faucet** funds EL accounts, not pre-activated consensus validators with deposit already on this genesis.

Unblocking needs one of:

- A **dedicated funded keystore set** (or mnemonic + deposit indices) for rs-vc on `devnet-8`, coordinated so indices are **not** already signing elsewhere; or
- A **new** Glamsterdam public net that is still pre-fork (or freshly post-fork) **and** funded keys for that net; or
- Explicit stakeholder/ethpandaops allocation of an unused validator range.

Until then: **no scorecard**, **no** #328/#329 start.

## Not collected (blocked)

- Activation-boundary observation (epoch N−1 → N) — fork already long past on the only live net  
- ≥100 consecutive post-fork epochs under uninterrupted rs-vc  
- `scripts/devnet_scorecard.py` output / raw metrics scrape / rvc log  
- Fail-closed rejection inventory  
- Attestation / PTC / proposal / slashing AC numbers  

## Next

Re-run this issue when funded keys land (or a new reachable pre-/early-post-fork Glamsterdam net appears). Keep tip pin unless Ash rebases the assignment.
