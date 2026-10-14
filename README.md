# RVC — Rust Validator Client

> [!WARNING]
> This project is under active development and not yet ready for production use. APIs and behavior may change without notice.

An Ethereum Validator Client built in Rust. Handles the full validator lifecycle: block proposals, attestations, sync committee participation, aggregation duties, slashing protection, multi-BN failover, doppelganger detection, MEV/builder integration, runtime key management, and distributed tracing.

## Features

- **3-phase slot processing** — Block proposals (t=0), attestations + sync messages (t=slot/3), aggregations + contributions (t=2*slot/3)
- **Multi-beacon-node failover** — Health-scored selection strategies (First, Best, Broadcast) with EMA latency tracking
- **Slashing protection** — EIP-3076 compliant SQLite-backed attestation and block checks with interchange import/export
- **Doppelganger detection** — 2-epoch monitoring before activating signing (Lodestar pattern)
- **MEV/builder integration** — Validator registration with jitter, blinded block support
- **Keymanager API** — Full [Ethereum Keymanager API](docs/keymanager-api.md) ([OpenAPI spec](docs/keymanager-api.openapi.yaml)) with keystores, remote keys, per-validator fee recipient/gas limit/graffiti, and voluntary exit signing (see also [validators config reference](docs/validators-config.md) and [sample file](validators.example.toml))
- **Remote signing** — Web3Signer support via CompositeSigner routing
- **Key generation** — BIP-39 mnemonic generation, EIP-2333 HD derivation, deposit data, voluntary exits, BLS-to-execution changes
- **Secret management** — Pluggable secret providers (GCP Secret Manager) with periodic key refresh, format auto-detection, and observability
- **Distributed tracing** — OpenTelemetry with OTLP/HTTP and GCP Cloud Trace exporters
- **Electra ready** — EIP-7549 single attestation support with fork-aware orchestration

## Quick Start

```bash
# Build
cargo build --release

# Generate validator keys
./target/release/rvc-keygen new-mnemonic \
    --network mainnet \
    --num-validators 1 \
    --output-dir ./validators

# Run the validator client
./target/release/rvc start -c config.toml
```

## Configuration

Copy `config.example.toml` to `config.toml` and customize. CLI flags override config file values.

```toml
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing_protection.sqlite"
network = "mainnet"
```

See `config.example.toml` for all options including multi-BN failover, Keymanager API, remote signing, secret providers, and tracing.

To estimate consensus-layer performance of a key set from a beacon node (without running `rvc`), see [docs/validator-perf.md](docs/validator-perf.md).

To run `rvc` against a local Electra chain (geth + Lighthouse) and collect client-side plus chain-side reports, see [docs/devnet-testbed.md](docs/devnet-testbed.md).

## Binaries

| Binary | Description |
|--------|-------------|
| `rvc` | Main validator client — runs duties, signs messages, manages keys |
| `rvc-keygen` | Key generation tool — mnemonics, deposits, exits, BLS-to-execution changes |

### rvc-keygen Subcommands

```bash
rvc-keygen new-mnemonic          # Generate new mnemonic and derive keys
rvc-keygen existing-mnemonic     # Derive keys from existing mnemonic
rvc-keygen bls-to-execution      # Generate BLS-to-execution-change messages
rvc-keygen exit                  # Generate signed voluntary exit messages
```

## Architecture

RVC is a modular workspace of 21 crates (2 binaries + 19 libraries) organized in four layers:

```
Binary         bin/rvc, bin/rvc-keygen
Orchestrator   rvc (DutyOrchestrator)
Domain         signer, duty-tracker, propagator, timing, block-service, sync-service, builder
Foundation     crypto, slashing, bn-manager, beacon, metrics, eth-types, keymanager-api, telemetry, validator-store, doppelganger, secret-provider
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams and crate descriptions.

## Development

```bash
cargo check                       # Type check
cargo fmt                         # Format
cargo clippy                      # Lint
cargo test                        # Run all tests
cargo test test_name              # Run single test
cargo test -- --nocapture         # Run with output
```

## Supported Networks

- Mainnet
- Hoodi
- Holesky
- Sepolia
- Custom (with explicit genesis parameters)

## Supported Forks

Phase0, Altair, Bellatrix, Capella, Deneb, Electra, Fulu

## License

MIT OR Apache-2.0
