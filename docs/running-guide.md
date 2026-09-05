# Running rvc - Rust Validator Client

To estimate consensus-layer performance of a validator set from a beacon node (without running `rvc`), see [validator-perf.md](validator-perf.md).

## Prerequisites

- Rust toolchain (edition 2021, MSRV 1.92)
- A running Ethereum beacon node (Lighthouse, Prysm, Teku, Nimbus, or Lodestar)
- EIP-2335 keystore files for your validators

## Building

```bash
# Debug build
cargo build

# Release build (recommended for production)
cargo build --release
```

Binary locations:
- Debug: `target/debug/rvc`, `target/debug/rvc-signer`
- Release: `target/release/rvc`, `target/release/rvc-signer`

To build with DVT support for `rvc-signer`:

```bash
cargo build --release -p rvc-signer --features dvt
```

## Quick Start

```bash
# Minimal invocation (uses defaults: mainnet, localhost:5052)
rvc start

# With a config file
rvc start -c config.toml

# With CLI overrides
rvc start --beacon-url http://localhost:5052 \
          --keystore-path ./keystores \
          --password-file ./passwords.txt \
          --network mainnet
```

## Commands

### `rvc start` - Run the Validator Client

```
rvc start [OPTIONS]
```

#### Core Options

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | none | TOML configuration file |
| `--beacon-url <URL>` | `http://localhost:5052` | Beacon node HTTP endpoint |
| `--beacon-nodes <URL,URL,...>` | none | Comma-separated beacon node URLs (multi-BN failover) |
| `--keystore-path <PATH>` | `./keystores` | Directory containing EIP-2335 keystore JSON files |
| `--password-file <PATH>` | none | Password file for keystore decryption |
| `--slashing-db-path <PATH>` | `./slashing_protection.sqlite` | Slashing protection SQLite database |
| `--init-slashing-db` | false | Allow creating a **fresh empty** slashing DB if the path is missing (SEC-3). Dangerous on a previously-active validator (zero history → double-sign risk). Use only for genuine first deploy; 0-byte/corrupt files always abort. Config equivalent: `allow_fresh_db = true` |
| `--network <NETWORK>` | `mainnet` | Network preset: `mainnet`, `sepolia`, `holesky`, `goerli`, `custom` |

#### Server Options

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-port <PORT>` | `8080` | Prometheus metrics HTTP port (`/metrics`, `/health`, `/livez`, `/readyz`) |

#### Validator Options

| Flag | Default | Description |
|------|---------|-------------|
| `--graffiti <STRING>` | none | Block graffiti (max 32 bytes) |
| `--no-doppelganger-detection` | false | Disable doppelganger detection (enabled by default) |
| `--log-level <LEVEL>` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `--log-format <FMT>` | `pretty` | Console output format: `pretty` (human-readable) or `json` (structured, for log aggregation). Also settable via `RVC_LOG_FORMAT`. See OPERATOR_GUIDE §6. |

#### Keymanager API Options

| Flag | Default | Description |
|------|---------|-------------|
| `--keymanager-enabled` | false | Enable the Keymanager API server |
| `--no-keymanager` | false | Disable Keymanager API (overrides config file) |
| `--keymanager-address <ADDR>` | `127.0.0.1:5062` | Keymanager API listen address |
| `--keymanager-token-file <PATH>` | `./keymanager-api-token.txt` | Bearer token file |
| `--remote-signer-url <URL>` | none | Web3Signer URL for remote signing |

#### gRPC Remote Signer Options

| Flag | Default | Description |
|------|---------|-------------|
| `--grpc-signer-url <URL>` | none | gRPC remote signer URL (e.g., `https://signer.example.com:50052`) |
| `--grpc-signer-tls-cert <PATH>` | none | Client TLS certificate for mTLS (required if URL set) |
| `--grpc-signer-tls-key <PATH>` | none | Client TLS private key for mTLS (required if URL set) |
| `--grpc-signer-tls-ca-cert <PATH>` | none | CA certificate for mTLS verification (required if URL set) |

All three TLS flags are required when `--grpc-signer-url` is set.

#### Security Options

| Flag | Default | Description |
|------|---------|-------------|
| `--strict-permissions` | false | Exit if slashing DB has unsafe file permissions |
| `--strict-slashing-semantics` | false | Reject null-root re-signs (strict EIP-3076) |

#### Timeout Options (seconds)

| Flag | Default | Description |
|------|---------|-------------|
| `--block-production-timeout` | 3 | Block production deadline |
| `--attestation-timeout` | 4 | Attestation fetch deadline |
| `--aggregate-timeout` | 2 | Aggregate fetch/submit deadline |
| `--duty-fetch-timeout` | 10 | Duty resolution deadline |

#### Secret Provider Options

| Flag | Default | Description |
|------|---------|-------------|
| `--secret-provider <NAME>` | none | Secret provider to use for loading validator keys (e.g., `gcp`) |
| `--gcp-project-id <ID>` | none | GCP project ID (required when `--secret-provider` includes `gcp`) |
| `--gcp-secret-prefix <PREFIX>` | `validator-key-` | Prefix for GCP secret names |
| `--secret-refresh-interval <SECS>` | `0` | Interval in seconds to refresh keys from secret providers (0 = disabled) |

#### Tracing Options (OpenTelemetry)

| Flag | Default | Description |
|------|---------|-------------|
| `--tracing-endpoint <URL>` | none | OTLP endpoint (enables tracing when set) |
| `--tracing-exporter <KIND>` | `otlp` | Exporter: `otlp` or `gcp` |
| `--tracing-sample-rate <FLOAT>` | `0.01` | Head-based sampling ratio (0.0–1.0) |
| `--tracing-max-queue-size <N>` | `2048` | Max spans queued for export |
| `--tracing-max-export-batch-size <N>` | `512` | Max spans per export batch |

#### Genesis Overrides (for custom networks)

| Flag | Description |
|------|-------------|
| `--genesis-time <UNIX_TS>` | Genesis time as Unix timestamp |
| `--genesis-validators-root <HEX>` | Genesis validators root (0x-prefixed hex) |

---

### `rvc voluntary-exit` - Submit a Voluntary Exit

```
rvc voluntary-exit [OPTIONS]
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--pubkey <HEX>` | yes | - | Validator public key (hex, 0x optional) |
| `--keystore-path <PATH>` | yes | - | Keystore directory |
| `--password-file <PATH>` | yes | - | Password file |
| `--epoch <N>` | no | current | Exit epoch |
| `--confirm` | no | false | Skip confirmation prompt |
| `--beacon-url <URL>` | no | `http://localhost:5052` | Beacon node URL |
| `--slashing-db-path <PATH>` | no | none | Slashing DB path |
| `--network <NETWORK>` | no | none | Network preset |
| `--genesis-validators-root <HEX>` | no | none | Override genesis root |
| `--log-level <LEVEL>` | no | `info` | Log level |

Example:
```bash
rvc voluntary-exit \
  --pubkey 0xabcd1234... \
  --keystore-path ./keystores \
  --password-file ./passwords.txt \
  --confirm
```

## Configuration File

Create a TOML file (see `config.example.toml`):

```toml
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing_protection.sqlite"
# allow_fresh_db = true   # only for genuine first deploy (prefer --init-slashing-db once)
metrics_port = 8080
network = "mainnet"
log_level = "info"

# Optional
# password_file = "./passwords.txt"
# graffiti = "rvc"
# doppelganger_detection = true

# Multi-BN failover
# beacon_nodes = ["http://bn1:5052", "http://bn2:5052"]

# Keymanager API
# keymanager_enabled = true
# keymanager_address = "127.0.0.1:5062"
# keymanager_token_file = "./keymanager-api-token.txt"
# remote_signer_url = "https://web3signer:9000"

# Secret provider
# [secret_provider]
# provider = "gcp"
# gcp_project_id = "my-project"
# gcp_secret_prefix = "validator-key-"
# refresh_interval = 3600

# gRPC remote signer (rvc-signer)
# grpc_signer_url = "https://signer.example.com:50052"
# grpc_signer_tls_cert = "./certs/client.pem"
# grpc_signer_tls_key = "./certs/client-key.pem"
# grpc_signer_tls_ca_cert = "./certs/ca.pem"
```

CLI flags override config file values.

### `[timing]` — duty deadlines (TOML only)

These keys have no CLI flags. Values are basis points of the slot duration
read from the beacon node's `/eth/v1/config/spec` as `SLOT_DURATION_MS`
(milliseconds). A legacy `SECONDS_PER_SLOT` spelling is still accepted and
converted (`seconds * 1000`). Deadline milliseconds are
`bps * slot_duration_ms / 10000`. On mainnet (12000 ms) the pre-Gloas
defaults are 3999 ms (attestation) and 8000 ms (aggregation).

Gloas keys parse and validate at startup so a devnet can change
`aggregate_due_bps_gloas` without a rebuild. They are not selected at
runtime until fork-aware deadline resolution lands; pre-Gloas deadlines
stay 3999 / 8000 ms on a 12 s slot.

Unknown keys under `[timing]` fail startup and name the offending key.

| Key | Default | Description |
|-----|---------|-------------|
| `attestation_due_bps` | 3333 | Attestation deadline (pre-Gloas) |
| `aggregate_due_bps` | 6667 | Aggregation deadline (pre-Gloas) |
| `attestation_due_bps_gloas` | 2500 | Attestation deadline after Gloas |
| `aggregate_due_bps_gloas` | 5000 | Aggregation deadline after Gloas (devnets may set 6667) |
| `sync_message_due_bps_gloas` | 2500 | Sync-committee message deadline after Gloas |
| `contribution_due_bps_gloas` | 5000 | Sync-committee contribution deadline after Gloas |
| `payload_due_bps` | 5000 | Payload deadline (Gloas) |
| `payload_attestation_due_bps` | 7500 | Payload attestation deadline (Gloas) |

```toml
[timing]
attestation_due_bps = 3333
aggregate_due_bps = 6667
attestation_due_bps_gloas = 2500
aggregate_due_bps_gloas = 5000
sync_message_due_bps_gloas = 2500
contribution_due_bps_gloas = 5000
payload_due_bps = 5000
payload_attestation_due_bps = 7500
```

## Password File Format

One entry per line. Comments (`#`) and blank lines are ignored, and a leading
`0x` prefix on a pubkey is stripped automatically.

```
# Comments start with #
# Format: pubkey=password (one per line, 0x prefix stripped automatically)
abcd1234=mypassword
0x5678efgh=anotherpassword
```

### Wildcard default password

A line whose key is `*` sets a single default password applied to any keystore
that does not have its own `pubkey=password` line. This lets you decrypt many
keystores with one shared password while still overriding individual validators:

```
# Default password for every keystore...
*=mySharedPassword
# ...with a per-validator override for this one
0xabcd1234=differentPassword
```

The password for each keystore is resolved in this order:

1. the exact `pubkey=password` entry for that validator, if present;
2. otherwise the `*` wildcard entry, if present;
3. otherwise the keystore is skipped with a `No password found for public key …`
   warning.

Existing password files that use only `pubkey=password` lines keep working
unchanged — the wildcard is purely additive.

> **Shared-secret blast radius:** the `*` password decrypts *every* keystore
> that lacks its own entry, so anyone who can read the password file effectively
> holds all of those un-overridden validator keys. Keep the file `chmod 600` and
> scope the shared password to a trust boundary you are comfortable with.

Set restrictive permissions: `chmod 600 passwords.txt`

## Supported Networks

| Network | Genesis Time | Genesis Validators Root |
|---------|-------------|------------------------|
| mainnet | 1606824023 | `0x4b363db9...` |
| sepolia | 1655733600 | `0xd8ea171f...` |
| holesky | 1695902400 | `0x9143aa7c...` |
| goerli | 1616508000 | `0x043db0d9...` |
| custom | must specify | must specify |

## Endpoints

### Metrics (default port 8080)

| Path | Description |
|------|-------------|
| `/metrics` | Prometheus metrics |
| `/health` | JSON diagnostic (`200` when ready, `503` otherwise). Same readiness predicate as `/readyz`. Not a Kubernetes probe. |
| `/livez` | Kubernetes liveness (always process-up) |
| `/readyz` | Kubernetes readiness |

The gRPC healthz / DutyTracker listener is gone. Leftover `grpc_port` /
`grpc_address` keys fail startup. Point probes at `/health`, `/livez`, and
`/readyz` on this metrics port.

### Keymanager API (default port 5062, when enabled)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/eth/v1/keystores` | List local keystores |
| POST | `/eth/v1/keystores` | Import keystores |
| DELETE | `/eth/v1/keystores` | Delete keystores |
| GET | `/eth/v1/remotekeys` | List remote keys |
| POST | `/eth/v1/remotekeys` | Import remote keys |
| DELETE | `/eth/v1/remotekeys` | Delete remote keys |

Requires bearer token authentication.

## Startup Sequence

1. Initialize logging and telemetry (if `--tracing-endpoint` set)
2. Validate CLI timeouts (must be > 0)
3. Load config file (or defaults) and merge CLI overrides
4. Open slashing protection database
5. Run integrity check on slashing DB
6. Apply strict slashing semantics (if `--strict-slashing-semantics`)
7. Check file permissions (if `--strict-permissions`)
8. Create beacon client and BnManager (multi-BN layer)
9. Validate genesis root against beacon node
10. Check beacon reachability and log beacon node version
11. Load validator keys from keystores
12. Load keys from secret providers (if `--secret-provider` configured)
13. Start periodic key refresh (if `--secret-refresh-interval` > 0)
14. Connect gRPC remote signer (if `--grpc-signer-url` configured, lazy, non-fatal)
15. Run doppelganger detection (if enabled, ~2 epochs)
16. Build services (signer, propagator, duty tracker, builder)
17. Start Keymanager API server (if enabled)
18. Start duty orchestrator (slot-by-slot validation)
19. Start gRPC and metrics servers

## Environment Variables

```bash
# Override log filter (takes precedence over --log-level)
RUST_LOG=debug rvc start

# Per-crate filtering
RUST_LOG=rvc=trace,rvc_bn_manager=debug rvc start
```

> For reading the log stream, `RUST_LOG` recipes with verified target names, the
> canonical field reference, following a `request_id` across the `:9000` signer hop, the
> healthy `info` heartbeat, and the file-more-verbose-than-console recipe, see the
> [Operator Guide](../plan/logging/OPERATOR_GUIDE.md).

### `RVC_ALLOW_NON_WAL_SLASHING_DB` (danger — durability escape hatch)

By default the slashing-protection SQLite DB **must** open in WAL journal mode.
If the underlying filesystem cannot support WAL (tmpfs, NFSv3, SMB, some FUSE
mounts), startup aborts with a `JournalMode` error rather than signing with a
weaker durability guarantee.

To override (temporary workaround only):

```bash
RVC_ALLOW_NON_WAL_SLASHING_DB=true rvc start -c config.toml
# same env var is honoured by rvc-signer
```

What this disables:

- The hard-fail that refuses a non-WAL journal mode.
- You still get `synchronous=EXTRA` (and macOS `fullfsync=ON`), but crash
  recovery after a host power loss is **degraded**. On shared/network storage,
  two processes can also more easily see inconsistent DB state.

Risk (same-key-two-places):

- Slashing protection only works if **one** process owns the DB and that DB
  survives restarts on durable local storage. Setting this flag to run on
  shared storage (NFS/SMB) does **not** make multi-host active-active safe —
  it only silences the WAL check. Running the same validator keys on two hosts
  (or two DBs) remains a double-sign risk regardless of this flag.
- Prefer moving the DB to a WAL-capable local volume instead of using the
  escape hatch in production.

### `keystore_path` / `slashing_db_path` must travel together

These two paths are **independently settable** in config and CLI:

| Setting | Default | Role |
|---------|---------|------|
| `keystore_path` / `--keystore-path` | `./keystores` | EIP-2335 keys + process lock (`<keystore_path>/.rvc.lock`) + deletion denylist |
| `slashing_db_path` / `--slashing-db-path` | `./slashing_protection.sqlite` | EIP-3076 signing history |

Footgun — **copied data-dir deployments**:

- A common ops mistake is to rsync/snapshot only the keystore directory (or only
  the DB file) onto a new host. Keys without their slashing history re-sign
  already-broadcast messages → **slashable**. History without the matching keys
  is useless and can mask the real risk when keys are restored later from a
  different path.
- Keep both on the **same durable volume** and treat them as one unit when
  migrating, restoring, or cloning a validator. Never run the same keys on two
  live hosts.
- On Unix, startup logs a **warning** when the two paths resolve to different
  filesystems (`st_dev` differs). Heed that warning: it often means one path is
  on ephemeral storage (container layer, tmpfs) while the other is on a mount.

Recommended layout:

```toml
keystore_path = "/var/lib/rvc/keystores"
slashing_db_path = "/var/lib/rvc/slashing_protection.sqlite"
```

## Shutdown

Send `SIGINT` (Ctrl+C) or `SIGTERM` for graceful shutdown. The client will:
1. Stop the duty orchestrator
2. Close beacon node connections
3. Persist slashing DB state
4. Shut down metrics and gRPC servers

## Example Configurations

### Single Beacon Node (Testnet)

```bash
rvc start \
  --beacon-url http://localhost:5052 \
  --keystore-path ./keystores \
  --password-file ./passwords.txt \
  --network holesky \
  --log-level debug
```

### Multi-BN Production Setup

```bash
rvc start -c config.prod.toml \
  --beacon-nodes http://bn1:5052,http://bn2:5052,http://bn3:5052 \
  --strict-permissions \
  --strict-slashing-semantics \
  --log-level info
```

### With Remote Signer (Web3Signer)

```bash
rvc start \
  --keymanager-enabled \
  --remote-signer-url https://web3signer:9000 \
  --keymanager-address 127.0.0.1:5062
```

### With GCP Secret Manager

```bash
# Requires building with --features gcp-secret
rvc start -c config.toml \
  --secret-provider gcp \
  --gcp-project-id my-gcp-project \
  --gcp-secret-prefix validator-key- \
  --secret-refresh-interval 3600
```

### With OpenTelemetry Tracing

```bash
rvc start -c config.toml \
  --tracing-endpoint http://localhost:4318 \
  --tracing-sample-rate 0.1
```

For GCP Cloud Trace (requires `--features gcp-trace`):

```bash
rvc start -c config.toml \
  --tracing-exporter gcp \
  --tracing-sample-rate 0.01
```

### With gRPC Remote Signer (rvc-signer)

```bash
# Start rvc-signer first
rvc-signer serve \
  --keystore-dir ./signer-keystores \
  --password-file ./signer-password.txt \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
  --tls-ca-cert ./certs/ca.pem \
  --listen-address 0.0.0.0:50052

# Then start rvc pointing to the signer
rvc start -c config.toml \
  --grpc-signer-url https://signer.example.com:50052 \
  --grpc-signer-tls-cert ./certs/client.pem \
  --grpc-signer-tls-key ./certs/client-key.pem \
  --grpc-signer-tls-ca-cert ./certs/ca.pem
```

---

## `rvc-signer` — Remote BLS Signing Server

Standalone gRPC signing server for key isolation. Keeps validator keys on a dedicated machine while `rvc` handles duty orchestration and slashing protection.

### `rvc-signer serve` — Start the Signing Server

```
rvc-signer serve [OPTIONS]
```

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | none | TOML configuration file |
| `--listen-address <ADDR>` | `127.0.0.1:50052` | gRPC listen address |
| `--keystore-dir <PATH>` | none | Directory containing EIP-2335 keystore files |
| `--password-file <PATH>` | none | Password file for all keystores (required) |
| `--tls-cert <PATH>` | none | Server TLS certificate (PEM) |
| `--tls-key <PATH>` | none | Server TLS private key (PEM) |
| `--tls-ca-cert <PATH>` | none | CA certificate for client authentication (PEM) |
| `--backend <TYPE>` | `basic` | Signing backend: `basic` or `dvt` (requires `dvt` feature) |
| `--metrics-address <ADDR>` | `127.0.0.1:9101` | Prometheus metrics listen address |
| `--reload-interval <SECS>` | `30` | Keystore hot-reload interval (0 to disable) |
| `--dry-run` | false | Validate configuration and exit |
| `--insecure` | false | Allow starting without TLS (NOT recommended for production) |

TLS is required by default. The server refuses to start without `--tls-cert`, `--tls-key`, and `--tls-ca-cert` unless `--insecure` is explicitly set.

#### DVT Options (requires `--features dvt`)

| Flag | Default | Description |
|------|---------|-------------|
| `--dvt-peers <ADDR,ADDR,...>` | none | Comma-separated DVT peer addresses |
| `--dvt-threshold <N>` | none | Threshold for signature reconstruction |
| `--dvt-index <N>` | none | This node's share index |
| `--dvt-timeout <MS>` | `2000` | Per-peer RPC timeout in milliseconds |

### `rvc-signer split-key` — Split Key into Shares (requires `--features dvt`)

Splits a BLS secret key into Shamir shares stored as EIP-2335 keystores.

```
rvc-signer split-key [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--keystore <PATH>` | yes | Source EIP-2335 keystore |
| `--password <STRING>` | no | Source keystore password |
| `--password-file <PATH>` | no | Source keystore password file |
| `--threshold <N>` | yes | Threshold (t) for Shamir secret sharing |
| `--shares <N>` | yes | Total number of shares (n) to generate |
| `--output-dir <PATH>` | yes | Output directory for share keystores |
| `--output-password <STRING>` | no | Password for output share keystores |
| `--output-password-file <PATH>` | no | Password file for output share keystores |

Example:

```bash
# Split a key into 3 shares with threshold of 2
rvc-signer split-key \
  --keystore ./validator.json \
  --password-file ./password.txt \
  --threshold 2 \
  --shares 3 \
  --output-dir ./shares \
  --output-password-file ./share-password.txt
```

### DVT Multi-Node Setup

```bash
# Node 1
rvc-signer serve \
  --backend dvt \
  --keystore-dir ./shares/node1 \
  --password-file ./password.txt \
  --tls-cert ./certs/node1.pem \
  --tls-key ./certs/node1-key.pem \
  --tls-ca-cert ./certs/ca.pem \
  --listen-address 0.0.0.0:50052 \
  --dvt-peers node2:50052,node3:50052 \
  --dvt-threshold 2 \
  --dvt-index 0

# Node 2 and Node 3 similar with their own shares and index
```

### gRPC Services

| Service | RPC | Description |
|---------|-----|-------------|
| `SignerService` | `Sign` | Produce BLS signature over a 32-byte signing root |
| `SignerService` | `ListPublicKeys` | List all available public keys |
| `SignerService` | `GetStatus` | Check readiness, backend type, key count |
| `PeerSignerService` | `PartialSign` | DVT partial signature for threshold signing |
