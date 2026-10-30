# Validator Key Generation Guide

This guide covers creating Ethereum validator keys, deposit data, BLS-to-execution-change messages, and voluntary exit messages using `rvc-keygen`.

## Building

```bash
cargo build --release -p rvc-keygen
```

The binary is at `target/release/rvc-keygen`.

## 1. Generate New Validator Keys

Generate a fresh mnemonic and derive one or more validator keystores with deposit data.

### Single validator (mainnet)

```bash
rvc-keygen new-mnemonic \
  --network mainnet \
  --withdrawal-address 0xYOUR_EXECUTION_ADDRESS
```

You will be prompted to create a keystore password (minimum 8 characters, entered twice for confirmation). The tool then:

1. Generates a 24-word BIP-39 mnemonic and displays it
2. Derives the signing key at path `m/12381/3600/0/0/0`
3. Encrypts the signing key into an EIP-2335 keystore (Scrypt)
4. Signs the deposit message and writes Launchpad-compatible JSON
5. Verifies the keystore by decrypting and comparing pubkeys

Output files in `./validator_keys/`:
- `keystore-m_12381_3600_0_0_0-<timestamp>.json` -- encrypted signing key
- `deposit_data-<timestamp>.json` -- upload this to the Ethereum Launchpad

**Write down the mnemonic immediately.** It is displayed once and is the only way to recover your keys.

### Multiple validators

```bash
rvc-keygen new-mnemonic \
  --network mainnet \
  --num-validators 3 \
  --withdrawal-address 0xYOUR_EXECUTION_ADDRESS \
  --output-dir ./my_validators
```

This derives keys at indices 0, 1, and 2. The deposit data file contains all three entries.

### Adding validators later

If you already have 3 validators and want to add 2 more from the same mnemonic:

```bash
rvc-keygen existing-mnemonic \
  --network mainnet \
  --num-validators 2 \
  --start-index 3 \
  --withdrawal-address 0xYOUR_EXECUTION_ADDRESS
```

You will be prompted for your mnemonic (no echo). Keys are derived at indices 3 and 4.

### Testnet (Hoodi)

```bash
rvc-keygen new-mnemonic \
  --network hoodi \
  --withdrawal-address 0xYOUR_HOODI_ADDRESS
```

### Dry run

Preview what would be generated without writing any files:

```bash
rvc-keygen new-mnemonic \
  --network mainnet \
  --num-validators 2 \
  --withdrawal-address 0xYOUR_EXECUTION_ADDRESS \
  --dry-run
```

The deposit data JSON is printed to stdout. No files are written and no output directory is created.

### Non-interactive password

For scripted/automated workflows, read the keystore password from a file:

```bash
echo -n "my-strong-password-here" > /tmp/pw.txt
rvc-keygen new-mnemonic \
  --network mainnet \
  --withdrawal-address 0xYOUR_EXECUTION_ADDRESS \
  --password-file /tmp/pw.txt
rm /tmp/pw.txt
```

### PBKDF2 encryption

Use PBKDF2 instead of Scrypt for faster keystore encryption/decryption (lower memory usage, still secure):

```bash
rvc-keygen new-mnemonic \
  --network mainnet \
  --withdrawal-address 0xYOUR_EXECUTION_ADDRESS \
  --pbkdf2
```

### BLS withdrawal credentials

If you omit `--withdrawal-address`, withdrawal credentials use the BLS scheme (`0x00` prefix) derived from the withdrawal key at `m/12381/3600/{index}/0`. You can convert these to execution addresses later using the `bls-to-execution` subcommand.

```bash
rvc-keygen new-mnemonic --network mainnet
```

## 2. Regenerate Keys from Existing Mnemonic

Recreate keystores and deposit data from a mnemonic you already have:

```bash
rvc-keygen existing-mnemonic \
  --network mainnet \
  --num-validators 1 \
  --withdrawal-address 0xYOUR_EXECUTION_ADDRESS
```

You will be prompted for your mnemonic phrase (hidden input). The same mnemonic, passphrase, network, and index always produce the same keys.

### With a mnemonic passphrase

If you used a passphrase during original generation:

```bash
rvc-keygen existing-mnemonic \
  --network mainnet \
  --mnemonic-passphrase "my secret passphrase" \
  --withdrawal-address 0xYOUR_EXECUTION_ADDRESS
```

A different passphrase produces entirely different keys.

## 3. BLS-to-Execution-Change

Convert BLS withdrawal credentials (`0x00`) to an execution address (`0x01`) so validator rewards and the principal are sent to your Ethereum address.

```bash
rvc-keygen bls-to-execution \
  --network mainnet \
  --validator-index 42 \
  --execution-address 0xYOUR_EXECUTION_ADDRESS
```

You will be prompted for your mnemonic. The tool:

1. Derives the withdrawal key at `m/12381/3600/0/0` (4-level path)
2. Builds a `BLSToExecutionChange` message
3. Signs it with `DOMAIN_BLS_TO_EXECUTION_CHANGE` using the network's genesis fork version
4. Writes a JSON array of one signed message to `./bls_to_execution_changes/`

If your validator's withdrawal key was derived at a non-zero index:

```bash
rvc-keygen bls-to-execution \
  --network mainnet \
  --validator-index 42 \
  --bls-withdrawal-index 5 \
  --execution-address 0xYOUR_EXECUTION_ADDRESS
```

Submit the output JSON to your beacon node:

```bash
curl -X POST http://localhost:5052/eth/v1/beacon/pool/bls_to_execution_changes \
  -H "Content-Type: application/json" \
  -d @bls_to_execution_changes/bls_to_execution-*.json
```

This operation is **irreversible** -- once set, the execution address cannot be changed.

## 4. Voluntary Exit

Generate a signed voluntary exit message to withdraw a validator from the beacon chain.

```bash
rvc-keygen exit \
  --network mainnet \
  --validator-index 42 \
  --epoch 300000 \
  --keystore ./validator_keys/keystore-m_12381_3600_0_0_0-1708800000.json
```

You will be prompted for the keystore password. The tool:

1. Loads and decrypts the keystore
2. Signs a `VoluntaryExit` message (EIP-7044: Capella fork version cap)
3. Writes the signed exit to `./signed_exits/`

Submit to your beacon node:

```bash
curl -X POST http://localhost:5052/eth/v1/beacon/pool/voluntary_exits \
  -H "Content-Type: application/json" \
  -d @signed_exits/signed_voluntary_exit-*.json
```

Exiting is **irreversible**. Your validator will stop earning rewards after the exit epoch and the principal will be withdrawn to the execution address.

## 5. Import Keys into rvc

After generating keystores, import them into the validator client:

```bash
rvc start \
  -c config.toml \
  --validators-dir ./validator_keys
```

Or use the keymanager API to import at runtime (if `--keymanager-enabled`):

```bash
# Read keystore JSON and password
KEYSTORE=$(cat validator_keys/keystore-*.json)
PASSWORD="your-keystore-password"

curl -X POST http://localhost:7500/eth/v1/keystores \
  -H "Authorization: Bearer $(cat /path/to/api-token.txt)" \
  -H "Content-Type: application/json" \
  -d "{\"keystores\":[\"$KEYSTORE\"],\"passwords\":[\"$PASSWORD\"]}"
```

## CLI Reference

| Subcommand | Required flags | Optional flags |
|---|---|---|
| `new-mnemonic` | (none) | `--network`, `--output-dir`, `--num-validators`, `--start-index`, `--withdrawal-address`, `--mnemonic-passphrase`, `--pbkdf2`, `--password-file`, `--dry-run` |
| `existing-mnemonic` | (none) | same as `new-mnemonic` |
| `bls-to-execution` | `--validator-index`, `--execution-address` | `--network`, `--output-dir`, `--bls-withdrawal-index` |
| `exit` | `--validator-index`, `--epoch`, `--keystore` | `--network`, `--output-dir`, `--password-file` |

## Security Notes

- All keystore files are written with `0600` permissions (owner read/write only)
- Mnemonic input uses `rpassword` (no terminal echo)
- Secret keys and seeds are wrapped in `Zeroizing<>` and cleared from memory on drop
- Keystore password must be at least 8 characters
- Scrypt (default) uses n=262144, r=8, p=1 for strong brute-force resistance
- The mnemonic is displayed **once** -- store it offline in a secure location

## Supported Networks

| Network | Genesis fork version | Capella fork version |
|---|---|---|
| `mainnet` | `0x00000000` | `0x03000000` |
| `hoodi` | `0x10000910` | `0x40000910` |
