# Keymanager API Reference

> rvc Validator Client — [Ethereum Keymanager API](https://github.com/ethereum/keymanager-APIs) implementation

## Overview

rvc exposes a Keymanager API server for managing validator keys and per-validator configuration at runtime. The API conforms to the [Ethereum Keymanager API specification](https://github.com/ethereum/keymanager-APIs).

**Base URL:** `http://127.0.0.1:5062` (configurable via `--keymanager-address`)

## Configuration

| CLI Flag | Default | Description |
|----------|---------|-------------|
| `--keymanager-enabled` | `false` | Enable the Keymanager API server |
| `--keymanager-address` | `127.0.0.1:5062` | Bind address |
| `--keymanager-token-file` | `./keymanager-api-token.txt` | Path to bearer token file |
| `--keymanager-cors-origins` | — | Comma-separated CORS origins |
| `--keymanager-body-limit` | `10485760` (10 MB) | Max request body size |
| `--allow-insecure-remote-signer` | `false` | Allow HTTP (non-TLS) URLs for Web3Signer |

## Authentication

All endpoints require Bearer token authentication.

```
Authorization: Bearer <token>
```

The token is a 64-character hex string (32 random bytes). On first start, rvc generates the token and writes it to the token file with `0400` permissions (owner-read only). Token comparison uses constant-time equality to prevent timing attacks.

**Responses without valid auth:** `401 Unauthorized` (no body).

## Error Responses

All errors return JSON with a `message` field:

```json
{ "message": "description of the error" }
```

| Status | Meaning |
|--------|---------|
| `400` | Bad request — malformed input, invalid pubkey, invalid address |
| `401` | Unauthorized — missing or invalid bearer token |
| `404` | Not found — unknown validator pubkey |
| `500` | Internal server error — beacon node unavailable, signing failure |

## Data Formats

| Type | Format | Example |
|------|--------|---------|
| Pubkey | `0x`-prefixed, lowercase hex, 48 bytes (96 chars) | `0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a` |
| Ethereum address | `0x`-prefixed hex, 20 bytes (40 chars) | `0xAbcF8e0d4e9587369b2301D0790347320302cc09` |
| Uint64 | String-encoded decimal | `"30000000"` |
| Signature | `0x`-prefixed hex, 96 bytes (192 chars) | `0xaa...` |

---

## Endpoints

### Local Keystores

#### `GET /eth/v1/keystores`

List all locally-managed validator keys.

**Response:** `200 OK`

```json
{
  "data": [
    {
      "validating_pubkey": "0x93247f...",
      "derivation_path": "m/12381/3600/0/0/0",
      "readonly": false
    }
  ]
}
```

---

#### `POST /eth/v1/keystores`

Import one or more keystores. Slashing protection data is imported first, before any keys are activated.

**Request:**

```json
{
  "keystores": ["{\"crypto\":{...},\"pubkey\":\"0x...\"}"],
  "passwords": ["password1"],
  "slashing_protection": "{\"metadata\":{...},\"data\":[...]}"
}
```

- `keystores` and `passwords` arrays must have the same length
- `slashing_protection` is optional (EIP-3076 interchange format)

**Response:** `200 OK`

```json
{
  "data": [
    { "status": "imported" },
    { "status": "duplicate", "message": "key already exists" },
    { "status": "error", "message": "decryption failed" }
  ]
}
```

| Status | Meaning |
|--------|---------|
| `imported` | Key successfully imported and activated |
| `duplicate` | Key already exists |
| `error` | Import failed |

---

#### `DELETE /eth/v1/keystores`

Delete one or more local keystores. Slashing protection is exported before deletion.

**Request:**

```json
{
  "pubkeys": ["0x93247f..."]
}
```

**Response:** `200 OK`

```json
{
  "data": [
    { "status": "deleted" },
    { "status": "not_found" },
    { "status": "error", "message": "..." }
  ],
  "slashing_protection": "{\"metadata\":{...},\"data\":[...]}"
}
```

| Status | Meaning |
|--------|---------|
| `deleted` | Key deleted and deactivated |
| `not_active` | Key exists but is not active |
| `not_found` | Key not found |
| `error` | Deletion failed |

---

### Remote Keys (Web3Signer)

#### `GET /eth/v1/remotekeys`

List all remote validator keys (Web3Signer).

**Response:** `200 OK`

```json
{
  "data": [
    {
      "pubkey": "0x93247f...",
      "url": "https://web3signer.example.com",
      "readonly": false
    }
  ]
}
```

---

#### `POST /eth/v1/remotekeys`

Import remote keys with their Web3Signer URLs.

**Request:**

```json
{
  "remote_keys": [
    {
      "pubkey": "0x93247f...",
      "url": "https://web3signer.example.com"
    }
  ]
}
```

- URLs must be HTTPS unless `--allow-insecure-remote-signer` is set

**Response:** `200 OK`

```json
{
  "data": [
    { "status": "imported" },
    { "status": "duplicate", "message": "key already exists" }
  ]
}
```

---

#### `DELETE /eth/v1/remotekeys`

Delete one or more remote keys.

**Request:**

```json
{
  "pubkeys": ["0x93247f..."]
}
```

**Response:** `200 OK`

```json
{
  "data": [
    { "status": "deleted" },
    { "status": "not_found" }
  ]
}
```

---

### Fee Recipient

#### `GET /eth/v1/validator/{pubkey}/feerecipient`

Get the fee recipient for a validator. Returns the per-validator override if set, otherwise the global default.

**Response:** `200 OK`

```json
{
  "data": {
    "pubkey": "0x93247f...",
    "ethaddress": "0xAbcF8e0d4e9587369b2301D0790347320302cc09"
  }
}
```

**Errors:** `400` (invalid pubkey), `404` (unknown validator)

---

#### `POST /eth/v1/validator/{pubkey}/feerecipient`

Set a per-validator fee recipient override. The change is persisted to the TOML config file.

**Request:**

```json
{
  "ethaddress": "0xAbcF8e0d4e9587369b2301D0790347320302cc09"
}
```

**Response:** `202 Accepted` (no body)

**Validation:**
- Address must be valid 20-byte hex
- Zero address (`0x0000000000000000000000000000000000000000`) is rejected with `400`

**Errors:** `400` (invalid/zero address), `404` (unknown validator)

---

#### `DELETE /eth/v1/validator/{pubkey}/feerecipient`

Remove the per-validator fee recipient override, reverting to the global default. The change is persisted.

**Response:** `204 No Content`

**Errors:** `404` (unknown validator)

---

### Gas Limit

#### `GET /eth/v1/validator/{pubkey}/gas_limit`

Get the gas limit for a validator. Default is `30000000`.

**Response:** `200 OK`

```json
{
  "data": {
    "pubkey": "0x93247f...",
    "gas_limit": "30000000"
  }
}
```

> `gas_limit` is a **string**, not a JSON number, per the Keymanager API spec (Uint64 type).

**Errors:** `400` (invalid pubkey), `404` (unknown validator)

---

#### `POST /eth/v1/validator/{pubkey}/gas_limit`

Set a per-validator gas limit override. The change is persisted.

**Request:**

```json
{
  "gas_limit": "35000000"
}
```

**Response:** `202 Accepted` (no body)

**Validation:**
- `gas_limit` must be a string-encoded decimal integer `<= i64::MAX` (TOML cannot store a larger value)

**Errors:** `400` (non-numeric value, or above `i64::MAX`), `404` (unknown validator)

---

#### `DELETE /eth/v1/validator/{pubkey}/gas_limit`

Remove the per-validator gas limit override, reverting to the default (`30000000`). The change is persisted.

**Response:** `204 No Content`

**Errors:** `404` (unknown validator)

---

### Graffiti

#### `GET /eth/v1/validator/{pubkey}/graffiti`

Get the graffiti for a validator. Returns empty string if no graffiti is configured.

**Response:** `200 OK`

```json
{
  "data": {
    "pubkey": "0x93247f...",
    "graffiti": "my-validator"
  }
}
```

**Errors:** `400` (invalid pubkey), `404` (unknown validator)

---

#### `POST /eth/v1/validator/{pubkey}/graffiti`

Set a per-validator graffiti override. The change is persisted.

**Request:**

```json
{
  "graffiti": "my-validator"
}
```

**Response:** `202 Accepted` (no body)

**Validation:**
- Graffiti must be 32 bytes or less (consensus layer limit)

**Errors:** `400` (exceeds 32 bytes), `404` (unknown validator)

---

#### `DELETE /eth/v1/validator/{pubkey}/graffiti`

Remove the per-validator graffiti override, reverting to the default. The change is persisted.

**Response:** `204 No Content`

**Errors:** `404` (unknown validator)

---

### Voluntary Exit

#### `POST /eth/v1/validator/{pubkey}/voluntary_exit`

Sign a voluntary exit message for a validator. Returns the signed exit without submitting it to the beacon node.

> **This operation is irreversible.** Once a signed voluntary exit is submitted to the beacon chain, the validator enters the exit queue and cannot be reactivated. A WARN-level log is emitted for every request.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `epoch` | Uint64 (string) | No | Epoch for the exit. If omitted, the current epoch is auto-detected from the beacon node. |

**Examples:**

```
POST /eth/v1/validator/0x93247f.../voluntary_exit
POST /eth/v1/validator/0x93247f.../voluntary_exit?epoch=300000
```

**Response:** `200 OK`

```json
{
  "data": {
    "message": {
      "epoch": "300000",
      "validator_index": "12345"
    },
    "signature": "0xaa..."
  }
}
```

All numeric fields (`epoch`, `validator_index`) are string-encoded per spec. The `signature` is `0x`-prefixed hex (96 bytes).

**Errors:**
- `400` — invalid pubkey or non-numeric epoch query param
- `404` — validator not found locally or on the beacon node
- `500` — beacon node unreachable, signing failure, or voluntary exit not configured

**Note:** This endpoint requires the beacon node to be configured and reachable. If rvc was started without a beacon node connection, the endpoint returns `500` with the message `"voluntary exit not available: beacon node not configured"`.

---

## Config Persistence

All POST and DELETE operations on fee recipient, gas limit, and graffiti endpoints persist changes to the TOML config file atomically (temp file + rename). Changes survive process restarts without re-applying.

Concurrent API requests are safe — writes are serialized through a lock, and atomic file operations prevent corruption on crash.

## CORS

When `--keymanager-cors-origins` is set, the server includes CORS headers allowing the specified origins. Allowed methods: `GET`, `POST`, `DELETE`, `OPTIONS`. Allowed headers: `Content-Type`, `Authorization`. Preflight `OPTIONS` requests are handled before authentication.

## Endpoint Summary

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/eth/v1/keystores` | 200 | List local keystores |
| POST | `/eth/v1/keystores` | 200 | Import keystores |
| DELETE | `/eth/v1/keystores` | 200 | Delete keystores |
| GET | `/eth/v1/remotekeys` | 200 | List remote keys |
| POST | `/eth/v1/remotekeys` | 200 | Import remote keys |
| DELETE | `/eth/v1/remotekeys` | 200 | Delete remote keys |
| GET | `/eth/v1/validator/{pubkey}/feerecipient` | 200 | Get fee recipient |
| POST | `/eth/v1/validator/{pubkey}/feerecipient` | 202 | Set fee recipient |
| DELETE | `/eth/v1/validator/{pubkey}/feerecipient` | 204 | Reset fee recipient |
| GET | `/eth/v1/validator/{pubkey}/gas_limit` | 200 | Get gas limit |
| POST | `/eth/v1/validator/{pubkey}/gas_limit` | 202 | Set gas limit |
| DELETE | `/eth/v1/validator/{pubkey}/gas_limit` | 204 | Reset gas limit |
| GET | `/eth/v1/validator/{pubkey}/graffiti` | 200 | Get graffiti |
| POST | `/eth/v1/validator/{pubkey}/graffiti` | 202 | Set graffiti |
| DELETE | `/eth/v1/validator/{pubkey}/graffiti` | 204 | Reset graffiti |
| POST | `/eth/v1/validator/{pubkey}/voluntary_exit` | 200 | Sign voluntary exit |
