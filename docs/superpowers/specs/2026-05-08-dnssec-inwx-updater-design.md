# Design: dnssec-inwx-updater

**Date:** 2026-05-08  
**Status:** Approved

## Problem

Caddy periodically renews Let's Encrypt certificates. When a certificate's public key changes, the TLSA (DANE) DNS record at INWX must be updated to match. This needs to happen automatically, run as a cron job, without manual intervention.

## Approach

A modular Python package (`dnssec-inwx-updater`) that:
1. Detects when the certificate managed by Caddy has changed (via SHA-256 hash comparison)
2. Generates a DANE-EE TLSA hash (type `3 1 1`) from the certificate's public key
3. Updates (or creates) the TLSA record at INWX via their JSON-RPC API

Published to PyPI for easy installation. Designed for cron execution (silent on no-op, logs to stdout/stderr, exits non-zero on failure).

---

## Architecture

### Package Structure

```
dnssec-inwx-updater/
├── .github/
│   └── workflows/
│       ├── ci.yml            # Lint + test on PRs
│       └── publish.yml       # Publish to PyPI on git tag v*
├── dnssec_inwx_updater/
│   ├── __init__.py
│   ├── main.py               # Orchestrator / CLI entry point
│   ├── config.py             # TOML config loading and validation
│   ├── cert.py               # Cert path resolution + SHA-256 hash
│   ├── tlsa.py               # TLSA hash generation via openssl subprocess
│   ├── inwx.py               # INWX API wrapper (list, create, update record)
│   └── state.py              # Read/write state.json (last hash + timestamp)
├── tests/
│   ├── test_cert.py
│   ├── test_tlsa.py
│   ├── test_inwx.py
│   └── test_state.py
├── config.example.toml
├── pyproject.toml
└── README.md
```

### Entry Points

- CLI command: `dnssec-inwx-updater --config /path/to/config.toml`
- Module: `python -m dnssec_inwx_updater --config /path/to/config.toml`

### Dependencies

- `inwx-domrobot` — official INWX Python client (JSON-RPC)
- `tomli` — TOML parsing for Python < 3.11 (built-in `tomllib` for 3.11+)

---

## Configuration

File: `config.toml` (path passed via `--config` flag, defaults to `./config.toml`)

```toml
[inwx]
username = "your-inwx-username"
password = "your-inwx-password"
# test_mode = false  # Set true to use INWX OT&E sandbox

[cert]
cert_directory = "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory"
domain = "mail.example.com"
# Cert resolved as: {cert_directory}/{domain}/{domain}.crt

[dns]
zone = "example.com"          # INWX zone (domain) containing the record
record_name = "_25._tcp.mail" # Record name (zone appended by INWX API)
ttl = 3600
```

---

## State File

Stored as `state.json` alongside the config file. Auto-created on first run.

```json
{
  "last_cert_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "last_updated": "2026-05-08T09:00:00"
}
```

State is only written after a successful INWX API update. If the API call fails, the hash is not saved, so the next cron run will retry.

---

## Run Flow

```
main()
  ├── load_config(config_path)
  ├── load_state(state_path)
  ├── current_hash = hash_cert(config.cert.cert_directory, config.cert.domain)
  ├── if current_hash == state.last_cert_hash → log "no change" → exit 0
  └── [changed]
        ├── tlsa_hash = generate_tlsa_hash(cert_path)
        ├── record = inwx.find_tlsa_record(zone, record_name)
        ├── if record exists → inwx.update_record(record.id, "3 1 1 {tlsa_hash}")
        │   else             → inwx.create_record(zone, record_name, "3 1 1 {tlsa_hash}", ttl)
        └── save_state(new_hash, now)
```

---

## Module Responsibilities

### `config.py`
- Loads and validates `config.toml`
- Raises descriptive errors for missing required fields
- Returns a typed config dataclass

### `cert.py`
- Resolves cert path: `{cert_directory}/{domain}/{domain}.crt`
- Computes SHA-256 hash of the `.crt` file
- Raises `FileNotFoundError` if cert does not exist

### `tlsa.py`
- Runs two-stage openssl subprocess pipeline:
  1. `openssl x509 -in {cert} -noout -pubkey` → PEM public key
  2. `openssl pkey -pubin -outform DER` → DER bytes (via stdin)
- Computes `hashlib.sha256(der).hexdigest()` in Python (no third openssl call)
- Raises `subprocess.CalledProcessError` on openssl failure

### `inwx.py`
- Wraps INWX JSON-RPC client
- `find_tlsa_record(zone, record_name)` → returns record dict or `None`
- `create_record(zone, name, content, ttl)` → creates TLSA record
- `update_record(record_id, content)` → updates existing TLSA record content
- Raises on API error codes

### `state.py`
- `load_state(path)` → returns dict (empty dict if file absent)
- `save_state(path, hash, timestamp)` → writes JSON atomically

### `main.py`
- Parses `--config` CLI argument
- Orchestrates all modules per run flow above
- Logs to stdout (info), stderr (errors)
- Exits 0 on success or no-op, non-zero on any error

---

## TLSA Record Format

DANE-EE with SPKI and SHA-256 (`3 1 1`):

| Field | Value | Meaning |
|---|---|---|
| Usage | `3` | DANE-EE (end entity certificate) |
| Selector | `1` | SPKI (subject public key info) |
| Matching | `1` | SHA-256 hash |
| Data | `<hex>` | SHA-256 of DER-encoded public key |

DNS record: `_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 <hash>`  
INWX content field: `3 1 1 <hash>`

---

## Error Handling

| Failure | Behaviour |
|---|---|
| Cert file not found | Log error, exit non-zero |
| openssl not available/fails | Log error, exit non-zero |
| INWX API unreachable/error | Log error, exit non-zero (state not saved → retried next cron run) |
| Config missing/invalid | Log descriptive error, exit non-zero |

---

## CI/CD & PyPI Publishing

### `ci.yml`
- Trigger: push / PR to `main`
- Steps: install deps, run `ruff` (lint), run `pytest`

### `publish.yml`
- Trigger: push of tag matching `v*` (e.g., `v1.0.0`)
- Uses PyPI trusted publishing (OIDC) — no API secrets required
- Steps: build with `python -m build`, publish with `twine` / `pypa/gh-action-pypi-publish`

---

## Testing Strategy

- `test_cert.py` — hash computation with a fixture cert file
- `test_tlsa.py` — TLSA hash generation (mock subprocess or use real openssl)
- `test_inwx.py` — API wrapper with mocked INWX client responses
- `test_state.py` — state load/save round-trip
