# dnssec-inwx-updater

Automatically update [INWX](https://www.inwx.de) DANE TLSA DNS records when [Caddy](https://caddyserver.com) renews a Let's Encrypt certificate.

When Caddy renews a certificate and its public key changes, this tool detects the change and updates the `_25._tcp.<domain>` TLSA record in your INWX DNS zone — keeping DANE validation working for SMTP without manual intervention.

## Installation

**From PyPI:**
```bash
pip install dnssec-inwx-updater
```

**From a wheel (without PyPI access):**
```bash
pip install dnssec_inwx_updater-*.whl
```

**From source:**
```bash
git clone <repo>
cd dnssec-inwx-updater
make dev        # creates .venv and installs dev dependencies
make build      # builds wheel into dist/
```

## Configuration

Generate a template config file:

```bash
dnssec-inwx-updater --create-config --config /etc/dnssec-inwx-updater/config.toml
```

This writes a commented template to the given path (parent directories are created automatically) and exits. If the file already exists the command aborts with an error.

Then edit the file and fill in your details:

```toml
[inwx]
username = "your-inwx-username"
password = "your-inwx-password"
# shared_secret = ""  # TOTP shared secret — only needed if 2FA is enabled on your account
# language = "de"     # API response language: "de" for inwx.de, "en" for inwx.com (default: de)
# test_mode = false   # Uncomment to use the INWX OT&E sandbox for testing

[cert]
# Directory where Caddy stores certificates
cert_directory = "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory"
# The domain whose certificate to watch — resolves to {cert_directory}/{domain}/{domain}.crt
domain = "mail.example.com"

[dns]
# The INWX zone (registered domain) that contains the record
zone = "example.com"
# The record name — INWX appends the zone automatically
record_name = "_25._tcp.mail"
# TTL in seconds
ttl = 3600
```

### Config fields

| Section | Key | Required | Default | Description |
|---------|-----|----------|---------|-------------|
| `[inwx]` | `username` | ✓ | — | INWX login name (shown top-right in the control panel) |
| `[inwx]` | `password` | ✓ | — | INWX account password |
| `[inwx]` | `shared_secret` | | `""` | TOTP base32 seed from QR code — only if 2FA is enabled |
| `[inwx]` | `language` | | `"de"` | API response language: `"de"` (inwx.de) or `"en"` (inwx.com) |
| `[inwx]` | `test_mode` | | `false` | Use the INWX OT&E sandbox instead of production |
| `[cert]` | `cert_directory` | ✓ | — | Root directory where Caddy stores certificates |
| `[cert]` | `domain` | ✓ | — | Domain to watch — cert resolved as `{cert_directory}/{domain}/{domain}.crt` |
| `[dns]` | `zone` | ✓ | — | INWX DNS zone (registered domain, e.g. `example.com`) |
| `[dns]` | `record_name` | ✓ | — | Record name within the zone (e.g. `_25._tcp.mail`) |
| `[dns]` | `ttl` | ✓ | — | TTL in seconds (e.g. `3600`) |

> **Note:** The INWX username is your **login handle**, not your customer number. It is displayed in the top-right corner of the INWX control panel after logging in.

## Usage

Run manually:

```bash
dnssec-inwx-updater --config /etc/dnssec-inwx-updater/config.toml
```

Run as a cron job (every 5 minutes):

```cron
*/5 * * * * /usr/local/bin/dnssec-inwx-updater --config /etc/dnssec-inwx-updater/config.toml >> /var/log/dnssec-inwx-updater.log 2>&1
```

The tool is silent when the certificate is unchanged. On a change it logs what it did. On error it logs to stderr and exits non-zero — cron will capture this.

## How It Works

1. Computes a SHA-256 hash of the `.crt` file managed by Caddy
2. Compares it to the last known hash stored in `state.json` (alongside `config.toml`)
3. If unchanged: exits silently
4. If changed: generates the TLSA hash (`3 1 1` — DANE-EE, SPKI, SHA-256) via openssl pipeline
5. Queries INWX for an existing TLSA record and updates it, or creates a new one if absent
6. Saves the new hash to `state.json` — only on success, so failures retry on the next run

## TLSA Record Format

```
_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 <sha256-of-spki>
```

Parameters: `3` = DANE-EE (end-entity), `1` = SPKI selector, `1` = SHA-256 hash.

## Requirements

- Python 3.11+
- `openssl` available in `PATH`
- An INWX account with DNS API access
