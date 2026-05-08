# dnssec-inwx-updater

Automatically update [INWX](https://www.inwx.de) DANE TLSA DNS records when [Caddy](https://caddyserver.com) renews a Let's Encrypt certificate.

When Caddy renews a certificate and its public key changes, this tool detects the change and updates the `_25._tcp.<domain>` TLSA record in your INWX DNS zone — keeping DANE validation working for SMTP without manual intervention.

## Installation

```bash
pip install dnssec-inwx-updater
```

## Configuration

Copy the example config and fill in your details:

```bash
cp config.example.toml /etc/dnssec-inwx-updater/config.toml
```

Edit `/etc/dnssec-inwx-updater/config.toml`:

```toml
[inwx]
username = "your-inwx-username"
password = "your-inwx-password"

[cert]
cert_directory = "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory"
domain = "mail.example.com"

[dns]
zone = "example.com"
record_name = "_25._tcp.mail"
ttl = 3600
```

## Usage

Run manually:

```bash
dnssec-inwx-updater --config /etc/dnssec-inwx-updater/config.toml
```

Run as a cron job (every 5 minutes):

```cron
*/5 * * * * /usr/local/bin/dnssec-inwx-updater --config /etc/dnssec-inwx-updater/config.toml >> /var/log/dnssec-inwx-updater.log 2>&1
```

The tool is silent on no-op (certificate unchanged). On a change it logs what it did. On error it logs to stderr and exits non-zero — cron will capture this.

## How It Works

1. Computes a SHA-256 hash of the `.crt` file managed by Caddy
2. Compares it to the last known hash stored in `state.json` (alongside `config.toml`)
3. If changed: generates the TLSA hash (`3 1 1` — DANE-EE, SPKI, SHA-256) via openssl
4. Finds the existing TLSA record in INWX and updates it, or creates a new one if absent
5. Saves the new hash to `state.json`

## TLSA Record Format

```
_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 <sha256-of-spki>
```

## Requirements

- Python 3.11+
- `openssl` available in `PATH`
- An INWX account with API access
