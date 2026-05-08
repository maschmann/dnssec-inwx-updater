from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from dnssec_inwx_updater.cert import hash_cert, resolve_cert_path
from dnssec_inwx_updater.config import load_config
from dnssec_inwx_updater.inwx import InwxClient
from dnssec_inwx_updater.state import load_state, save_state
from dnssec_inwx_updater.tlsa import generate_tlsa_hash

log = logging.getLogger(__name__)

CONFIG_TEMPLATE = """\
[inwx]
username = "your-inwx-username"
password = "your-inwx-password"
# shared_secret = ""  # TOTP shared secret (base32 string from QR code) — only needed if 2FA is enabled
# test_mode = false  # Uncomment to use the INWX OT&E sandbox for testing

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
"""


def create_config(config_path: Path) -> None:
    if config_path.exists():
        log.error("Config file already exists: %s", config_path)
        sys.exit(1)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(CONFIG_TEMPLATE)
    print(f"Config template written to {config_path}")
    print("Edit the file and fill in your INWX credentials and domain details.")


def run(config_path: Path, state_path: Path) -> None:
    cfg = load_config(config_path)
    state = load_state(state_path)

    current_hash = hash_cert(cfg.cert.cert_directory, cfg.cert.domain)

    if current_hash == state.get("last_cert_hash"):
        log.info("Certificate unchanged — nothing to do.")
        return

    log.info("Certificate change detected, updating TLSA record.")

    cert_path = str(resolve_cert_path(cfg.cert.cert_directory, cfg.cert.domain))
    tlsa_hash = generate_tlsa_hash(cert_path)
    content = f"3 1 1 {tlsa_hash}"

    client = InwxClient(
        username=cfg.inwx.username,
        password=cfg.inwx.password,
        test_mode=cfg.inwx.test_mode,
        shared_secret=cfg.inwx.shared_secret,
    )
    try:
        record = client.find_tlsa_record(cfg.dns.zone, cfg.dns.record_name)
        if record:
            log.info("Updating existing TLSA record (id=%s).", record["id"])
            client.update_record(record["id"], content)
        else:
            log.info("No existing TLSA record found — creating new one.")
            client.create_record(cfg.dns.zone, cfg.dns.record_name, content, cfg.dns.ttl)
    finally:
        try:
            client.logout()
        except Exception as exc:
            log.warning("INWX logout failed (non-critical): %s", exc)

    save_state(state_path, current_hash, datetime.now(tz=UTC))
    log.info("TLSA record updated successfully. New hash: %s", tlsa_hash)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Update INWX DANE TLSA records when Caddy certificates change."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.toml"),
        help="Path to config.toml (default: ./config.toml)",
    )
    parser.add_argument(
        "--create-config",
        action="store_true",
        help="Write a template config.toml to the path given by --config and exit.",
    )
    args = parser.parse_args()

    config_path = args.config
    state_path = config_path.parent / "state.json"

    if args.create_config:
        create_config(config_path)
        return

    try:
        run(config_path, state_path)
    except Exception as exc:
        log.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
