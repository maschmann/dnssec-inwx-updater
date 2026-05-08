from __future__ import annotations

import hashlib
import subprocess


def generate_tlsa_hash(cert_path: str) -> str:
    pubkey_result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-pubkey"],
        capture_output=True,
        check=True,
    )
    der_result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pubkey_result.stdout,
        capture_output=True,
        check=True,
    )
    return hashlib.sha256(der_result.stdout).hexdigest()
