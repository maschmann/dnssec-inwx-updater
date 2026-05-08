from __future__ import annotations

import hashlib
import subprocess


def generate_tlsa_hash(cert_path: str) -> str:
    """Generate a DANE-EE SPKI SHA-256 hash (TLSA 3 1 1) from a PEM certificate.

    Requires ``openssl`` to be available in PATH.

    Raises:
        subprocess.CalledProcessError: If openssl fails (e.g. invalid/missing cert).
        FileNotFoundError: If openssl is not installed.
    """
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
