import hashlib
import subprocess

import pytest

from dnssec_inwx_updater.tlsa import generate_tlsa_hash


def test_generate_tlsa_hash_returns_hex(sample_cert):
    result = generate_tlsa_hash(str(sample_cert))
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_generate_tlsa_hash_matches_manual_pipeline(sample_cert):
    """Verify output matches manual openssl pipeline."""
    pubkey = subprocess.run(
        ["openssl", "x509", "-in", str(sample_cert), "-noout", "-pubkey"],
        capture_output=True, check=True,
    ).stdout
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pubkey, capture_output=True, check=True,
    ).stdout
    expected = hashlib.sha256(der).hexdigest()
    assert generate_tlsa_hash(str(sample_cert)) == expected


def test_generate_tlsa_hash_raises_on_missing_file():
    with pytest.raises(subprocess.CalledProcessError):
        generate_tlsa_hash("/nonexistent/cert.crt")
