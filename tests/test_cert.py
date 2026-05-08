import hashlib
from pathlib import Path
import pytest
from dnssec_inwx_updater.cert import resolve_cert_path, hash_cert
from tests.conftest import CERT_DOMAIN


def test_resolve_cert_path():
    path = resolve_cert_path("/certs", "mail.example.com")
    assert path == Path("/certs/mail.example.com/mail.example.com.crt")


def test_hash_cert_returns_sha256(sample_cert):
    result = hash_cert(str(sample_cert.parent.parent), CERT_DOMAIN)
    # Verify it is a valid 64-char hex SHA-256
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_hash_cert_is_deterministic(sample_cert):
    h1 = hash_cert(str(sample_cert.parent.parent), CERT_DOMAIN)
    h2 = hash_cert(str(sample_cert.parent.parent), CERT_DOMAIN)
    assert h1 == h2


def test_hash_cert_raises_when_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="Certificate not found"):
        hash_cert(str(tmp_path), "nonexistent.example.com")
