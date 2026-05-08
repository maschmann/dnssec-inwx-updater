import subprocess
import pytest
from pathlib import Path

CERT_DOMAIN = "mail.example.com"


@pytest.fixture
def sample_cert(tmp_path) -> Path:
    """Generate a self-signed cert in the Caddy directory structure for testing.

    Creates: tmp_path/mail.example.com/mail.example.com.crt
    Returns the path to the .crt file.
    """
    cert_dir = tmp_path / CERT_DOMAIN
    cert_dir.mkdir()
    key = cert_dir / f"{CERT_DOMAIN}.key"
    cert = cert_dir / f"{CERT_DOMAIN}.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes",
            "-subj", f"/CN={CERT_DOMAIN}",
        ],
        check=True,
        capture_output=True,
    )
    return cert
