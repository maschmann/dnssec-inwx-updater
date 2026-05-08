from __future__ import annotations

import hashlib
from pathlib import Path


def resolve_cert_path(cert_directory: str, domain: str) -> Path:
    return Path(cert_directory) / domain / f"{domain}.crt"


def hash_cert(cert_directory: str, domain: str) -> str:
    path = resolve_cert_path(cert_directory, domain)
    if not path.exists():
        raise FileNotFoundError(f"Certificate not found: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest
