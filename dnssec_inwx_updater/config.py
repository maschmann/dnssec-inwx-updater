from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class InwxConfig:
    username: str
    password: str
    test_mode: bool = False
    shared_secret: str | None = None
    language: str = "de"


@dataclass
class CertConfig:
    cert_directory: str
    domain: str


@dataclass
class DnsConfig:
    zone: str
    record_name: str
    ttl: int


@dataclass
class AppConfig:
    inwx: InwxConfig
    cert: CertConfig
    dns: DnsConfig


def load_config(path: Path | str) -> AppConfig:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "rb") as f:
        data = tomllib.load(f)

    inwx_data = data.get("inwx", {})
    _require(inwx_data, "username", "[inwx]")
    _require(inwx_data, "password", "[inwx]")

    cert_data = data.get("cert", {})
    _require(cert_data, "cert_directory", "[cert]")
    _require(cert_data, "domain", "[cert]")

    dns_data = data.get("dns", {})
    _require(dns_data, "zone", "[dns]")
    _require(dns_data, "record_name", "[dns]")
    _require(dns_data, "ttl", "[dns]")

    return AppConfig(
        inwx=InwxConfig(
            username=inwx_data["username"],
            password=inwx_data["password"],
            test_mode=inwx_data.get("test_mode", False),
            shared_secret=inwx_data.get("shared_secret") or None,
            language=inwx_data.get("language", "de"),
        ),
        cert=CertConfig(
            cert_directory=cert_data["cert_directory"],
            domain=cert_data["domain"],
        ),
        dns=DnsConfig(
            zone=dns_data["zone"],
            record_name=dns_data["record_name"],
            ttl=dns_data["ttl"],
        ),
    )


def _require(data: dict, key: str, section: str) -> None:
    if key not in data:
        raise ValueError(f"Missing required config field '{key}' in {section}")
