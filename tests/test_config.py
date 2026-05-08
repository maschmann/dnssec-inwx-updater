from pathlib import Path

import pytest

from dnssec_inwx_updater.config import load_config


def write_toml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(content)
    return p


def test_load_valid_config(tmp_path):
    p = write_toml(tmp_path, """
[inwx]
username = "user1"
password = "secret"

[cert]
cert_directory = "/var/lib/caddy/certs"
domain = "mail.example.com"

[dns]
zone = "example.com"
record_name = "_25._tcp.mail"
ttl = 3600
""")
    cfg = load_config(p)
    assert cfg.inwx.username == "user1"
    assert cfg.inwx.password == "secret"
    assert cfg.inwx.test_mode is False
    assert cfg.cert.cert_directory == "/var/lib/caddy/certs"
    assert cfg.cert.domain == "mail.example.com"
    assert cfg.dns.zone == "example.com"
    assert cfg.dns.record_name == "_25._tcp.mail"
    assert cfg.dns.ttl == 3600


def test_load_config_with_test_mode(tmp_path):
    p = write_toml(tmp_path, """
[inwx]
username = "u"
password = "p"
test_mode = true

[cert]
cert_directory = "/certs"
domain = "mail.example.com"

[dns]
zone = "example.com"
record_name = "_25._tcp.mail"
ttl = 300
""")
    cfg = load_config(p)
    assert cfg.inwx.test_mode is True


def test_missing_config_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nonexistent.toml")


def test_missing_required_field_raises(tmp_path):
    p = write_toml(tmp_path, """
[inwx]
password = "secret"

[cert]
cert_directory = "/certs"
domain = "mail.example.com"

[dns]
zone = "example.com"
record_name = "_25._tcp.mail"
ttl = 3600
""")
    with pytest.raises(ValueError, match="username"):
        load_config(p)
