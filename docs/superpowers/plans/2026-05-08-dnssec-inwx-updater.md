# dnssec-inwx-updater Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a PyPI-installable Python package that detects Caddy certificate changes and updates INWX DANE TLSA DNS records automatically.

**Architecture:** Modular package with one file per concern (config, cert, tlsa, inwx, state, main). Main orchestrates the others: load config → detect cert change → generate TLSA hash → upsert INWX record → save state.

**Tech Stack:** Python 3.11+, `inwx-domrobot`, `tomllib` (stdlib), `pytest`, `ruff`, GitHub Actions + PyPI trusted publishing.

---

## File Map

| File | Purpose |
|---|---|
| `pyproject.toml` | Package metadata, deps, entry point, ruff config |
| `dnssec_inwx_updater/__init__.py` | Package marker + version |
| `dnssec_inwx_updater/config.py` | TOML loading, validation, typed dataclasses |
| `dnssec_inwx_updater/state.py` | Read/write `state.json` atomically |
| `dnssec_inwx_updater/cert.py` | Resolve cert path, compute SHA-256 of `.crt` |
| `dnssec_inwx_updater/tlsa.py` | Generate TLSA hash via openssl subprocess pipeline |
| `dnssec_inwx_updater/inwx.py` | INWX API wrapper: find/create/update TLSA record |
| `dnssec_inwx_updater/main.py` | CLI entry point, orchestrator |
| `tests/conftest.py` | Shared fixtures (tmp paths, sample cert) |
| `tests/test_config.py` | Config loading and validation tests |
| `tests/test_state.py` | State load/save round-trip tests |
| `tests/test_cert.py` | Cert hash computation tests |
| `tests/test_tlsa.py` | TLSA hash generation tests |
| `tests/test_inwx.py` | INWX API wrapper tests (mocked client) |
| `tests/test_main.py` | Integration test of the full orchestration |
| `config.example.toml` | Example config for users |
| `README.md` | Installation, config, cron usage |
| `.github/workflows/ci.yml` | Lint + test on push/PR |
| `.github/workflows/publish.yml` | PyPI publish on `v*` tag |

---

## Task 1: Project Scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `dnssec_inwx_updater/__init__.py`
- Create: `tests/__init__.py`
- Create: `.gitignore`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "dnssec-inwx-updater"
version = "0.1.0"
description = "Automatically update INWX DANE TLSA DNS records when Caddy certificates change"
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.11"
dependencies = [
    "inwx-domrobot>=3.0.0",
]

[project.scripts]
dnssec-inwx-updater = "dnssec_inwx_updater.main:main"

[project.urls]
Homepage = "https://github.com/YOUR_GITHUB_USER/dnssec-inwx-updater"
Repository = "https://github.com/YOUR_GITHUB_USER/dnssec-inwx-updater"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create `dnssec_inwx_updater/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 3: Create `tests/__init__.py`**

```python
```

- [ ] **Step 4: Create `.gitignore`**

```
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.venv/
*.egg
.pytest_cache/
.ruff_cache/
state.json
config.toml
```

- [ ] **Step 5: Install dependencies**

```bash
pip install inwx-domrobot pytest ruff hatchling
```

Expected: packages install without errors.

- [ ] **Step 6: Verify package is importable**

```bash
python -c "import dnssec_inwx_updater; print('ok')"
```

Expected: `ok`

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml dnssec_inwx_updater/__init__.py tests/__init__.py .gitignore
git commit -m "chore: project scaffold"
```

---

## Task 2: `config.py` — TOML Loading and Validation

**Files:**
- Create: `dnssec_inwx_updater/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config.py`:

```python
import tomllib
import pytest
from pathlib import Path
from dnssec_inwx_updater.config import load_config, InwxConfig, CertConfig, DnsConfig, AppConfig


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
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_config.py -v
```

Expected: `ModuleNotFoundError` or `ImportError` — `config` not yet implemented.

- [ ] **Step 3: Implement `dnssec_inwx_updater/config.py`**

```python
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class InwxConfig:
    username: str
    password: str
    test_mode: bool = False


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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_config.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add dnssec_inwx_updater/config.py tests/test_config.py
git commit -m "feat: add config loading with TOML and validation"
```

---

## Task 3: `state.py` — State File Read/Write

**Files:**
- Create: `dnssec_inwx_updater/state.py`
- Create: `tests/test_state.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_state.py`:

```python
import json
from datetime import datetime, timezone
from pathlib import Path
from dnssec_inwx_updater.state import load_state, save_state


def test_load_state_returns_empty_when_missing(tmp_path):
    result = load_state(tmp_path / "state.json")
    assert result == {}


def test_load_state_returns_existing_data(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"last_cert_hash": "abc123", "last_updated": "2026-01-01T00:00:00"}))
    result = load_state(p)
    assert result["last_cert_hash"] == "abc123"


def test_save_state_writes_hash_and_timestamp(tmp_path):
    p = tmp_path / "state.json"
    now = datetime(2026, 5, 8, 9, 0, 0, tzinfo=timezone.utc)
    save_state(p, "deadbeef", now)
    data = json.loads(p.read_text())
    assert data["last_cert_hash"] == "deadbeef"
    assert "2026-05-08" in data["last_updated"]


def test_save_state_is_atomic(tmp_path):
    """Writing state should not leave a partial file on read."""
    p = tmp_path / "state.json"
    now = datetime(2026, 5, 8, 9, 0, 0, tzinfo=timezone.utc)
    save_state(p, "hash1", now)
    save_state(p, "hash2", now)
    data = json.loads(p.read_text())
    assert data["last_cert_hash"] == "hash2"
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_state.py -v
```

Expected: `ImportError` — `state` not yet implemented.

- [ ] **Step 3: Implement `dnssec_inwx_updater/state.py`**

```python
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def load_state(path: Path | str) -> dict:
    path = Path(path)
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def save_state(path: Path | str, cert_hash: str, timestamp: datetime) -> None:
    path = Path(path)
    data = {
        "last_cert_hash": cert_hash,
        "last_updated": timestamp.isoformat(),
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_state.py -v
```

Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add dnssec_inwx_updater/state.py tests/test_state.py
git commit -m "feat: add state file read/write"
```

---

## Task 4: `cert.py` — Cert Path Resolution and SHA-256 Hash

**Files:**
- Create: `dnssec_inwx_updater/cert.py`
- Create: `tests/test_cert.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Create `tests/conftest.py` with shared fixtures**

```python
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
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_cert.py`:

```python
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
```

- [ ] **Step 3: Run tests to confirm they fail**

```bash
pytest tests/test_cert.py -v
```

Expected: `ImportError` — `cert` not yet implemented.

- [ ] **Step 4: Implement `dnssec_inwx_updater/cert.py`**

```python
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
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
pytest tests/test_cert.py -v
```

Expected: all 4 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add dnssec_inwx_updater/cert.py tests/test_cert.py tests/conftest.py
git commit -m "feat: add cert path resolution and SHA-256 hashing"
```

---

## Task 5: `tlsa.py` — TLSA Hash Generation

**Files:**
- Create: `dnssec_inwx_updater/tlsa.py`
- Create: `tests/test_tlsa.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_tlsa.py`:

```python
import subprocess
import hashlib
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
    with pytest.raises(Exception):
        generate_tlsa_hash("/nonexistent/cert.crt")
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_tlsa.py -v
```

Expected: `ImportError` — `tlsa` not yet implemented.

- [ ] **Step 3: Implement `dnssec_inwx_updater/tlsa.py`**

```python
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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_tlsa.py -v
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add dnssec_inwx_updater/tlsa.py tests/test_tlsa.py
git commit -m "feat: add TLSA hash generation via openssl pipeline"
```

---

## Task 6: `inwx.py` — INWX API Wrapper

**Files:**
- Create: `dnssec_inwx_updater/inwx.py`
- Create: `tests/test_inwx.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_inwx.py`:

```python
from unittest.mock import MagicMock, patch
import pytest
from dnssec_inwx_updater.inwx import InwxClient


def make_client(api_responses: dict) -> InwxClient:
    mock_api = MagicMock()
    mock_api.login.return_value = {"code": 1000, "msg": "OK"}
    mock_api.call_api.side_effect = lambda api_method, method_params: api_responses.get(api_method, {})
    with patch("dnssec_inwx_updater.inwx.ApiClient", return_value=mock_api):
        client = InwxClient(username="user", password="pass", test_mode=False)
        client._api = mock_api
    return client


def test_find_tlsa_record_returns_none_when_empty():
    client = make_client({
        "nameserver.listRecords": {"code": 1000, "resData": {"record": []}}
    })
    result = client.find_tlsa_record("example.com", "_25._tcp.mail")
    assert result is None


def test_find_tlsa_record_returns_matching_record():
    record = {"id": 42, "name": "_25._tcp.mail", "type": "TLSA", "content": "3 1 1 oldhash"}
    client = make_client({
        "nameserver.listRecords": {"code": 1000, "resData": {"record": [record]}}
    })
    result = client.find_tlsa_record("example.com", "_25._tcp.mail")
    assert result == record


def test_find_tlsa_record_raises_on_api_error():
    client = make_client({
        "nameserver.listRecords": {"code": 2200, "msg": "Not authorized"}
    })
    with pytest.raises(RuntimeError, match="INWX API error"):
        client.find_tlsa_record("example.com", "_25._tcp.mail")


def test_create_record_calls_api():
    mock_api = MagicMock()
    mock_api.login.return_value = {"code": 1000}
    mock_api.call_api.return_value = {"code": 1000}
    with patch("dnssec_inwx_updater.inwx.ApiClient", return_value=mock_api):
        client = InwxClient(username="user", password="pass", test_mode=False)
        client._api = mock_api
    client.create_record("example.com", "_25._tcp.mail", "3 1 1 newhash", 3600)
    mock_api.call_api.assert_called_once_with(
        api_method="nameserver.createRecord",
        method_params={
            "domain": "example.com",
            "name": "_25._tcp.mail",
            "type": "TLSA",
            "content": "3 1 1 newhash",
            "ttl": 3600,
        },
    )


def test_update_record_calls_api():
    mock_api = MagicMock()
    mock_api.login.return_value = {"code": 1000}
    mock_api.call_api.return_value = {"code": 1000}
    with patch("dnssec_inwx_updater.inwx.ApiClient", return_value=mock_api):
        client = InwxClient(username="user", password="pass", test_mode=False)
        client._api = mock_api
    client.update_record(42, "3 1 1 newhash")
    mock_api.call_api.assert_called_once_with(
        api_method="nameserver.updateRecord",
        method_params={"id": 42, "content": "3 1 1 newhash"},
    )
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_inwx.py -v
```

Expected: `ImportError` — `inwx` not yet implemented.

- [ ] **Step 3: Implement `dnssec_inwx_updater/inwx.py`**

```python
from __future__ import annotations

from INWX.Domrobot import ApiClient


class InwxClient:
    API_URL = ApiClient.API_LIVE_URL
    API_OTE_URL = ApiClient.API_OTE_URL

    def __init__(self, username: str, password: str, test_mode: bool = False) -> None:
        url = self.API_OTE_URL if test_mode else self.API_URL
        self._api = ApiClient(api_url=url, debug_mode=False)
        result = self._api.login(username, password)
        if result["code"] != 1000:
            raise RuntimeError(f"INWX login failed: {result.get('msg')}")

    def find_tlsa_record(self, zone: str, record_name: str) -> dict | None:
        result = self._api.call_api(
            api_method="nameserver.listRecords",
            method_params={"domain": zone, "name": record_name, "type": "TLSA"},
        )
        if result["code"] != 1000:
            raise RuntimeError(f"INWX API error listing records: {result.get('msg')}")
        records = result.get("resData", {}).get("record", [])
        return records[0] if records else None

    def create_record(self, zone: str, name: str, content: str, ttl: int) -> None:
        result = self._api.call_api(
            api_method="nameserver.createRecord",
            method_params={
                "domain": zone,
                "name": name,
                "type": "TLSA",
                "content": content,
                "ttl": ttl,
            },
        )
        if result["code"] != 1000:
            raise RuntimeError(f"INWX API error creating record: {result.get('msg')}")

    def update_record(self, record_id: int, content: str) -> None:
        result = self._api.call_api(
            api_method="nameserver.updateRecord",
            method_params={"id": record_id, "content": content},
        )
        if result["code"] != 1000:
            raise RuntimeError(f"INWX API error updating record: {result.get('msg')}")

    def logout(self) -> None:
        self._api.logout()
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_inwx.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add dnssec_inwx_updater/inwx.py tests/test_inwx.py
git commit -m "feat: add INWX API wrapper for TLSA record management"
```

---

## Task 7: `main.py` — Orchestrator and CLI Entry Point

**Files:**
- Create: `dnssec_inwx_updater/main.py`
- Create: `tests/test_main.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_main.py`:

```python
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from dnssec_inwx_updater.main import run


def make_config_file(tmp_path: Path) -> Path:
    p = tmp_path / "config.toml"
    p.write_text("""
[inwx]
username = "user"
password = "pass"

[cert]
cert_directory = "/fake/certs"
domain = "mail.example.com"

[dns]
zone = "example.com"
record_name = "_25._tcp.mail"
ttl = 3600
""")
    return p


def test_run_no_op_when_cert_unchanged(tmp_path):
    cfg = make_config_file(tmp_path)
    state = tmp_path / "state.json"
    with (
        patch("dnssec_inwx_updater.main.hash_cert", return_value="samehash"),
        patch("dnssec_inwx_updater.main.load_state", return_value={"last_cert_hash": "samehash"}),
        patch("dnssec_inwx_updater.main.InwxClient") as mock_inwx,
    ):
        run(cfg, state)
        mock_inwx.assert_not_called()


def test_run_creates_record_when_none_exists(tmp_path):
    cfg = make_config_file(tmp_path)
    state = tmp_path / "state.json"
    mock_client = MagicMock()
    mock_client.find_tlsa_record.return_value = None

    with (
        patch("dnssec_inwx_updater.main.hash_cert", return_value="newhash"),
        patch("dnssec_inwx_updater.main.load_state", return_value={}),
        patch("dnssec_inwx_updater.main.generate_tlsa_hash", return_value="tlsahash"),
        patch("dnssec_inwx_updater.main.InwxClient", return_value=mock_client),
        patch("dnssec_inwx_updater.main.save_state") as mock_save,
    ):
        run(cfg, state)
        mock_client.create_record.assert_called_once_with(
            "example.com", "_25._tcp.mail", "3 1 1 tlsahash", 3600
        )
        mock_save.assert_called_once()


def test_run_updates_record_when_exists(tmp_path):
    cfg = make_config_file(tmp_path)
    state = tmp_path / "state.json"
    mock_client = MagicMock()
    mock_client.find_tlsa_record.return_value = {"id": 99, "content": "3 1 1 oldhash"}

    with (
        patch("dnssec_inwx_updater.main.hash_cert", return_value="newhash"),
        patch("dnssec_inwx_updater.main.load_state", return_value={"last_cert_hash": "oldhash_cert"}),
        patch("dnssec_inwx_updater.main.generate_tlsa_hash", return_value="tlsahash"),
        patch("dnssec_inwx_updater.main.InwxClient", return_value=mock_client),
        patch("dnssec_inwx_updater.main.save_state") as mock_save,
    ):
        run(cfg, state)
        mock_client.update_record.assert_called_once_with(99, "3 1 1 tlsahash")
        mock_save.assert_called_once()


def test_run_does_not_save_state_on_api_error(tmp_path):
    cfg = make_config_file(tmp_path)
    state = tmp_path / "state.json"
    mock_client = MagicMock()
    mock_client.find_tlsa_record.side_effect = RuntimeError("API error")

    with (
        patch("dnssec_inwx_updater.main.hash_cert", return_value="newhash"),
        patch("dnssec_inwx_updater.main.load_state", return_value={}),
        patch("dnssec_inwx_updater.main.generate_tlsa_hash", return_value="tlsahash"),
        patch("dnssec_inwx_updater.main.InwxClient", return_value=mock_client),
        patch("dnssec_inwx_updater.main.save_state") as mock_save,
    ):
        with pytest.raises(RuntimeError):
            run(cfg, state)
        mock_save.assert_not_called()
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_main.py -v
```

Expected: `ImportError` — `main` not yet implemented.

- [ ] **Step 3: Implement `dnssec_inwx_updater/main.py`**

```python
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from dnssec_inwx_updater.cert import hash_cert, resolve_cert_path
from dnssec_inwx_updater.config import load_config, AppConfig
from dnssec_inwx_updater.inwx import InwxClient
from dnssec_inwx_updater.state import load_state, save_state
from dnssec_inwx_updater.tlsa import generate_tlsa_hash

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


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
        client.logout()

    save_state(state_path, current_hash, datetime.now(tz=timezone.utc))
    log.info("TLSA record updated successfully. New hash: %s", tlsa_hash)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update INWX DANE TLSA records when Caddy certificates change."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.toml"),
        help="Path to config.toml (default: ./config.toml)",
    )
    args = parser.parse_args()

    config_path = args.config
    state_path = config_path.parent / "state.json"

    try:
        run(config_path, state_path)
    except Exception as exc:
        log.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run all tests to confirm they pass**

```bash
pytest -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add dnssec_inwx_updater/main.py tests/test_main.py
git commit -m "feat: add orchestrator and CLI entry point"
```

---

## Task 8: Config Example and README

**Files:**
- Create: `config.example.toml`
- Create: `README.md`

- [ ] **Step 1: Create `config.example.toml`**

```toml
[inwx]
username = "your-inwx-username"
password = "your-inwx-password"
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
```

- [ ] **Step 2: Create `README.md`**

```markdown
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
```

- [ ] **Step 3: Commit**

```bash
git add config.example.toml README.md
git commit -m "docs: add README and example config"
```

---

## Task 9: GitHub Actions CI/CD Workflows

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/publish.yml`

- [ ] **Step 1: Create `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          pip install -e ".[dev]"

      - name: Lint with ruff
        run: ruff check .

      - name: Run tests
        run: pytest -v
```

- [ ] **Step 2: Add dev dependencies to `pyproject.toml`**

Open `pyproject.toml` and add after the `[project]` section:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "ruff>=0.4",
]
```

- [ ] **Step 3: Create `.github/workflows/publish.yml`**

```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - "v*"

permissions:
  id-token: write  # Required for OIDC trusted publishing

jobs:
  publish:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install build tools
        run: pip install build

      - name: Build package
        run: python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

- [ ] **Step 4: Run full test suite one final time**

```bash
pip install -e ".[dev]"
ruff check .
pytest -v
```

Expected: ruff reports no issues, all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add .github/ pyproject.toml
git commit -m "ci: add GitHub Actions workflows for CI and PyPI publishing"
```

---

## Task 10: Final Verification

- [ ] **Step 1: Install the package locally and verify CLI works**

```bash
pip install -e .
dnssec-inwx-updater --help
```

Expected output:
```
usage: dnssec-inwx-updater [-h] [--config CONFIG]

Update INWX DANE TLSA records when Caddy certificates change.
...
```

- [ ] **Step 2: Run the full test suite clean**

```bash
pytest -v --tb=short
```

Expected: all tests PASS, no warnings.

- [ ] **Step 3: Tag a release**

```bash
git tag v0.1.0
git push origin main --tags
```

Expected: GitHub Actions `publish.yml` workflow triggers and publishes to PyPI (requires PyPI trusted publishing configured in PyPI project settings).
