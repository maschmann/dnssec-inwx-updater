import json
from datetime import UTC, datetime

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
    now = datetime(2026, 5, 8, 9, 0, 0, tzinfo=UTC)
    save_state(p, "deadbeef", now)
    data = json.loads(p.read_text())
    assert data["last_cert_hash"] == "deadbeef"
    assert "2026-05-08" in data["last_updated"]


def test_save_state_is_atomic(tmp_path):
    """Writing state should not leave a partial file on read."""
    p = tmp_path / "state.json"
    now = datetime(2026, 5, 8, 9, 0, 0, tzinfo=UTC)
    save_state(p, "hash1", now)
    save_state(p, "hash2", now)
    data = json.loads(p.read_text())
    assert data["last_cert_hash"] == "hash2"
