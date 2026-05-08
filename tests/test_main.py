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
        patch(
            "dnssec_inwx_updater.main.load_state",
            return_value={"last_cert_hash": "oldhash_cert"},
        ),
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
