import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dnssec_inwx_updater.main import main, run


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


def test_run_calls_logout_even_on_api_error(tmp_path):
    cfg = make_config_file(tmp_path)
    state = tmp_path / "state.json"
    mock_client = MagicMock()
    mock_client.find_tlsa_record.side_effect = RuntimeError("API error")

    with (
        patch("dnssec_inwx_updater.main.hash_cert", return_value="newhash"),
        patch("dnssec_inwx_updater.main.load_state", return_value={}),
        patch("dnssec_inwx_updater.main.generate_tlsa_hash", return_value="tlsahash"),
        patch("dnssec_inwx_updater.main.InwxClient", return_value=mock_client),
    ):
        with pytest.raises(RuntimeError):
            run(cfg, state)
        mock_client.logout.assert_called_once()


def test_run_calls_logout_on_success(tmp_path):
    cfg = make_config_file(tmp_path)
    state = tmp_path / "state.json"
    mock_client = MagicMock()
    mock_client.find_tlsa_record.return_value = None

    with (
        patch("dnssec_inwx_updater.main.hash_cert", return_value="newhash"),
        patch("dnssec_inwx_updater.main.load_state", return_value={}),
        patch("dnssec_inwx_updater.main.generate_tlsa_hash", return_value="tlsahash"),
        patch("dnssec_inwx_updater.main.InwxClient", return_value=mock_client),
        patch("dnssec_inwx_updater.main.save_state"),
    ):
        run(cfg, state)
        mock_client.logout.assert_called_once()


def test_main_exits_nonzero_on_error(tmp_path, monkeypatch):
    config_path = str(tmp_path / "config.toml")
    monkeypatch.setattr(sys, "argv", ["dnssec-inwx-updater", "--config", config_path])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1


def test_main_derives_state_path_from_config(tmp_path, monkeypatch):
    cfg = make_config_file(tmp_path)
    monkeypatch.setattr(sys, "argv", ["dnssec-inwx-updater", "--config", str(cfg)])
    with patch("dnssec_inwx_updater.main.run") as mock_run:
        main()
        _, state_arg = mock_run.call_args[0]
        assert state_arg == tmp_path / "state.json"


def test_run_logs_warning_when_logout_fails(tmp_path):
    cfg = make_config_file(tmp_path)
    state = tmp_path / "state.json"
    mock_client = MagicMock()
    mock_client.find_tlsa_record.return_value = None
    mock_client.logout.side_effect = RuntimeError("network gone")

    with (
        patch("dnssec_inwx_updater.main.hash_cert", return_value="newhash"),
        patch("dnssec_inwx_updater.main.load_state", return_value={}),
        patch("dnssec_inwx_updater.main.generate_tlsa_hash", return_value="tlsahash"),
        patch("dnssec_inwx_updater.main.InwxClient", return_value=mock_client),
        patch("dnssec_inwx_updater.main.save_state"),
        patch("dnssec_inwx_updater.main.log") as mock_log,
    ):
        run(cfg, state)  # must NOT raise
        mock_log.warning.assert_called_once()
