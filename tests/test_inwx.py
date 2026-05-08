from unittest.mock import MagicMock, patch

import pytest

from dnssec_inwx_updater.inwx import InwxClient


def make_client(api_responses: dict) -> InwxClient:
    mock_api = MagicMock()
    mock_api.login.return_value = {"code": 1000, "msg": "OK"}

    def side_effect(api_method, method_params):
        return api_responses.get(api_method, {})

    mock_api.call_api.side_effect = side_effect
    with patch("dnssec_inwx_updater.inwx.ApiClient", return_value=mock_api):
        client = InwxClient(username="user", password="pass", test_mode=False)
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


def test_create_record_raises_on_api_error():
    client = make_client({
        "nameserver.createRecord": {"code": 2200, "msg": "Quota exceeded"}
    })
    with pytest.raises(RuntimeError, match="INWX API error"):
        client.create_record("example.com", "_25._tcp.mail", "3 1 1 hash", 3600)


def test_update_record_raises_on_api_error():
    client = make_client({
        "nameserver.updateRecord": {"code": 2200, "msg": "Record not found"}
    })
    with pytest.raises(RuntimeError, match="INWX API error"):
        client.update_record(42, "3 1 1 hash")
