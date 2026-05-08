from __future__ import annotations

from INWX.Domrobot import ApiClient


class InwxClient:
    API_URL = ApiClient.API_LIVE_URL
    API_OTE_URL = ApiClient.API_OTE_URL

    def __init__(
        self,
        username: str,
        password: str,
        test_mode: bool = False,
        shared_secret: str | None = None,
        language: str = "de",
    ) -> None:
        url = self.API_OTE_URL if test_mode else self.API_URL
        self._api = ApiClient(api_url=url, debug_mode=False, language=language)
        result = self._api.login(username, password, shared_secret=shared_secret)
        if result["code"] != 1000:
            raise RuntimeError(f"INWX login failed: {result.get('msg')}")

    def find_tlsa_record(self, zone: str, record_name: str) -> dict | None:
        result = self._api.call_api(
            api_method="nameserver.listRecords",
            method_params={"domain": zone, "name": record_name, "type": "TLSA"},
        )
        if result["code"] != 1000:
            raise RuntimeError(f"INWX API error listing records: {result.get('msg')}")
        records = (result.get("resData") or {}).get("record", [])
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
        result = self._api.logout()
        if result and result.get("code") != 1000:
            raise RuntimeError(f"INWX logout failed: {result.get('msg')}")
