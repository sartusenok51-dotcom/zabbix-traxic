"""Минимальный клиент Zabbix JSON-RPC API (6.0 … 7.x)."""
from __future__ import annotations

import logging
from typing import Any

import requests

log = logging.getLogger(__name__)


class ZabbixAPIError(RuntimeError):
    pass


def normalize_url(url: str) -> str:
    url = url.rstrip("/")
    return url if url.endswith("api_jsonrpc.php") else url + "/api_jsonrpc.php"


class ZabbixAPI:
    def __init__(self, url: str, token: str | None = None, user: str | None = None,
                 password: str | None = None, verify: bool = True, timeout: int = 60):
        self.url = normalize_url(url)
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers["Content-Type"] = "application/json-rpc"
        self.timeout = timeout
        self._id = 0
        self._auth: str | None = None
        self.version = self._version()
        if token:
            self._auth = token
        elif user:
            key = "username" if self.version >= (5, 4) else "user"
            self._auth = self.call("user.login", {key: user, "password": password}, auth=False)
        else:
            raise ValueError("Нужен zabbix.token или zabbix.user/password")

    @classmethod
    def from_config(cls, cfg: dict) -> "ZabbixAPI":
        z = cfg["zabbix"]
        return cls(z["url"], z.get("token"), z.get("user"), z.get("password"),
                   z.get("verify_ssl", True), z.get("timeout", 60))

    @property
    def header_auth(self) -> bool:
        return self.version >= (6, 4)

    def _version(self) -> tuple[int, int]:
        v = self.call("apiinfo.version", {}, auth=False)
        major, minor = v.split(".")[:2]
        return int(major), int(minor)

    def call(self, method: str, params: Any, auth: bool = True) -> Any:
        self._id += 1
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params, "id": self._id}
        headers = {}
        if auth and self._auth:
            if self.header_auth:
                headers["Authorization"] = f"Bearer {self._auth}"
            else:
                body["auth"] = self._auth
        resp = self.session.post(self.url, json=body, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            err = data["error"]
            raise ZabbixAPIError(f"{method}: {err.get('message')} {err.get('data')}")
        return data["result"]

    def __getattr__(self, name: str):
        # api.host.get(...) -> call("host.get", ...)
        if name.startswith("_"):
            raise AttributeError(name)
        return _Namespace(self, name)


class _Namespace:
    def __init__(self, api: ZabbixAPI, prefix: str):
        self._api, self._prefix = api, prefix

    def __getattr__(self, method: str):
        def _call(params: Any = None, **kwargs):
            return self._api.call(f"{self._prefix}.{method}", params if params is not None else kwargs)
        return _call
