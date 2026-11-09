"""Загрузка устройств из Traxic.

Основной источник — GraphQL API. Запрос и пути к полям задаются в конфиге,
потому что схема Traxic у каждой инсталляции своя (см. `introspect`).
Запасные варианты: csv / json (выгрузка из Traxic) и обычный REST.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import logging
from typing import Any, Iterator

import requests

from .models import Device

log = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
query Introspect {
  __schema {
    queryType { name }
    types {
      name kind
      fields { name args { name type { name kind ofType { name kind ofType { name kind } } } }
               type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
    }
  }
}
"""


def get_path(obj: Any, path: str) -> Any:
    """'a.b.0.c' -> obj['a']['b'][0]['c']. Список на промежуточном шаге
    без индекса разворачивается: 'tags.name' -> ['t1', 't2']."""
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, list):
            if part.lstrip("-").isdigit():
                idx = int(part)
                cur = cur[idx] if -len(cur) <= idx < len(cur) else None
            else:
                cur = [get_path(x, part) for x in cur]
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _to_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(_to_str(v) for v in value if v not in (None, ""))
    return str(value).strip()


class GraphQLClient:
    def __init__(self, url: str, headers: dict | None = None, verify: bool = True, timeout: int = 60):
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
        self.session.headers.update(headers or {})
        self.session.verify = verify
        self.timeout = timeout

    def query(self, query: str, variables: dict | None = None) -> dict:
        resp = self.session.post(self.url, json={"query": query, "variables": variables or {}}, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("errors"):
            raise RuntimeError(f"GraphQL error: {json.dumps(data['errors'], ensure_ascii=False)}")
        return data


def _client(src: dict) -> GraphQLClient:
    return GraphQLClient(src["url"], src.get("headers"), src.get("verify_ssl", True), src.get("timeout", 60))


def _iter_graphql(src: dict) -> Iterator[dict]:
    client = _client(src)
    query = src["query"]
    items_path = src.get("items_path", "data")
    pag = src.get("pagination") or {"mode": "none"}
    variables = dict(src.get("variables") or {})
    mode = pag.get("mode", "none")

    if mode == "none":
        yield from get_path(client.query(query, variables), items_path) or []
        return

    if mode == "offset":
        limit = int(pag.get("limit", 500))
        offset = int(pag.get("start", 0))
        variables[pag.get("limit_var", "limit")] = limit
        page_based = pag.get("page_based", False)  # offset_var = номер страницы, а не смещение
        while True:
            variables[pag.get("offset_var", "offset")] = offset
            rows = get_path(client.query(query, variables), items_path) or []
            yield from rows
            if len(rows) < limit:
                return
            offset += 1 if page_based else limit

    if mode == "cursor":
        # Relay-style: items_path указывает на edges/nodes, page_info_path — на pageInfo
        variables[pag.get("limit_var", "first")] = int(pag.get("limit", 500))
        cursor = None
        while True:
            variables[pag.get("cursor_var", "after")] = cursor
            data = client.query(query, variables)
            rows = get_path(data, items_path) or []
            if pag.get("node_field"):
                rows = [get_path(r, pag["node_field"]) for r in rows]
            yield from rows
            info = get_path(data, pag["page_info_path"]) or {}
            if not info.get(pag.get("has_next_field", "hasNextPage")) or not rows:
                return
            cursor = info.get(pag.get("end_cursor_field", "endCursor"))
        return

    raise ValueError(f"Неизвестный pagination.mode: {mode}")


def _iter_csv(src: dict) -> Iterator[dict]:
    with open(src["path"], encoding=src.get("encoding", "utf-8-sig"), newline="") as fh:
        yield from csv.DictReader(fh, delimiter=src.get("delimiter", ";"))


def _iter_json(src: dict) -> Iterator[dict]:
    with open(src["path"], encoding=src.get("encoding", "utf-8")) as fh:
        yield from get_path(json.load(fh), src.get("items_path", "")) or []


def _iter_http(src: dict) -> Iterator[dict]:
    resp = requests.get(src["url"], headers=src.get("headers"), params=src.get("params"),
                        verify=src.get("verify_ssl", True), timeout=src.get("timeout", 60))
    resp.raise_for_status()
    yield from get_path(resp.json(), src.get("items_path", "")) or []


SOURCES = {"graphql": _iter_graphql, "csv": _iter_csv, "json": _iter_json, "http": _iter_http}


def row_to_device(row: dict, fields: dict) -> Device | None:
    vals = {k: _to_str(get_path(row, p)) if p else "" for k, p in fields.items()}
    raw_ip = vals.get("ip", "")
    # поле ip может содержать "10.0.0.5/24" или "10.0.0.5:8080"
    ip = raw_ip.split("/")[0].split(",")[0].strip()
    if ip.count(":") == 1:
        ip = ip.split(":")[0]
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        log.debug("Пропуск записи без валидного IP: %s", vals)
        return None
    known = {"id", "name", "ip", "type", "site", "template"}
    return Device(
        id=vals.get("id", "") or ip,
        name=vals.get("name", "") or ip,
        ip=ip,
        type_raw=vals.get("type", ""),
        site=vals.get("site", ""),
        template=vals.get("template", ""),
        extra={k: v for k, v in vals.items() if k not in known},
    )


def load_devices(cfg: dict) -> tuple[list[Device], int]:
    """Возвращает (устройства, кол-во пропущенных записей без IP)."""
    src = cfg["traxic"]
    kind = src.get("source", "graphql")
    if kind not in SOURCES:
        raise ValueError(f"traxic.source должен быть одним из {list(SOURCES)}")
    devices, skipped = [], 0
    for row in SOURCES[kind](src):
        dev = row_to_device(row, src["fields"])
        if dev is None:
            skipped += 1
        else:
            devices.append(dev)
    return devices, skipped


def introspect(cfg: dict) -> str:
    """Человекочитаемый дамп схемы GraphQL: корневые запросы и поля объектов."""
    data = _client(cfg["traxic"]).query(INTROSPECTION_QUERY)
    schema = data["data"]["__schema"]

    def tname(t: dict | None) -> str:
        if not t:
            return "?"
        if t["kind"] == "NON_NULL":
            return tname(t.get("ofType")) + "!"
        if t["kind"] == "LIST":
            return "[" + tname(t.get("ofType")) + "]"
        return t.get("name") or "?"

    out = []
    root = schema["queryType"]["name"]
    for t in sorted(schema["types"], key=lambda x: (x["name"] != root, x["name"])):
        if t["name"].startswith("__") or t["kind"] != "OBJECT" or not t.get("fields"):
            continue
        out.append(f"type {t['name']}{'   # <- корневые запросы' if t['name'] == root else ''}")
        for f in t["fields"]:
            args = ", ".join(f"{a['name']}: {tname(a['type'])}" for a in f.get("args") or [])
            out.append(f"  {f['name']}{'(' + args + ')' if args else ''}: {tname(f['type'])}")
        out.append("")
    return "\n".join(out)
