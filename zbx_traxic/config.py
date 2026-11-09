"""Загрузка config.yaml с подстановкой ${ENV_VAR}."""
from __future__ import annotations

import copy
import os
import re
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

DEFAULTS: dict[str, Any] = {
    "traxic": {
        "source": "graphql",
        "headers": {},
        "verify_ssl": True,
        "timeout": 60,
        "fields": {
            "id": "id",
            "name": "name",
            "ip": "ip",
            "type": "type",
            "site": "site",
            "template": "template",
        },
    },
    "zabbix": {
        "url": "http://localhost/api_jsonrpc.php",
        "verify_ssl": True,
        "timeout": 60,
    },
    "mikrotik": {
        "host_regex": r"^\d{4}$",
        # Чем привязывать устройство к микротику (по порядку, первый сработавший выигрывает)
        "assign_by": ["site", "subnet"],
        "site_regex": r"(\d{4})",
        "subnet_prefix": 24,
        # Тип (ключ из types), под которым в Traxic числятся сами микротики
        "self_type": "mikrotik",
    },
    "template": {
        "name": "Traxic Mega Node",
        "group": "Templates/Traxic",
        "discovery_interval": "1h",
        "lost_resources_period": "7d",
        "base_templates": [],
        "ping_count": 3,
        "ping_interval": "1m",
        "tcp_interval": "2m",
        "default_severity": "AVERAGE",
        "loss_warn": 20,
        "rtt_warn": 0.3,
    },
    "types": {},
}


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k != "fields":
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    cfg = _merge(DEFAULTS, _expand_env(raw))
    if "fields" in (raw.get("traxic") or {}):
        cfg["traxic"]["fields"] = {**DEFAULTS["traxic"]["fields"], **raw["traxic"]["fields"]}
    cfg["types"].setdefault("other", {"title": "Прочее"})
    return cfg
