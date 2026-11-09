"""Перенос старых шаблонов устройств (камера / е-реле / комп) в мегашаблон узла.

Берёт экспорт шаблона Zabbix (YAML-файл или configuration.export через API) и
превращает его в описание проверок типа, которое `megatemplate` разворачивает
в item/trigger prototypes на узле:

* SNMP-item'ы       -> dependent-прототипы от external-опроса traxic_poll.py по {#IP};
* icmpping*         -> уже есть в мегашаблоне (ping/loss/rtt по {#IP});
* триггеры (и на один item, и на несколько) -> trigger prototypes с переписанными ключами;
* value maps        -> копируются с префиксом шаблона;
* {HOST.NAME}/{HOST.IP}/{HOST.CONN} -> {#NAME}/{#IP}.

Что перенести нельзя, складывается в warnings: LLD-правила самого шаблона
(LLD внутри LLD Zabbix не умеет), item'ы с динамическим индексом OID,
SSH/агент/прочие типы, графики, дашборды.
"""
from __future__ import annotations

import re
from typing import Any

import yaml

PING_KEYS = {"icmpping": "{PING}", "icmppingloss": "{LOSS}", "icmppingsec": "{RTT}"}
HOST_MACROS = [("{HOST.NAME}", "{#NAME}"), ("{HOST.HOST}", "{#NAME}"), ("{HOST.IP}", "{#IP}"),
               ("{HOST.CONN}", "{#IP}"), ("{HOST.DNS}", "{#IP}")]
ITEM_FIELDS = ("units", "description", "history", "trends", "status")


def slug(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z_.-]", "_", str(s)).strip("_") or "x"


def host_macros(s: str) -> str:
    for a, b in HOST_MACROS:
        s = s.replace(a, b)
    return s


def load_export_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)["zabbix_export"]


def export_from_api(api, names: list[str]) -> dict:
    res = api.template.get({"output": ["templateid", "host"], "filter": {"host": names}})
    found = {r["host"] for r in res}
    missing = [n for n in names if n not in found]
    if missing:
        raise ValueError(f"В Zabbix нет шаблонов: {missing}")
    raw = api.call("configuration.export", {"format": "yaml",
                                            "options": {"templates": [r["templateid"] for r in res]}})
    return yaml.safe_load(raw)["zabbix_export"]


def _ping_ref(key: str):
    name = key.split("[", 1)[0]
    if name in PING_KEYS and (key == name or re.fullmatch(rf"{name}\[,*\]", key)):
        return PING_KEYS[name]
    return None


def convert_template(export: dict, template_name: str, warnings: list[str]) -> dict:
    """-> {"items": [...], "triggers": [...], "valuemaps": [...], "macros": {...}}"""
    tpl = next((t for t in export.get("templates", []) if t["template"] == template_name), None)
    if tpl is None:
        raise ValueError(f"В экспорте нет шаблона {template_name!r}")
    tn = tpl["template"]
    w = lambda msg: warnings.append(f"{tn}: {msg}")  # noqa: E731

    for linked in tpl.get("templates") or []:
        w(f"вложенный шаблон «{linked['name']}» не разворачивается — добавьте его в source_templates отдельно")

    vm_names = {v["name"]: f"{tn}: {v['name']}" for v in tpl.get("valuemaps") or []}
    valuemaps = [{"name": vm_names[v["name"]], "mappings": v.get("mappings") or []} for v in tpl.get("valuemaps") or []]

    refs: dict[str, str] = {}      # исходный ключ -> {ITEM:id} / {PING}
    items: list[dict] = []
    triggers: list[dict] = []
    used_ids: set[str] = set()

    for it in tpl.get("items") or []:
        itype = it.get("type", "ZABBIX_PASSIVE")
        key = it["key"]
        pr = _ping_ref(key) if itype == "SIMPLE" else None
        if pr:
            refs[key] = pr
            continue
        if itype != "SNMP_AGENT":
            w(f"item {key} ({itype}) не переносится: шаблон узла опрашивает устройства только по SNMP/ICMP/TCP/HTTP")
            continue
        oid = str(it.get("snmp_oid", ""))
        if oid.startswith("walk[") or oid.startswith("discovery[") or "[" in oid.replace("get[", "", 1):
            w(f"item {key}: OID «{oid}» (walk/динамический индекс) не переносится")
            continue
        iid = slug(key)
        while iid in used_ids:
            iid += "_"
        used_ids.add(iid)
        refs[key] = "{ITEM:%s}" % iid
        item: dict[str, Any] = {
            "id": iid, "name": host_macros(it["name"]), "oid": oid,
            "value_type": it.get("value_type", "UNSIGNED"),
            "delay": it.get("delay", "1m"),
            "preprocessing": it.get("preprocessing") or [],
            "tags": it.get("tags") or [],
        }
        for f in ITEM_FIELDS:
            if it.get(f) is not None:
                item[f] = it[f]
        if it.get("valuemap"):
            item["valuemap"] = {"name": vm_names.get(it["valuemap"]["name"], it["valuemap"]["name"])}
        items.append(item)
        for tr in it.get("triggers") or []:
            triggers.append(tr)

    triggers += [tr for tr in export.get("triggers") or [] if f"/{tn}/" in tr.get("expression", "")]

    out_triggers = []
    for tr in triggers:
        expr = _rewrite(tr["expression"], tn, refs)
        rec = _rewrite(tr.get("recovery_expression", ""), tn, refs) if tr.get("recovery_expression") else ""
        if expr is None or rec is None:
            w(f"триггер «{tr['name']}» ссылается на непереносимые item'ы или другие хосты — пропущен")
            continue
        t = {"name": host_macros(tr["name"]), "expression": expr, "priority": tr.get("priority", "NOT_CLASSIFIED")}
        if rec:
            t["recovery_mode"] = "RECOVERY_EXPRESSION"
            t["recovery_expression"] = rec
        for f in ("description", "manual_close", "status", "event_name", "opdata", "type"):
            if tr.get(f) is not None:
                t[f] = host_macros(str(tr[f])) if f in ("description", "event_name", "opdata") else tr[f]
        t["tags"] = tr.get("tags") or []
        deps = []
        for d in tr.get("dependencies") or []:
            de = _rewrite(d.get("expression", ""), tn, refs)
            if de is None:
                w(f"триггер «{tr['name']}»: зависимость «{d['name']}» не переносится — убрана")
                continue
            deps.append({"name": host_macros(d["name"]), "expression": de,
                         **({"recovery_expression": _rewrite(d["recovery_expression"], tn, refs)}
                            if d.get("recovery_expression") else {})})
        t["dependencies"] = deps
        out_triggers.append(t)

    for r in tpl.get("discovery_rules") or []:
        w(f"LLD-правило «{r['name']}» ({len(r.get('item_prototypes') or [])} прототипов) не переносится: "
          f"LLD внутри LLD в Zabbix нет")
    if tpl.get("dashboards"):
        w("дашборды не переносятся")
    if export.get("graphs"):
        w("графики не переносятся")
    macros = {m["macro"]: m.get("value", "") for m in tpl.get("macros") or [] if m.get("type") != "SECRET_TEXT"}
    for m in tpl.get("macros") or []:
        if m.get("type") == "SECRET_TEXT":
            w(f"секретный макрос {m['macro']} не переносится (значение не экспортируется) — задайте в мегашаблоне вручную")
    return {"items": items, "triggers": out_triggers, "valuemaps": valuemaps, "macros": macros}


_FUNC_REF = re.compile(r"/([^/()]+)/((?:[^,()\[\]\"]|\[(?:[^\]\"]|\"(?:[^\"\\]|\\.)*\")*\])+)")


def _rewrite(expr: str, tn: str, refs: dict[str, str]):
    """/<шаблон>/<ключ> -> {ITEM:id}/{PING}…; None, если есть ссылка на неизвестное."""
    bad = False

    def sub(m):
        nonlocal bad
        host, key = m.group(1), m.group(2)
        if host != tn or key not in refs:
            bad = True
            return m.group(0)
        return refs[key]

    out = _FUNC_REF.sub(sub, expr)
    return None if bad else host_macros(out)
