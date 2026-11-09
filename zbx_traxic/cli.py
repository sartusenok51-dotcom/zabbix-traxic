from __future__ import annotations

import argparse
import logging
import os
import sys

from . import convert, megatemplate, reports, traxic
from .config import load_config
from .matcher import TypeResolver, assign_to_mikrotiks, fetch_hosts, is_mikrotik, match_devices
from .zabbix_api import ZabbixAPI

log = logging.getLogger("zbx_traxic")


def _context(cfg):
    devices, skipped = traxic.load_devices(cfg)
    log.info("Traxic: %d устройств (%d записей без IP пропущено)", len(devices), skipped)
    api = ZabbixAPI.from_config(cfg)
    log.info("Zabbix API %s.%s", *api.version)
    hosts = fetch_hosts(api)
    log.info("Zabbix: %d хостов", len(hosts))
    resolver = TypeResolver(cfg["types"])
    rep = match_devices(devices, hosts, resolver, cfg)
    assignments, unassigned, ambiguous = assign_to_mikrotiks(devices, hosts, cfg)
    return api, hosts, rep, assignments, unassigned, ambiguous


def _only(hosts, only: str | None):
    if not only:
        return hosts
    names = {x.strip() for x in only.split(",")}
    return [h for h in hosts if h.host in names]


# --------------------------------------------------------------------------- commands

def cmd_introspect(cfg, args):
    print(traxic.introspect(cfg))


def cmd_traxic(cfg, args):
    devices, skipped = traxic.load_devices(cfg)
    resolver = TypeResolver(cfg["types"])
    for d in devices[: args.limit or None]:
        d.kind = resolver.resolve(d)
        print(f"{d.ip:<16} {d.kind:<10} site={d.site:<8} {d.name}  type={d.type_raw!r} template={d.template!r}")
    print(f"\nвсего {len(devices)}, без IP пропущено {skipped}", file=sys.stderr)


def cmd_report(cfg, args):
    _api, _h, rep, assignments, unassigned, ambiguous = _context(cfg)
    print(reports.write_match_report(args.out, rep, assignments, unassigned, ambiguous, cfg["template"]["name"]))
    print(f"\nОтчёт: {os.path.abspath(args.out)}")


def load_conversions(cfg, api=None) -> tuple[dict[str, list[dict]], list[str]]:
    """types.<k>.source_templates / source_files -> сконвертированные проверки по типам."""
    out: dict[str, list[dict]] = {}
    warnings: list[str] = []
    for key, tc in cfg["types"].items():
        tc = tc or {}
        for src in tc.get("source_files") or []:
            exp = convert.load_export_file(src["file"])
            out.setdefault(key, []).append(convert.convert_template(exp, src["template"], warnings))
        names = list(tc.get("source_templates") or [])
        if names:
            if api is None:
                raise SystemExit(f"Тип {key}: source_templates требуют доступа к Zabbix API (уберите --offline)")
            exp = convert.export_from_api(api, names)
            for n in names:
                out.setdefault(key, []).append(convert.convert_template(exp, n, warnings))
    return out, warnings


def cmd_convert(cfg, args):
    api = None if args.offline else ZabbixAPI.from_config(cfg)
    conv, warnings = load_conversions(cfg, api)
    lines = ["# Перенос шаблонов устройств в мегашаблон", ""]
    for key, parts in conv.items():
        items = [i for p in parts for i in p["items"]]
        trigs = [t for p in parts for t in p["triggers"]]
        lines += [f"## {key} ({(cfg['types'][key] or {}).get('title', key)})", "",
                  f"SNMP item'ов: {len(items)}, триггеров: {len(trigs)}", ""]
        delays = {}
        for i in items:
            delays.setdefault(i["delay"], 0)
            delays[i["delay"]] += 1
        lines.append("Периодичность → мастер-опросов: " + ", ".join(f"{d}: {n} OID" for d, n in delays.items()))
        lines.append("")
        lines += [f"- `{i['oid']}` → {i['name']} ({i['value_type']})" for i in items]
        lines.append("")
        lines += [f"- ⚡ {t['name']}: `{t['expression'][:160]}`" for t in trigs]
        lines.append("")
    if warnings:
        lines += ["## Не переносится", ""] + [f"- {w}" for w in warnings]
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "convert.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nОтчёт: {path}")


def cmd_build_template(cfg, args):
    api = None if args.offline else ZabbixAPI.from_config(cfg)
    version = api.version if api else tuple(int(x) for x in str(cfg["zabbix"].get("version", "7.0")).split(".")[:2])
    conv, cwarn = load_conversions(cfg, api)
    export, warnings = megatemplate.build_template(cfg, version, conv)
    if api and cfg["template"].get("base_templates"):
        have = {t["host"] for t in api.template.get({"output": ["host"],
                                                     "filter": {"host": cfg["template"]["base_templates"]}})}
        missing = [x for x in cfg["template"]["base_templates"] if x not in have]
        if missing:
            sys.exit(f"Базовых шаблонов нет в Zabbix: {missing}")
    for w in cwarn + warnings:
        print("WARN", w, file=sys.stderr)
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "traxic_mega_template.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(megatemplate.to_yaml(export))
    rule = export["zabbix_export"]["templates"][0]["discovery_rules"][0]
    print(f"Шаблон: {path}  (прототипов item: {len(rule['item_prototypes'])}, "
          f"триггеров типов: {len(rule.get('trigger_prototypes', []))}, overrides: {len(rule.get('overrides', []))})")
    if args.do_import:
        tid = megatemplate.import_template(api, export)
        print(f"Импортирован в Zabbix, templateid={tid}")


def cmd_link(cfg, args):
    """Привязать мегашаблон к узлам ^\\d{4}$.

    Базовые шаблоны (template.base_templates, напр. «Mikrotik LTAP») уже входят в мегашаблон,
    поэтому если они висят на узле напрямую — заменяем их одним host.update: Zabbix
    сохраняет item'ы с теми же ключами (itemid и история не меняются).
    """
    api = ZabbixAPI.from_config(cfg)
    name = cfg["template"]["name"]
    res = api.template.get({"output": ["templateid"], "filter": {"host": [name]}})
    if not res:
        sys.exit(f"Шаблона «{name}» нет — сначала build-template --import")
    tid = res[0]["templateid"]
    hosts = _only([h for h in fetch_hosts(api) if is_mikrotik(h, cfg)], args.only)
    replace = set(cfg["template"].get("base_templates") or []) | set(cfg["template"].get("replace_on_link") or [])
    todo = []
    for h in hosts:
        direct = api.host.get({"hostids": [h.hostid], "output": ["hostid"],
                               "selectParentTemplates": ["templateid", "host"]})[0]["parentTemplates"]
        if tid in {t["templateid"] for t in direct}:
            continue
        keep = [t for t in direct if t["host"] not in replace]
        drop = [t for t in direct if t["host"] in replace]
        todo.append((h, keep))
        print(f"[{h.host}] + {name}" + (f"  (вместо {', '.join(t['host'] for t in drop)})" if drop else ""))
    print(f"\nУзлов к привязке: {len(todo)} из {len(hosts)}")
    if not args.apply:
        print("Это dry-run. Для применения добавьте --apply")
        return
    for h, keep in todo:
        api.host.update({"hostid": h.hostid,
                         "templates": [{"templateid": t["templateid"]} for t in keep] + [{"templateid": tid}]})
        print(f"OK {h.host}")


def cmd_migrate(cfg, args):
    """Шаг 6: отключить старые отдельные хосты устройств, которые теперь мониторит узел."""
    api, hosts, rep, assignments, _u, _a = _context(cfg)
    linked = {h.hostid for h in hosts if cfg["template"]["name"] in h.template_names}
    names = {x.strip() for x in args.only.split(",")} if args.only else None
    todo = []
    for a in assignments.values():
        mk = a.mikrotik
        if mk.hostid not in linked or (names and mk.host not in names):
            continue
        for dev, _how in a.devices:
            m = next((m for m in rep.matches if m.device is dev), None)
            h = m.host if m else None
            if h is None or h.hostid == mk.hostid or is_mikrotik(h, cfg) or h.status != "0":
                continue
            todo.append((mk, dev, h))
            print(f"[{mk.host}] отключить {h.host} ({dev.ip}, {dev.kind})")
    print(f"\nК отключению: {len(todo)}")
    if not args.apply:
        print("Это dry-run. Для применения добавьте --apply (хосты отключаются, не удаляются — история сохраняется)")
        return
    for mk, dev, h in todo:
        tags = [t for t in h.tags if t["tag"] != "traxic_migrated"] + [{"tag": "traxic_migrated", "value": mk.host}]
        api.host.update({"hostid": h.hostid, "status": 1, "tags": tags})
        print(f"OK {h.host}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zbx-traxic", description="Traxic → Zabbix: сверка и мегашаблон узла")
    ap.add_argument("-c", "--config", default="config.yaml")
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("introspect", help="показать GraphQL-схему Traxic (для настройки запроса)")
    p = sub.add_parser("traxic", help="загрузить устройства из Traxic и показать, как распознались типы")
    p.add_argument("--limit", type=int, default=50)
    sub.add_parser("report", help="сверка Traxic ↔ Zabbix (CSV + summary.md)")
    p = sub.add_parser("convert", help="показать, как старые шаблоны типов переносятся в мегашаблон")
    p.add_argument("--offline", action="store_true", help="только source_files, без Zabbix API")
    p = sub.add_parser("build-template", help="собрать мегашаблон (YAML)")
    p.add_argument("--import", dest="do_import", action="store_true", help="сразу импортировать в Zabbix")
    p.add_argument("--offline", action="store_true", help="не ходить в Zabbix (версия из zabbix.version)")
    p = sub.add_parser("link", help="привязать мегашаблон к узлам (имя из 4 цифр)")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--only", help="только эти узлы: 1234,5678")
    p = sub.add_parser("migrate", help="отключить старые отдельные хосты устройств на узлах с мегашаблоном")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--only", help="только эти узлы: 1234,5678")

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s", stream=sys.stderr)
    cfg = load_config(args.config)
    {"introspect": cmd_introspect, "traxic": cmd_traxic, "report": cmd_report, "convert": cmd_convert,
     "build-template": cmd_build_template, "link": cmd_link, "migrate": cmd_migrate}[args.cmd](cfg, args)
    return 0
