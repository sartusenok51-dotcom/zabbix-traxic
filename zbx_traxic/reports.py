from __future__ import annotations

import csv
import os
from collections import Counter

from .matcher import MatchReport


def _write_csv(path: str, header: list[str], rows: list[list]) -> None:
    # utf-8-sig — чтобы Excel открывал кириллицу без танцев
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(header)
        w.writerows(rows)


def write_match_report(out: str, rep: MatchReport, assignments, unassigned, ambiguous,
                       mega_name: str = "") -> str:
    os.makedirs(out, exist_ok=True)
    mega_nodes = {a.mikrotik.host for a in assignments.values() if mega_name in a.mikrotik.template_names}
    mk_of = {d.ip: (a.mikrotik.host, how) for a in assignments.values() for d, how in a.devices}
    rows = []
    for m in rep.matches:
        d = m.device
        mk, how = mk_of.get(d.ip, ("", ""))
        rows.append([d.id, d.name, d.ip, d.type_raw, d.kind, d.site, d.template,
                     m.status, m.how, m.host.host if m.host else "", m.host.name if m.host else "",
                     ", ".join(m.host.ips()) if m.host else "",
                     m.template_status, ", ".join(m.expected_templates),
                     ", ".join(m.host.template_names) if m.host else "", mk, how,
                     "да" if mk in mega_nodes else ""])
    _write_csv(os.path.join(out, "traxic_vs_zabbix.csv"),
               ["traxic_id", "name", "ip", "traxic_type", "kind", "site", "traxic_template",
                "status", "matched_by", "zabbix_host", "zabbix_name", "zabbix_ips",
                "template_status", "expected_templates", "zabbix_templates", "mikrotik", "assigned_by",
                "node_monitored"], rows)
    _write_csv(os.path.join(out, "zabbix_not_in_traxic.csv"), ["hostid", "host", "name", "ips", "templates"],
               [[h.hostid, h.host, h.name, ", ".join(h.ips()), ", ".join(h.template_names)] for h in rep.orphans])
    _write_csv(os.path.join(out, "mikrotik_assignment.csv"), ["mikrotik", "device", "ip", "kind", "assigned_by"],
               [[a.mikrotik.host, d.name, d.ip, d.kind, how] for a in assignments.values() for d, how in a.devices])
    _write_csv(os.path.join(out, "unassigned.csv"), ["name", "ip", "kind", "site", "reason"],
               [[d.name, d.ip, d.kind, d.site, "не нашёлся микротик"] for d in unassigned]
               + [[d.name, d.ip, d.kind, d.site, "несколько микротиков: " + ", ".join(ms)] for d, ms in ambiguous])

    st = Counter(m.status for m in rep.matches)
    ts = Counter(m.template_status for m in rep.matches)
    kinds = Counter(m.device.kind for m in rep.matches)
    mk_with = [a for a in assignments.values() if a.devices]
    lines = [
        "# Traxic ↔ Zabbix", "",
        f"Устройств в Traxic: **{len(rep.matches)}**", "",
        "| Статус | Кол-во |", "|---|---|",
        f"| найдено в Zabbix по IP | {st['ok']} |",
        f"| найдено только по имени (IP разный) | {st['ip_mismatch']} |",
        f"| нет в Zabbix | {st['missing']} |",
        f"| хостов Zabbix, которых нет в Traxic | {len(rep.orphans)} |",
        f"| IP-дубли внутри Traxic | {len(rep.duplicates)} |", "",
        "## Шаблоны", "",
        f"- совпадают: {ts['ok']}", f"- расходятся: {ts['mismatch']}",
        f"- нет ожиданий (тип не описан в config.types и шаблона в Traxic нет): {ts['no_expectation']}", "",
        "## Типы устройств", "",
        *[f"- {k}: {v}" for k, v in kinds.most_common()], "",
        "## Микротики", "",
        f"Микротиков (по маске имени): {len(assignments)}, с устройствами: {len(mk_with)}, "
        f"с мегашаблоном: {len(mega_nodes)}",
        f"Устройств, которые уже мониторит узел (мегашаблон): {sum(1 for r in rows if r[-1])}",
        f"Привязаны к узлу по подсети, а не по объекту — в Traxic не заполнен объект, шаблон их не увидит: "
        f"{sum(1 for r in rows if r[16] == 'subnet')}",
        f"Не привязано устройств: {len(unassigned)}, неоднозначно: {len(ambiguous)}", "",
    ]
    if rep.duplicates:
        lines += ["## IP-дубли в Traxic", ""]
        lines += [f"- {ip}: " + ", ".join(d.name for d in ds) for ip, ds in rep.duplicates.items()]
        lines.append("")
    lines += ["Детали — в CSV рядом: traxic_vs_zabbix.csv, zabbix_not_in_traxic.csv, "
              "mikrotik_assignment.csv, unassigned.csv."]
    path = os.path.join(out, "summary.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return "\n".join(lines)
