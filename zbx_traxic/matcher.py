"""Сопоставление Traxic <-> Zabbix и привязка устройств к микротикам."""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .models import Device, ZHost

# --------------------------------------------------------------------------- types

class TypeResolver:
    """Определяет тип устройства (ключ config.types) по шаблону, типу из Traxic, имени."""

    def __init__(self, types_cfg: dict):
        self.types = types_cfg
        self._tpl: dict[str, str] = {}
        self._traxic: dict[str, str] = {}
        self._name_re: list[tuple[re.Pattern, str]] = []
        for key, t in types_cfg.items():
            m = t.get("match") or {}
            for name in m.get("templates", []):
                self._tpl[name.strip().lower()] = key
            for name in m.get("traxic_types", []):
                self._traxic[name.strip().lower()] = key
            if m.get("name_regex"):
                self._name_re.append((re.compile(m["name_regex"], re.I), key))

    def by_template(self, names) -> Optional[str]:
        for n in names:
            for part in str(n).split(","):
                k = self._tpl.get(part.strip().lower())
                if k:
                    return k
        return None

    def resolve(self, dev: Device, zhost: Optional[ZHost] = None) -> str:
        return (
            self.by_template([dev.template] if dev.template else [])
            or self._traxic.get(dev.type_raw.strip().lower())
            or (self.by_template(zhost.template_names) if zhost else None)
            or next((k for r, k in self._name_re if r.search(dev.name)), None)
            or "other"
        )

    def expected_templates(self, kind: str) -> list[str]:
        return list((self.types.get(kind, {}).get("match") or {}).get("templates", []))


# --------------------------------------------------------------------------- zabbix

def fetch_hosts(api) -> list[ZHost]:
    groups_key = "selectHostGroups" if api.version >= (6, 2) else "selectGroups"
    rows = api.host.get({
        "output": ["hostid", "host", "name", "status", "flags"],
        "selectInterfaces": ["interfaceid", "ip", "dns", "useip", "port", "type", "main", "details"],
        "selectParentTemplates": ["templateid", "host", "name"],
        "selectTags": ["tag", "value"],
        groups_key: ["groupid", "name"],
    })
    return [ZHost(r["hostid"], r["host"], r["name"], r.get("status", "0"), r.get("interfaces") or [],
                  r.get("parentTemplates") or [], r.get("tags") or [],
                  r.get("hostgroups") or r.get("groups") or [], str(r.get("flags", "0")) == "4")
            for r in rows]


# --------------------------------------------------------------------------- matching

@dataclass
class Match:
    device: Device
    host: Optional[ZHost]
    how: str                      # ip | name | none
    status: str                   # ok | ip_mismatch | missing
    template_status: str          # ok | mismatch | no_expectation | -
    expected_templates: list[str] = field(default_factory=list)


@dataclass
class MatchReport:
    matches: list[Match]
    orphans: list[ZHost]          # есть в Zabbix, нет в Traxic
    duplicates: dict[str, list[Device]]  # один IP у нескольких устройств Traxic


def is_mikrotik(host: ZHost, cfg: dict) -> bool:
    return bool(re.match(cfg["mikrotik"]["host_regex"], host.host))


def match_devices(devices: list[Device], hosts: list[ZHost], resolver: TypeResolver, cfg: dict) -> MatchReport:
    by_ip: dict[str, list[ZHost]] = defaultdict(list)
    by_name: dict[str, ZHost] = {}
    for h in hosts:
        for ip in set(h.ips()):
            by_ip[ip].append(h)
        by_name[h.host.lower()] = h
        by_name.setdefault(h.name.lower(), h)

    dup: dict[str, list[Device]] = defaultdict(list)
    for d in devices:
        dup[d.ip].append(d)
    duplicates = {ip: ds for ip, ds in dup.items() if len(ds) > 1}

    matches, used = [], set()
    for d in devices:
        cands = by_ip.get(d.ip, [])
        host, how = None, "none"
        if cands:
            # несколько хостов на IP: сначала созданный мегашаблоном, потом совпавший по имени
            host = (next((h for h in cands if h.discovered and h.status == "0"), None)
                    or next((h for h in cands if d.name.lower() in (h.host.lower(), h.name.lower())), cands[0]))
            how = "ip"
        elif d.name.lower() in by_name:
            host, how = by_name[d.name.lower()], "name"
        d.kind = resolver.resolve(d, host)
        expected = resolver.expected_templates(d.kind)
        if d.template:
            expected = [t.strip() for t in d.template.split(",") if t.strip()]
        if host is None:
            matches.append(Match(d, None, how, "missing", "-", expected))
            continue
        used.add(host.hostid)
        status = "ok" if how == "ip" else "ip_mismatch"
        if not expected:
            tstat = "no_expectation"
        else:
            actual = {t.lower() for t in host.template_names}
            if cfg["template"]["name"].lower() in actual:  # базовые шаблоны вложены в мегашаблон
                actual |= {b.lower() for b in cfg["template"].get("base_templates") or []}
            tstat = "ok" if all(e.lower() in actual for e in expected) else "mismatch"
        matches.append(Match(d, host, how, status, tstat, expected))

    traxic_ips = {d.ip for d in devices}
    orphans = [h for h in hosts if h.hostid not in used and not (set(h.ips()) & traxic_ips)]
    return MatchReport(matches, orphans, duplicates)


# --------------------------------------------------------------------------- mikrotik assignment

@dataclass
class Assignment:
    mikrotik: ZHost
    devices: list[tuple[Device, str]] = field(default_factory=list)  # (устройство, способ привязки)


def assign_to_mikrotiks(devices: list[Device], hosts: list[ZHost], cfg: dict):
    """Возвращает (dict hostid -> Assignment, список непривязанных, список неоднозначных)."""
    mcfg = cfg["mikrotik"]
    mikrotiks = [h for h in hosts if is_mikrotik(h, cfg)]
    by_name = {m.host: m for m in mikrotiks}
    result = {m.hostid: Assignment(m) for m in mikrotiks}
    site_re = re.compile(mcfg.get("site_regex") or r"(.+)")
    self_type = mcfg.get("self_type", "mikrotik")
    prefix = int(mcfg.get("subnet_prefix", 24))

    # сети микротиков: собственные IP + IP самого микротика в Traxic
    nets: dict[str, set] = defaultdict(set)
    for m in mikrotiks:
        for ip in set(m.ips()):
            nets[m.hostid].add(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    for d in devices:
        if d.kind == self_type:
            site = _site(d, site_re)
            if site in by_name:
                nets[by_name[site].hostid].add(ipaddress.ip_network(f"{d.ip}/{prefix}", strict=False))

    mikrotik_ips = {ip for m in mikrotiks for ip in m.ips()}
    unassigned, ambiguous = [], []
    for d in devices:
        if d.kind == self_type or d.ip in mikrotik_ips:
            continue
        target, how = None, None
        for strategy in mcfg.get("assign_by", ["site", "subnet"]):
            if strategy == "site":
                site = _site(d, site_re)
                if site and site in by_name:
                    target, how = by_name[site], "site"
            elif strategy == "name_prefix":
                hit = [m for m in mikrotiks if re.match(rf"^{re.escape(m.host)}\D", d.name)]
                if len(hit) == 1:
                    target, how = hit[0], "name_prefix"
            elif strategy == "subnet":
                addr = ipaddress.ip_address(d.ip)
                hit = [m for m in mikrotiks if any(addr in n for n in nets.get(m.hostid, ()))]
                if len(hit) == 1:
                    target, how = hit[0], "subnet"
                elif len(hit) > 1:
                    ambiguous.append((d, [m.host for m in hit]))
                    target = None
                    break
            if target:
                break
        if target:
            result[target.hostid].devices.append((d, how))
        elif not any(a[0] is d for a in ambiguous):
            unassigned.append(d)
    return result, unassigned, ambiguous


def _site(d: Device, site_re: re.Pattern) -> str:
    m = site_re.search(d.site or "")
    return m.group(1) if m else ""
