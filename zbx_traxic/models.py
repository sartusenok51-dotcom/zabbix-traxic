from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

IFACE_AGENT, IFACE_SNMP, IFACE_IPMI, IFACE_JMX = 1, 2, 3, 4
IFACE_TYPES = {"agent": IFACE_AGENT, "snmp": IFACE_SNMP, "ipmi": IFACE_IPMI, "jmx": IFACE_JMX}
IFACE_NAMES = {v: k for k, v in IFACE_TYPES.items()}
DEFAULT_PORTS = {IFACE_AGENT: "10050", IFACE_SNMP: "161", IFACE_IPMI: "623", IFACE_JMX: "12345"}


@dataclass
class Device:
    """Устройство из Traxic в нормализованном виде."""

    id: str
    name: str
    ip: str
    type_raw: str = ""
    site: str = ""
    template: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    kind: Optional[str] = None  # ключ из config.types после сопоставления

    def label(self) -> str:
        return f"{self.name} ({self.ip})"


@dataclass
class ZHost:
    hostid: str
    host: str
    name: str
    status: str = "0"
    interfaces: list[dict] = field(default_factory=list)
    templates: list[dict] = field(default_factory=list)
    tags: list[dict] = field(default_factory=list)
    groups: list[dict] = field(default_factory=list)
    discovered: bool = False  # создан LLD (host prototype мегашаблона)

    @property
    def template_names(self) -> list[str]:
        return [t.get("host") or t.get("name") for t in self.templates]

    def ips(self) -> list[str]:
        return [i["ip"] for i in self.interfaces if i.get("ip")]

    def main_ips(self) -> list[str]:
        return [i["ip"] for i in self.interfaces if i.get("ip") and str(i.get("main")) == "1"]

    def interface_by_ip(self, ip: str, itype: Optional[int] = None) -> Optional[dict]:
        for i in self.interfaces:
            if i.get("ip") == ip and (itype is None or int(i["type"]) == itype):
                return i
        return None

    @property
    def group_names(self) -> list[str]:
        return [g["name"] for g in self.groups]
