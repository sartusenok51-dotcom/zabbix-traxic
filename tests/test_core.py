import json
import os
import re

import yaml

from zbx_traxic import convert, megatemplate
from zbx_traxic.config import DEFAULTS, _merge
from zbx_traxic.matcher import TypeResolver, assign_to_mikrotiks
from zbx_traxic.models import Device, ZHost
from zbx_traxic.traxic import get_path, row_to_device

HERE = os.path.dirname(__file__)


def cfg(**types):
    c = _merge(DEFAULTS, {"types": types, "traxic": {"url": "http://traxic/graphql", "query": "q"}})
    c["types"].setdefault("other", {})
    return c


def test_get_path_and_row():
    row = {"ip": "10.0.0.5/24", "type": {"name": "Камера"}, "tags": [{"n": "a"}, {"n": "b"}], "obj": {"number": 1234}}
    assert get_path(row, "type.name") == "Камера"
    assert get_path(row, "tags.n") == ["a", "b"]
    assert get_path(row, "tags.1.n") == "b"
    d = row_to_device(row, {"id": "", "name": "", "ip": "ip", "type": "type.name", "site": "obj.number", "template": "tags.n"})
    assert d.ip == "10.0.0.5" and d.site == "1234" and d.template == "a, b"
    assert row_to_device({"ip": "нет"}, {"ip": "ip"}) is None


def test_type_resolver_order():
    r = TypeResolver({"erelay": {"match": {"templates": ["IP-relay UPS"], "traxic_types": ["Е-реле"]}},
                      "camera": {"match": {"traxic_types": ["Камера"], "name_regex": "(?i)cam"}}})
    assert r.resolve(Device("1", "x", "1.1.1.1", template="IP-relay UPS", type_raw="Камера")) == "erelay"
    assert r.resolve(Device("1", "x", "1.1.1.1", type_raw="камера")) == "camera"
    assert r.resolve(Device("1", "CAM-01", "1.1.1.1")) == "camera"
    assert r.resolve(Device("1", "x", "1.1.1.1")) == "other"


def test_assign_by_site_then_subnet():
    c = cfg()
    mk = ZHost("1", "1234", "1234", interfaces=[{"ip": "10.12.34.1", "type": "2", "main": "1"}])
    d1 = Device("a", "cam", "10.99.0.5", site="Объект 1234", kind="camera")
    d2 = Device("b", "cam2", "10.12.34.9", kind="camera")
    d3 = Device("c", "lost", "192.168.1.1", kind="camera")
    res, unassigned, amb = assign_to_mikrotiks([d1, d2, d3], [mk], c)
    assert [(d.name, how) for d, how in res["1"].devices] == [("cam", "site"), ("cam2", "subnet")]
    assert unassigned == [d3] and not amb


def test_convert_template():
    exp = convert.load_export_file(os.path.join(HERE, "fixtures", "relay_export.yaml"))
    w = []
    r = convert.convert_template(exp, "Test relay", w)
    assert [i["id"] for i in r["items"]] == ["bat1.v.ups", "gate.version"]
    assert r["items"][0]["name"] == "Battery voltage {#NAME}"
    assert r["items"][1]["valuemap"] == {"name": "Test relay: onoff"}
    names = {t["name"]: t["expression"] for t in r["triggers"]}
    assert names["Low voltage on {#NAME} {#IP}"] == "last({ITEM:bat1.v.ups})<20.5"
    assert names["Battery dead and no ping"] == "last({ITEM:bat1.v.ups})<14 and avg({PING},10m)=0"
    assert "SSH says bad" not in names
    assert any("ssh.run[x]" in x for x in w) and any("LLD-правило «Network»" in x for x in w)


def test_build_template_end_to_end():
    c = cfg(
        mikrotik={"match": {"traxic_types": ["MikroTik"]}},
        camera={"title": "Камера", "severity": "HIGH", "tcp": [80, 554],
                "http": [{"name": "web", "url": "http://{#IP}/", "ok_codes": [200, 401]}]},
        erelay={"title": "Е-реле", "snmp": {"community": "{$SNMP_COMMUNITY}"}},
    )
    c["template"]["base_templates"] = ["Mikrotik LTAP"]
    exp = convert.load_export_file(os.path.join(HERE, "fixtures", "relay_export.yaml"))
    conv = {"erelay": [convert.convert_template(exp, "Test relay", [])]}
    export, warnings = megatemplate.build_template(c, (7, 4), conv)
    text = megatemplate.to_yaml(export)
    data = yaml.safe_load(text)["zabbix_export"]
    assert data["version"] == "7.0" and "template_groups" in data
    t = data["templates"][0]
    assert t["templates"] == [{"name": "Mikrotik LTAP"}]
    rule = t["discovery_rules"][0]
    keys = [p["key"] for p in rule["item_prototypes"]]
    assert len(keys) == len(set(keys)), "ключи прототипов должны быть уникальны"
    assert all("{#IP}" in k for k in keys)
    # разная периодичность (5m и 1d) -> два мастер-опроса
    masters = [p for p in rule["item_prototypes"] if p["type"] == "EXTERNAL"]
    assert len(masters) == 2
    m5 = next(m for m in masters if m["delay"] == "5m")
    assert m5["key"].startswith("traxic_poll.py[snmp,erelay-1,{#IP},161,2,{$SNMP_COMMUNITY},.1.3.6.1.4.1.26381.1.1.1.1.4")
    m1d = next(m for m in masters if m["delay"] == "1d")
    assert '"NET-SNMP-EXTEND-MIB::nsExtendOutputFull.\\"gate_version\\""' in m1d["key"]
    dep = next(p for p in rule["item_prototypes"] if p["key"] == "traxic.snmp.erelay.bat1.v.ups[{#IP}]")
    assert dep["preprocessing"][0] == {"type": "JSONPATH", "parameters": ["$['1.3.6.1.4.1.26381.1.1.1.1.4']"]}
    assert dep["preprocessing"][1]["type"] == "MULTIPLIER"
    trig = {tp["name"]: tp for tp in rule["trigger_prototypes"]}
    dead = trig["Е-реле • Battery dead and no ping: {#NAME} ({#IP})"]
    assert dead["expression"] == ("last(/Traxic Mega Node/traxic.snmp.erelay.bat1.v.ups[{#IP}])<14 and "
                                  "avg(/Traxic Mega Node/icmpping[{#IP},3],10m)=0")
    assert "dependencies" not in dead  # сам про ping — от «Нет связи» не зависит
    low = trig["Е-реле • Low voltage on {#NAME} {#IP}"]
    assert low["dependencies"][0]["name"] == "Нет связи: {#NAME} ({#IP})"
    # overrides: камера включает свои TCP/HTTP и поднимает важность
    ov = {o["name"]: o for o in rule["overrides"]}
    cam_ops = ov["Тип: camera"]["operations"]
    assert {"operationobject": "TRIGGER_PROTOTYPE", "operator": "REGEXP", "value": "^Нет связи:",
            "severity": "HIGH"} in cam_ops
    assert ov["TCP 554"]["filter"]["conditions"][0]["value"] == "^(camera)$"
    assert any(v["name"] == "Test relay: onoff" for v in t["valuemaps"])
    # скрипт: CFG валидный JSON, тип микротика исключается
    script = t["items"][0]["params"]
    cfg_json = json.loads(re.search(r"var CFG = (\{.*?\n\});", script, re.S).group(1))
    assert cfg_json["self_type"] == "mikrotik" and cfg_json["by_traxic"]["mikrotik"] == "mikrotik"
    assert not warnings
    # uuid детерминированы и формата v4
    uuids = re.findall(r"uuid: ([0-9a-f]{32})", text)
    assert len(uuids) == len(set(uuids)) and all(u[12] == "4" for u in uuids)
    export2, _ = megatemplate.build_template(c, (7, 4), conv)
    assert re.findall(r"uuid: ([0-9a-f]{32})", megatemplate.to_yaml(export2)) == uuids


def test_key_param_quoting():
    assert megatemplate._key_param("1.3.6") == "1.3.6"
    assert megatemplate._key_param('A::b."x"') == '"A::b.\\"x\\""'
    assert megatemplate._key_param("a,b") == '"a,b"'
