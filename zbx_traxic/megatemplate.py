"""Мегашаблон для узла сети (микротик, имя = номер объекта из 4 цифр).

Всё живёт на одном хосте-узле — отдельных хостов под устройства нет.

1. Мастер-item traxic.devices (Script) по {HOST.HOST} идёт в GraphQL Traxic и
   забирает устройства объекта. Тип (camera/pc/erelay/...) вычисляется в скрипте
   по тем же правилам, что config.types.
2. Dependent LLD-правило создаёт на узле item'ы, у которых IP устройства стоит
   в ключе, поэтому интерфейс выбирать не нужно и одинаковые устройства на
   объекте не конфликтуют по ключам:
     * icmpping/icmppingloss/icmppingsec[{#IP}]           — все типы
     * net.tcp.service[tcp,{#IP},<port>]                  — порты типа
     * HTTP agent http://{#IP}/...                        — HTTP-проверки типа
     * traxic_poll.py[snmp|agent,<type>,{#IP},...]        — external check: SNMP/
       zabbix_get по IP устройства одним запросом, dependent item'ы разбирают JSON.
3. Проверки типа включаются overrides по {#TYPE}.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

import yaml


UUID_NS = uuid.UUID("6f1c3c2e-7a4b-4c41-9d2a-1f1e0b7a7c11")
SEVERITIES = {"NOT_CLASSIFIED", "INFO", "WARNING", "AVERAGE", "HIGH", "DISASTER"}

# Duktape (ES5). CFG подставляется генератором.
SCRIPT_TEMPLATE = r"""
var CFG = __CFG__;
var p = JSON.parse(value);

function get(o, path) {
    if (!path) { return o; }
    var parts = path.split('.'), cur = o;
    for (var i = 0; i < parts.length; i++) {
        if (cur === null || cur === undefined) { return null; }
        var k = parts[i];
        if (Object.prototype.toString.call(cur) === '[object Array]') {
            if (/^-?\d+$/.test(k)) { cur = cur[parseInt(k, 10)]; }
            else { var rest = parts.slice(i).join('.'); return cur.map(function (x) { return get(x, rest); }); }
        } else if (typeof cur === 'object') { cur = cur[k]; }
        else { return null; }
    }
    return cur;
}
function str(v) {
    if (v === null || v === undefined) { return ''; }
    if (Object.prototype.toString.call(v) === '[object Array]') {
        return v.map(str).filter(function (x) { return x !== ''; }).join(', ');
    }
    return String(v).replace(/^\s+|\s+$/g, '');
}
function resolve(typeRaw, tpl, name) {
    var parts = tpl ? tpl.split(',') : [], i, k;
    for (i = 0; i < parts.length; i++) {
        k = CFG.by_template[str(parts[i]).toLowerCase()];
        if (k) { return k; }
    }
    k = CFG.by_traxic[typeRaw.toLowerCase()];
    if (k) { return k; }
    for (i = 0; i < CFG.by_name.length; i++) {
        if (new RegExp(CFG.by_name[i][0], 'i').test(name)) { return CFG.by_name[i][1]; }
    }
    return 'other';
}

if (!/^\d+$/.test(p.node) && CFG.node_must_be_digits) { throw 'Имя узла не номер объекта: ' + p.node; }
var vars = JSON.parse(JSON.stringify(CFG.variables));
vars[CFG.node_var] = CFG.node_as_int ? parseInt(p.node, 10) : p.node;
var rows = [], offset = CFG.start, pages = 0;
while (true) {
    if (CFG.limit) { vars[CFG.limit_var] = CFG.limit; vars[CFG.offset_var] = offset; }
    var req = new HttpRequest();
    req.addHeader('Content-Type: application/json');
    req.addHeader('Accept: application/json');
    if (p.token && p.token.indexOf('{$') !== 0) {
        req.addHeader(CFG.auth_header + ': ' + (CFG.auth_prefix ? CFG.auth_prefix + ' ' : '') + p.token);
    }
    var raw = req.post(p.url, JSON.stringify({query: CFG.query, variables: vars}));
    if (req.getStatus() != 200) { throw 'Traxic HTTP ' + req.getStatus() + ': ' + String(raw).substring(0, 500); }
    var resp = JSON.parse(raw);
    if (resp.errors) { throw 'Traxic GraphQL: ' + JSON.stringify(resp.errors).substring(0, 500); }
    var page = get(resp, CFG.items_path) || [];
    if (CFG.node_field) { page = page.map(function (x) { return get(x, CFG.node_field); }); }
    rows = rows.concat(page);
    pages++;
    if (!CFG.limit || page.length < CFG.limit || pages >= 200) { break; }
    offset += CFG.page_based ? 1 : CFG.limit;
}

var siteRe = new RegExp(CFG.site_regex), out = [], seen = {};
rows.forEach(function (r) {
    if (!r) { return; }
    if (CFG.filter_site) {
        var m = siteRe.exec(str(get(r, CFG.fields.site)));
        if (!m || m[1] !== p.node) { return; }
    }
    var ip = str(get(r, CFG.fields.ip)).split('/')[0].split(',')[0].replace(/^\s+|\s+$/g, '');
    if (/^[^:]+:\d+$/.test(ip)) { ip = ip.split(':')[0]; }
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || seen[ip] || ip === p.node_ip) { return; }
    var typeRaw = str(get(r, CFG.fields.type)), tpl = str(get(r, CFG.fields.template));
    var name = str(get(r, CFG.fields.name)) || ip;
    var kind = resolve(typeRaw, tpl, name);
    if (kind === CFG.self_type) { return; }
    seen[ip] = 1;
    var id = str(get(r, CFG.fields.id)) || ip;
    out.push({'{#IP}': ip, '{#NAME}': name.substring(0, 100), '{#TYPE}': kind, '{#TYPE.TITLE}': CFG.titles[kind] || kind,
              '{#TYPE.RAW}': typeRaw, '{#TRAXIC.ID}': id, '{#NODE}': p.node, '{#TEMPLATE}': tpl});
});
return JSON.stringify(out);
""".strip()


def _uuid(*parts) -> str:
    # детерминированный (повторный импорт обновляет, а не плодит дубли), но формата v4 — Zabbix требует v4
    raw = bytearray(uuid.uuid5(UUID_NS, "/".join(str(p) for p in parts)).bytes)
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(raw)).hex


def _sev(value, default: str) -> str:
    v = str(value or default).upper()
    if v not in SEVERITIES:
        raise ValueError(f"Неизвестная важность {value!r}, допустимо: {sorted(SEVERITIES)}")
    return v


def _js_regex(rx: str) -> str:
    # в JS нет inline-флагов; регистр и так игнорируется
    return re.sub(r"^\(\?[a-z]+\)", "", rx)


def script_config(cfg: dict) -> dict:
    tx = cfg["traxic"]
    tt = cfg["template"]
    q = tt.get("traxic_query") or tx.get("node_query") or tx["query"]
    filter_site = bool(tt.get("filter_site", not (tt.get("traxic_query") or tx.get("node_query"))))
    pag = (tt.get("traxic_pagination") or tx.get("pagination") or {"mode": "none"})
    if pag.get("mode") == "cursor":
        raise ValueError("В скрипте шаблона пагинация cursor не поддержана: задайте template.traxic_query "
                         "с фильтром по объекту без пагинации или с mode: offset")
    by_template, by_traxic, by_name, titles = {}, {}, [], {}
    for key, t in cfg["types"].items():
        t = t or {}
        titles[key] = t.get("title", key)
        m = t.get("match") or {}
        for n in m.get("templates", []):
            by_template[n.strip().lower()] = key
        for n in m.get("traxic_types", []):
            by_traxic[n.strip().lower()] = key
        if m.get("name_regex"):
            by_name.append([_js_regex(m["name_regex"]), key])
    return {
        "query": q,
        "variables": tt.get("traxic_variables") or tx.get("variables") or {},
        "node_var": tt.get("node_var", "node"),
        "node_as_int": bool(tt.get("node_as_int", False)),
        "node_must_be_digits": True,
        "items_path": tt.get("traxic_items_path") or tx.get("items_path", "data"),
        "node_field": pag.get("node_field", ""),
        "limit": int(pag.get("limit", 0)) if pag.get("mode") == "offset" else 0,
        "limit_var": pag.get("limit_var", "limit"),
        "offset_var": pag.get("offset_var", "offset"),
        "start": int(pag.get("start", 0)),
        "page_based": bool(pag.get("page_based", False)),
        "auth_header": tt.get("auth_header", "Authorization"),
        "auth_prefix": tt.get("auth_prefix", "Bearer"),
        "fields": tx["fields"],
        "filter_site": filter_site,
        "site_regex": cfg["mikrotik"].get("site_regex") or "(.+)",
        "self_type": cfg["mikrotik"].get("self_type", "mikrotik"),
        "by_template": by_template, "by_traxic": by_traxic, "by_name": by_name, "titles": titles,
    }


def build_script(cfg: dict) -> str:
    return SCRIPT_TEMPLATE.replace("__CFG__", json.dumps(script_config(cfg), ensure_ascii=False, indent=1))


def _tags(component: str) -> list[dict]:
    return [{"tag": "component", "value": component}, {"tag": "traxic_type", "value": "{#TYPE}"},
            {"tag": "device", "value": "{#NAME}"}, {"tag": "device_ip", "value": "{#IP}"},
            {"tag": "traxic_id", "value": "{#TRAXIC.ID}"}]


def _type_regex(names) -> str:
    return "^(" + "|".join(re.escape(n) for n in names) + ")$"


def _slug(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z_.-]", "_", str(s))


def norm_ref(oid: str) -> str:
    """Тот же вид OID, что отдаёт traxic_poll.py: без get[] и ведущей точки."""
    oid = oid.strip()
    if oid.startswith("get[") and oid.endswith("]"):
        oid = oid[4:-1]
    return oid.lstrip(".")


def _key_param(v: str) -> str:
    v = str(v)
    if re.search(r'[,\]\[" ]', v) or v.startswith(" "):
        return '"' + v.replace('"', '\\"') + '"'
    return v


_REF_RE = re.compile(r"\{(PING|LOSS|RTT|ITEM:[0-9A-Za-z_.-]+)\}")


def _expand_refs(expr: str, tname: str, refs: dict) -> str:
    """{ITEM:id} -> /<шаблон>/<ключ прототипа>, {PING}/{LOSS}/{RTT} -> ping-прототипы."""
    def sub(m):
        k = refs.get(m.group(1))
        if k is None:
            raise ValueError(f"В выражении триггера ссылка на неизвестный item {m.group(0)}: {expr}")
        return f"/{tname}/{k}"
    return _REF_RE.sub(sub, expr)


def _ref(it: dict, mode: str) -> str:
    return str(it["oid"] if mode == "snmp" else it["key"])


def _master_key(script: str, head: list, type_key: str, group: int, refs: list[str]) -> str:
    args = list(head)
    args[1] = f"{type_key}-{group + 1}"
    return f"{script}[{','.join(_key_param(a) for a in args + refs)}]"


def _valuemaps(tname: str, vms: list[dict]) -> list[dict]:
    out, seen = [], set()
    for vm in vms:
        if vm["name"] in seen or not vm.get("mappings"):
            continue
        seen.add(vm["name"])
        out.append({"uuid": _uuid(tname, "vm", vm["name"]), "name": vm["name"],
                    "mappings": [{"value": str(m["value"]), "newvalue": str(m["newvalue"])} for m in vm["mappings"]]})
    return out


def build_template(cfg: dict, api_version: tuple[int, int] = (7, 0),
                   converted: dict[str, list[dict]] | None = None) -> tuple[dict, list[str]]:
    """Возвращает (export-словарь, предупреждения).

    Одно LLD-правило на узле. Прототипы:
      * ping / loss / rtt — для всех типов (кроме no_ping);
      * TCP-порты — по одному прототипу на порт, включаются overrides по типу;
      * HTTP-проверки — свои у каждого типа, ключ traxic.http.<тип>.<имя>[{#IP}].
    Все ключи содержат {#IP}, поэтому любое число одинаковых устройств на узле не конфликтует.
    """
    t = cfg["template"]
    tname = t["name"]
    types = {k: (v or {}) for k, v in cfg["types"].items() if k != cfg["mikrotik"].get("self_type", "mikrotik")}
    warnings: list[str] = []
    converted = converted or {}
    n = int(t.get("ping_count", 3))
    k_ping, k_loss, k_rtt = f"icmpping[{{#IP}},{n}]", f"icmppingloss[{{#IP}},{n}]", f"icmppingsec[{{#IP}},{n}]"
    default_sev = _sev(t.get("default_severity"), "AVERAGE")
    down_name = "Нет связи: {#NAME} ({#IP})"
    down_expr = f"max(/{tname}/{k_ping},#3)=0"
    dep = [{"name": down_name, "expression": down_expr}]
    pi = t.get("ping_interval", "1m")

    protos = [
        {"uuid": _uuid(tname, "ping"), "name": "Ping: {#NAME} ({#IP})", "type": "SIMPLE", "key": k_ping,
         "delay": pi, "value_type": "UNSIGNED", "valuemap": {"name": "Traxic: Up/Down"}, "tags": _tags("ping"),
         "trigger_prototypes": [{"uuid": _uuid(tname, "trig-down"), "expression": down_expr, "name": down_name,
                                 "priority": default_sev,
                                 "description": "Устройство Traxic (ID {#TRAXIC.ID}, тип {#TYPE.TITLE}) "
                                                "не отвечает на ICMP 3 проверки подряд.",
                                 "tags": [{"tag": "scope", "value": "availability"}]}]},
        {"uuid": _uuid(tname, "loss"), "name": "Ping loss: {#NAME} ({#IP})", "type": "SIMPLE", "key": k_loss,
         "delay": pi, "value_type": "FLOAT", "units": "%", "tags": _tags("ping"),
         "trigger_prototypes": [{"uuid": _uuid(tname, "trig-loss"),
                                 "expression": f'min(/{tname}/{k_loss},5m)>{{$TRAXIC.PING.LOSS.WARN:"{{#TYPE}}"}}',
                                 "name": "Потери пакетов: {#NAME} ({#IP})", "priority": "WARNING",
                                 "dependencies": dep, "tags": [{"tag": "scope", "value": "performance"}]}]},
        {"uuid": _uuid(tname, "rtt"), "name": "Ping RTT: {#NAME} ({#IP})", "type": "SIMPLE", "key": k_rtt,
         "delay": pi, "value_type": "FLOAT", "units": "s", "tags": _tags("ping"),
         "trigger_prototypes": [{"uuid": _uuid(tname, "trig-rtt"),
                                 "expression": f'avg(/{tname}/{k_rtt},5m)>{{$TRAXIC.PING.RTT.WARN:"{{#TYPE}}"}}',
                                 "name": "Высокий RTT: {#NAME} ({#IP})", "priority": "WARNING",
                                 "dependencies": dep, "tags": [{"tag": "scope", "value": "performance"}]}]},
    ]

    overrides: list[dict] = []
    vms_extra: list[dict] = []
    type_triggers: list[dict] = []

    def override(name: str, type_keys: list[str], ops: list[dict]) -> None:
        overrides.append({"name": name, "step": str(len(overrides) + 1),
                          "filter": {"conditions": [{"macro": "{#TYPE}", "value": _type_regex(type_keys),
                                                     "formulaid": "A"}]},
                          "operations": ops})

    # --- TCP: один прототип на порт, включается для типов, у которых порт указан
    port_types: dict[int, list[str]] = {}
    for key, tc in types.items():
        for p in tc.get("tcp", []):
            port_types.setdefault(int(p), []).append(key)
    for port, tkeys in sorted(port_types.items()):
        key = f"net.tcp.service[tcp,{{#IP}},{port}]"
        protos.append({
            "uuid": _uuid(tname, "tcp", port), "name": f"TCP {port}: {{#NAME}} ({{#IP}})", "type": "SIMPLE",
            "key": key, "delay": t.get("tcp_interval", "2m"), "value_type": "UNSIGNED", "discover": "NO_DISCOVER",
            "valuemap": {"name": "Traxic: Up/Down"}, "tags": _tags(f"tcp-{port}"),
            "trigger_prototypes": [{"uuid": _uuid(tname, "trig-tcp", port), "expression": f"max(/{tname}/{key},#3)=0",
                                    "name": f"TCP {port} не отвечает: {{#NAME}} ({{#IP}})", "priority": "WARNING",
                                    "dependencies": dep, "tags": [{"tag": "scope", "value": "availability"}]}]})
        override(f"TCP {port}", tkeys, [{"operationobject": "ITEM_PROTOTYPE", "operator": "REGEXP",
                                         "value": f"^TCP {port}:", "discover": "DISCOVER"}])

    # --- Проверки конкретного типа: HTTP, SNMP, агент. Имена начинаются с «<Тип> • »,
    #     по этому префиксу один override включает их только для своего типа.
    type_macros: dict[str, tuple[str, str]] = {}
    for key, tc in types.items():
        title = tc.get("title", key)
        prefix = f"{title} • "
        tdep = [] if tc.get("no_ping") else dep
        typed = []

        for chk in tc.get("http", []):
            cname = _slug(chk["name"])
            ikey = f"traxic.http.{_slug(key)}.{cname}[{{#IP}}]"
            ok = [int(c) for c in chk.get("ok_codes", [200])]
            url = chk.get("url", "http://{#IP}/")
            if "{#IP}" not in url:
                warnings.append(f"Тип {key}, HTTP {chk['name']}: в url нет {{#IP}} — проверка будет ходить не туда")
            ctitle = chk.get("title", chk["name"])
            proto = {
                "uuid": _uuid(tname, "http", key, cname), "name": f"{prefix}HTTP {ctitle}: {{#NAME}} ({{#IP}})",
                "type": "HTTP_AGENT", "key": ikey, "delay": chk.get("interval", "2m"), "value_type": "UNSIGNED",
                "url": url, "timeout": str(chk.get("timeout", "5s")),
                "retrieve_mode": "HEADERS", "status_codes": "", "follow_redirects": "NO",
                "preprocessing": [{"type": "REGEX", "parameters": [r"HTTP/\S+\s+(\d{3})", r"\1"]}],
                "tags": _tags(f"http-{cname}"),
                "trigger_prototypes": [{
                    "uuid": _uuid(tname, "trig-http", key, cname),
                    "expression": "(" + " and ".join(f"last(/{tname}/{ikey})<>{c}" for c in ok) + ")"
                                  + f" or nodata(/{tname}/{ikey},{chk.get('nodata', '10m')})=1",
                    "name": f"{prefix}HTTP {ctitle} не в норме: {{#NAME}} ({{#IP}})",
                    "priority": _sev(chk.get("severity"), "WARNING"), "dependencies": tdep,
                    "tags": [{"tag": "scope", "value": "availability"}]}],
            }
            if chk.get("username"):
                proto.update({"authtype": "BASIC", "username": chk["username"], "password": chk.get("password", "")})
            typed.append(proto)

        for mode in ("snmp", "agent"):
            sec = dict(tc.get(mode) or {})
            items = [dict(i) for i in sec.get("items") or []]
            trig_specs = list(sec.get("triggers") or [])
            if mode == "snmp":
                for conv in converted.get(key, []):
                    items += conv["items"]
                    trig_specs += conv["triggers"]
                    vms_extra.extend(conv["valuemaps"])
                    for m, v in conv["macros"].items():
                        tc.setdefault("macros", {}).setdefault(m, v)
            if not items:
                continue
            for it in items:
                it["id"] = _slug(it.get("id") or it.get("name"))
                it.setdefault("delay", sec.get("interval", "2m"))
            ids = {it["id"]: f"traxic.{mode}.{_slug(key)}.{it['id']}[{{#IP}}]" for it in items}
            refs = {"PING": k_ping, "LOSS": k_loss, "RTT": k_rtt, **{f"ITEM:{i}": k for i, k in ids.items()}}
            if mode == "snmp":
                ver = str(sec.get("version", 2))
                auth = sec.get("community", "{$SNMP_COMMUNITY}") if ver != "3" else sec["v3"]
                head = [mode, None, "{#IP}", str(sec.get("port", 161)), ver, auth]
            else:
                head = [mode, None, "{#IP}", str(sec.get("port", 10050))]
            script = t.get("external_script", "traxic_poll.py")
            # мастера: отдельный на каждую периодичность, и не длиннее 2048 символов ключа
            groups: list[tuple[str, list[dict]]] = []
            for it in items:
                ref = str(it["oid"] if mode == "snmp" else it["key"])
                g = next((g for g in groups if g[0] == it["delay"] and
                          len(_master_key(script, head, key, len(groups), [*(_ref(x, mode) for x in g[1]), ref])) < 1900),
                         None)
                if g is None:
                    g = (it["delay"], [])
                    groups.append(g)
                g[1].append(it)
            for gi, (delay, gitems) in enumerate(groups):
                mkey = _master_key(script, head, key, gi, [_ref(x, mode) for x in gitems])
                master = {
                    "uuid": _uuid(tname, mode, key, "master", gi),
                    "name": f"{prefix}{mode.upper()} опрос #{gi + 1} ({delay}): {{#NAME}} ({{#IP}})",
                    "type": "EXTERNAL", "key": mkey, "delay": delay,
                    "history": sec.get("raw_history", "0"), "trends": "0", "value_type": "TEXT",
                    "tags": _tags(mode),
                }
                if api_version >= (7, 0):
                    master["timeout"] = str(sec.get("timeout", "10s"))
                typed.append(master)
                for it in gitems:
                    jp = norm_ref(_ref(it, mode)) if mode == "snmp" else _ref(it, mode)
                    name = it["name"]
                    proto = {
                        "uuid": _uuid(tname, mode, key, it["id"]),
                        "name": f"{prefix}{name}" + ("" if "{#NAME}" in name else ": {#NAME} ({#IP})"),
                        "type": "DEPENDENT", "key": ids[it["id"]], "delay": "0",
                        "value_type": str(it.get("value_type", "FLOAT")).upper(),
                        "master_item": {"key": mkey},
                        "preprocessing": [{"type": "JSONPATH",
                                           "parameters": ["$['" + jp.replace("\\", "\\\\").replace("'", "\\'") + "']"]}]
                                         + list(it.get("preprocessing") or []),
                        "tags": [x for x in (it.get("tags") or []) if x.get("tag") not in {y["tag"] for y in _tags("")}]
                                + _tags(f"{mode}-{it['id']}"),
                    }
                    for f in ("units", "description", "history", "trends", "status"):
                        if it.get(f) is not None:
                            proto[f] = str(it[f])
                    if it.get("valuemap"):
                        proto["valuemap"] = {"name": it["valuemap"]["name"]}
                        if it["valuemap"].get("mappings"):
                            vms_extra.append(it["valuemap"])
                    typed.append(proto)
            # триггеры типа: всё на уровне правила (могут ссылаться на несколько item'ов)
            for n_tr, tr in enumerate(trig_specs):
                tp = {
                    "uuid": _uuid(tname, mode, key, "trig", tr["name"], n_tr),
                    "expression": _expand_refs(tr["expression"], tname, refs),
                    "name": f"{prefix}{tr['name']}" + ("" if "{#NAME}" in tr["name"] else ": {#NAME} ({#IP})"),
                    "priority": _sev(tr.get("priority"), "WARNING"),
                    "tags": list(tr.get("tags") or []),
                }
                if tr.get("recovery_expression"):
                    tp["recovery_mode"] = "RECOVERY_EXPRESSION"
                    tp["recovery_expression"] = _expand_refs(tr["recovery_expression"], tname, refs)
                for f in ("description", "manual_close", "status", "event_name", "opdata", "type"):
                    if tr.get(f) is not None:
                        tp[f] = tr[f]
                deps = []
                for d in tr.get("dependencies") or []:
                    dn = d["name"] if "{#NAME}" in d["name"] else d["name"] + ": {#NAME} ({#IP})"
                    deps.append({"name": f"{prefix}{dn}", "expression": _expand_refs(d["expression"], tname, refs),
                                 **({"recovery_expression": _expand_refs(d["recovery_expression"], tname, refs)}
                                    if d.get("recovery_expression") else {})})
                # если триггер сам не про пинг — пусть молчит, пока устройство недоступно
                if not tc.get("no_ping") and k_ping not in tp["expression"]:
                    deps.append(dep[0])
                if deps:
                    tp["dependencies"] = deps
                type_triggers.append(tp)
        for m, v in (tc.get("macros") or {}).items():
            if m in type_macros and type_macros[m][1] != str(v):
                warnings.append(f"Макрос {m}: разные значения у {type_macros[m][0]} и {key} — оставлено первое")
                continue
            type_macros.setdefault(m, (key, str(v)))

        for p in typed:
            p["discover"] = "NO_DISCOVER"
        protos.extend(typed)
        ops = []
        if typed:
            ops.append({"operationobject": "ITEM_PROTOTYPE", "operator": "REGEXP",
                        "value": "^" + re.escape(prefix), "discover": "DISCOVER"})
        if tc.get("severity") and _sev(tc["severity"], default_sev) != default_sev:
            ops.append({"operationobject": "TRIGGER_PROTOTYPE", "operator": "REGEXP", "value": "^Нет связи:",
                        "severity": _sev(tc["severity"], default_sev)})
        if tc.get("no_ping"):
            ops.append({"operationobject": "ITEM_PROTOTYPE", "operator": "REGEXP", "value": "^Ping",
                        "discover": "NO_DISCOVER"})
        if ops:
            override(f"Тип: {key}", [key], ops)

    rule = {
        "uuid": _uuid(tname, "lld"),
        "name": "Traxic: устройства объекта",
        "type": "DEPENDENT",
        "key": "traxic.devices.discovery",
        "delay": "0",
        "lifetime": t.get("lost_resources_period", "7d"),
        "master_item": {"key": "traxic.devices"},
        "item_prototypes": protos,
    }
    if type_triggers:
        rule["trigger_prototypes"] = type_triggers
    if overrides:
        rule["overrides"] = overrides

    macros = [
        {"macro": "{$TRAXIC.URL}", "value": t.get("traxic_url_from_server") or cfg["traxic"].get("url", ""),
         "description": "GraphQL endpoint Traxic, доступный с Zabbix-сервера/прокси"},
        {"macro": "{$TRAXIC.TOKEN}", "type": "SECRET_TEXT", "description": "Токен Traxic API"},
        {"macro": "{$TRAXIC.DISCOVERY.INTERVAL}", "value": t.get("discovery_interval", "1h")},
        {"macro": "{$TRAXIC.PING.LOSS.WARN}", "value": str(t.get("loss_warn", 20)), "description": "%"},
        {"macro": "{$TRAXIC.PING.RTT.WARN}", "value": str(t.get("rtt_warn", 0.3)), "description": "секунды"},
    ]
    for m, (_k, v) in type_macros.items():
        macros.append({"macro": m, "value": v})
    for key, tc in types.items():
        if "loss_warn" in tc:
            macros.append({"macro": f'{{$TRAXIC.PING.LOSS.WARN:"{key}"}}', "value": str(tc["loss_warn"])})
        if "rtt_warn" in tc:
            macros.append({"macro": f'{{$TRAXIC.PING.RTT.WARN:"{key}"}}', "value": str(tc["rtt_warn"])})

    type_list = "\n".join(f"  {k}: {v.get('title', k)}" for k, v in types.items())
    template = {
        "uuid": _uuid(tname, "template"),
        "template": tname,
        "name": tname,
        "description": "Ставится на узел сети (микротик, имя = номер объекта). Забирает из Traxic устройства "
                       "объекта и мониторит их прямо с этого хоста по IP (LLD): ping/TCP/HTTP, а SNMP — через "
                       "external check traxic_poll.py. Базовый мониторинг узла — во вложенных шаблонах.\n"
                       "Сгенерирован zbx-traxic. Типы:\n" + type_list,
        **({"templates": [{"name": x} for x in t["base_templates"]]} if t.get("base_templates") else {}),
        "groups": [{"name": t["group"]}],
        "items": [
            {"uuid": _uuid(tname, "item", "devices"), "name": "Traxic: устройства объекта (JSON)",
             "type": "SCRIPT", "key": "traxic.devices", "delay": "{$TRAXIC.DISCOVERY.INTERVAL}",
             "history": "1d", "trends": "0", "value_type": "TEXT", "params": build_script(cfg),
             "timeout": str(t.get("script_timeout", "30s")),
             "parameters": [
                 {"name": "url", "value": "{$TRAXIC.URL}"},
                 {"name": "token", "value": "{$TRAXIC.TOKEN}"},
                 {"name": "node", "value": "{HOST.HOST}"},
                 {"name": "node_ip", "value": "{HOST.IP}"},
             ],
             "tags": [{"tag": "component", "value": "traxic"}]},
            {"uuid": _uuid(tname, "item", "count"), "name": "Traxic: количество устройств объекта",
             "type": "DEPENDENT", "key": "traxic.devices.count", "delay": "0", "value_type": "UNSIGNED",
             "master_item": {"key": "traxic.devices"},
             "preprocessing": [{"type": "JSONPATH", "parameters": ["$.length()"]}],
             "tags": [{"tag": "component", "value": "traxic"}],
             "triggers": [{"uuid": _uuid(tname, "trig", "nodata"),
                           "expression": f"nodata(/{tname}/traxic.devices.count,3h)=1",
                           "name": "Traxic: не удаётся получить список устройств объекта",
                           "priority": "WARNING",
                           "description": "Смотрите ошибку элемента «Traxic: устройства объекта (JSON)»: "
                                          "токен/URL Traxic, доступность Traxic с Zabbix-сервера."}]},
        ],
        "discovery_rules": [rule],
        "tags": [{"tag": "class", "value": "network"}, {"tag": "target", "value": "traxic"}],
        "macros": macros,
        "valuemaps": [{"uuid": _uuid(tname, "vm", "updown"), "name": "Traxic: Up/Down",
                       "mappings": [{"value": "0", "newvalue": "Down"}, {"value": "1", "newvalue": "Up"}]}]
                     + _valuemaps(tname, vms_extra),
    }
    new = api_version >= (7, 0)
    export = {"zabbix_export": {
        "version": "7.0" if new else "6.0",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "template_groups" if new else "groups": [{"uuid": _uuid("group", t["group"]), "name": t["group"]}],
        "templates": [template],
    }}
    if new:
        del export["zabbix_export"]["date"]
    return export, warnings


class _Dumper(yaml.SafeDumper):
    pass


def _str_repr(dumper, data: str):
    if "\n" in data:
        # block-стиль невозможен с хвостовыми пробелами/табами — чистим (для выражений и JS это безопасно)
        data = "\n".join(line.replace("\t", "    ").rstrip() for line in data.split("\n"))
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|" if "\n" in data else None)


_Dumper.add_representer(str, _str_repr)


def to_yaml(export: dict) -> str:
    clean = {k: v for k, v in export.items() if not k.startswith("_")}
    return yaml.dump(clean, Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=float("inf"))


def import_rules(api_version: tuple[int, int]) -> dict:
    cu = {"createMissing": True, "updateExisting": True}
    cud = {**cu, "deleteMissing": True}
    rules = {"templates": cu, "items": cud, "discoveryRules": cud, "triggers": cud, "valueMaps": cud,
             "templateLinkage": {"createMissing": True}}
    if api_version >= (6, 2):
        rules["template_groups"] = {"createMissing": True}
    else:
        rules["groups"] = {"createMissing": True}
    return rules


def import_template(api, export: dict) -> str:
    api.call("configuration.import", {"format": "yaml", "source": to_yaml(export),
                                      "rules": import_rules(api.version)})
    name = export["zabbix_export"]["templates"][0]["template"]
    return api.template.get({"output": ["templateid"], "filter": {"host": [name]}})[0]["templateid"]
