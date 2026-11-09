#!/usr/bin/env python3
"""External check для мегашаблона Traxic: опрос устройства по IP, переданному в ключе.

Кладётся в ExternalScripts Zabbix-сервера и всех прокси (обычно /usr/lib/zabbix/externalscripts),
chmod +x. Нужны: python3, snmpget (net-snmp-utils / snmp), для agent — zabbix_get.

Ключи (генерирует zbx-traxic):
  traxic_poll.py[snmp,<type>,<ip>,<port>,<version>,<community | v3-строка>,<oid1>,<oid2>,...]
  traxic_poll.py[agent,<type>,<ip>,<port>,<key1>,<key2>,...]

v3-строка: user:level:authproto:authpass:privproto:privpass  (level = noAuthNoPriv|authNoPriv|authPriv)
<type> в ключе нужен только для уникальности ключа в шаблоне.

Печатает JSON {"<oid или key>": "<value>", ...}. Недоступные OID/ключи в ответ не попадают,
ошибки — в "_errors". Если не ответило ничего — exit 1 (item станет unsupported).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 2      # секунды на одну попытку SNMP / zabbix_get
RETRIES = 1


def norm_oid(oid: str) -> str:
    oid = oid.strip()
    if oid.startswith("get[") and oid.endswith("]"):
        oid = oid[4:-1]
    return oid.lstrip(".")


NUM_RE = re.compile(r"^\d+(\.\d+)+$")
LINE_RE = re.compile(r"^\.?(\d+(?:\.\d+)+) = (.*)$")
CACHE = os.path.join(tempfile.gettempdir(), "traxic_poll_oids.json")


# Без MIB-файлов: самые частые символьные OID'ы из шаблонов (net-snmp extend на шлюзах).
BUILTIN = {
    "nsExtendOutput1Line": "1.3.6.1.4.1.8072.1.3.2.3.1.1",
    "nsExtendOutputFull": "1.3.6.1.4.1.8072.1.3.2.3.1.2",
    "nsExtendOutNumLines": "1.3.6.1.4.1.8072.1.3.2.3.1.3",
    "nsExtendResult": "1.3.6.1.4.1.8072.1.3.2.3.1.4",
}
SYM_RE = re.compile(r'^(?:[\w-]+::)?(\w+)(?:\."((?:[^"\\]|\\.)*)"|((?:\.\d+)*))$')


def builtin(oid: str):
    m = SYM_RE.match(oid)
    if not m or m.group(1) not in BUILTIN:
        return None
    base = BUILTIN[m.group(1)]
    if m.group(2) is not None:                   # строковый индекс: длина + коды символов
        idx = m.group(2).encode()
        return base + "." + ".".join([str(len(idx))] + [str(b) for b in idx])
    return base + (m.group(3) or "")


def translate(oids: list) -> dict:
    """символьный OID -> числовой (через snmptranslate, с кэшем на диске)."""
    try:
        with open(CACHE) as fh:
            cache = json.load(fh)
    except Exception:  # noqa: BLE001
        cache = {}
    out, changed = {}, False
    exe = shutil.which("snmptranslate") or "/usr/bin/snmptranslate"
    for o in oids:
        if NUM_RE.match(o):
            out[o] = o
        elif o.startswith("iso.") and NUM_RE.match("1." + o[4:]):
            out[o] = "1." + o[4:]
        elif builtin(o):
            out[o] = builtin(o)
        elif o in cache:
            out[o] = cache[o]
        else:
            for extra in ([], ["-m", "ALL"]):
                try:
                    r = subprocess.run([exe, "-On", *extra, o], capture_output=True, text=True, timeout=5)
                    num = r.stdout.strip().lstrip(".")
                    if r.returncode == 0 and NUM_RE.match(num):
                        out[o] = cache[o] = num
                        changed = True
                        break
                except Exception:  # noqa: BLE001
                    pass
    if changed:
        try:
            tmp = CACHE + f".{os.getpid()}"
            with open(tmp, "w") as fh:
                json.dump(cache, fh)
            os.replace(tmp, CACHE)
        except OSError:
            pass
    return out


def _snmpget(base: list, target: str, oids: list):
    res = subprocess.run(base + [target] + oids, capture_output=True, text=True,
                         timeout=TIMEOUT * (RETRIES + 1) + 3)
    vals, cur = {}, None
    for line in res.stdout.splitlines():
        m = LINE_RE.match(line)
        if m:
            cur = m.group(1)
            vals[cur] = m.group(2)
        elif cur is not None:          # продолжение многострочного значения
            vals[cur] += "\n" + line
    return vals, res


def _clean(val: str):
    val = val.strip()
    if val.startswith("No Such") or val.startswith("No more"):
        return None
    if len(val) >= 2 and val[0] == val[-1] == '"':
        val = val[1:-1]
    return val


def snmp(ip: str, port: str, version: str, auth: str, oids: list):
    exe = shutil.which("snmpget") or "/usr/bin/snmpget"
    base = [exe, "-On", "-Oe", "-Ot", "-OQ", "-t", str(TIMEOUT), "-r", str(RETRIES)]
    if version == "3":
        user, level, aproto, apass, pproto, ppass = (auth.split(":") + [""] * 6)[:6]
        base += ["-v3", "-u", user, "-l", level or "noAuthNoPriv"]
        if level in ("authNoPriv", "authPriv"):
            base += ["-a", aproto or "SHA", "-A", apass]
        if level == "authPriv":
            base += ["-x", pproto or "AES", "-X", ppass]
    else:
        base += ["-v", "1" if version == "1" else "2c", "-c", auth]
    target = f"{ip}:{port or 161}"
    wanted = [norm_oid(o) for o in oids if o.strip()]
    num = translate(wanted)
    out, errors = {}, []
    resolved = [o for o in wanted if o in num]
    for i in range(0, len(resolved), 40):          # не больше 40 OID в одном PDU
        chunk = resolved[i:i + 40]
        vals, res = _snmpget(base, target, [num[o] for o in chunk])
        if not vals and res.stderr.strip():
            errors.append(res.stderr.strip()[:300])
            if "Timeout" in res.stderr:
                break
        for o in chunk:
            v = vals.get(num[o])
            v = _clean(v) if v is not None else None
            if v is None:
                errors.append(f"{o}: нет значения")
            else:
                out[o] = v
    for o in wanted:                                # не перевелись в числа — по одному
        if o in num:
            continue
        vals, res = _snmpget(base, target, [o])
        v = _clean(next(iter(vals.values()))) if len(vals) == 1 else None
        if v is None:
            errors.append(f"{o}: {res.stderr.strip()[:200] or 'нет значения'}")
        else:
            out[o] = v
    return out, errors


def agent(ip: str, port: str, keys: list) -> dict:
    exe = shutil.which("zabbix_get") or "/usr/bin/zabbix_get"

    def one(key):
        try:
            r = subprocess.run([exe, "-s", ip, "-p", port or "10050", "-t", str(TIMEOUT), "-k", key],
                               capture_output=True, text=True, timeout=TIMEOUT + 2)
            v = r.stdout.strip()
            if r.returncode != 0 or v.startswith("ZBX_NOTSUPPORTED"):
                return key, None, (v or r.stderr.strip())[:200]
            return key, v, None
        except subprocess.TimeoutExpired:
            return key, None, "timeout"

    out, errors = {}, []
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(keys)))) as ex:
        for key, val, err in ex.map(one, [k for k in keys if k.strip()]):
            if err is None:
                out[key] = val
            else:
                errors.append(f"{key}: {err}")
    return out, errors


def main(argv: list) -> int:
    if len(argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    mode, _type, ip = argv[0], argv[1], argv[2]
    if mode == "snmp":
        port, version, auth, oids = argv[3], argv[4], argv[5], argv[6:]
        out, errors = snmp(ip, port, version, auth, oids)
    elif mode == "agent":
        port, keys = argv[3], argv[4:]
        out, errors = agent(ip, port, keys)
    else:
        print(f"unknown mode {mode}", file=sys.stderr)
        return 2
    if not out:
        print("; ".join(errors) or "no data", file=sys.stderr)
        return 1
    if errors:
        out["_errors"] = errors
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
