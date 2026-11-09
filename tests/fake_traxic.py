"""Мини-заглушка GraphQL Traxic для локальных тестов: python tests/fake_traxic.py 8099"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

DEVICES = [
    {"id": "1", "name": "MT 1234", "ip": "10.12.34.1", "type": {"name": "MikroTik"}, "object": {"number": "1234"}, "zabbixTemplate": None},
    {"id": "2", "name": "Камера вход 1234", "ip": "10.12.34.21", "type": {"name": "Камера"}, "object": {"number": "1234"}, "zabbixTemplate": None},
    {"id": "8", "name": "Камера двор 1234", "ip": "10.12.34.22", "type": {"name": "Камера"}, "object": {"number": "1234"}, "zabbixTemplate": None},
    {"id": "3", "name": "Е-реле 1234", "ip": "10.12.34.30", "type": {"name": "Е-реле"}, "object": {"number": "1234"}, "zabbixTemplate": "IP-relay UPS"},
    {"id": "4", "name": "Шлюз Стрелка", "ip": "10.12.34.50", "type": {"name": "ПК"}, "object": {"number": "1234"}, "zabbixTemplate": None},
    {"id": "5", "name": "Камера склад", "ip": "10.56.78.21", "type": {"name": "Камера"}, "object": {"number": ""}, "zabbixTemplate": None},
    {"id": "6", "name": "Без IP", "ip": "", "type": {"name": "Камера"}, "object": {"number": "1234"}, "zabbixTemplate": None},
    {"id": "7", "name": "Потерянная", "ip": "192.168.200.5", "type": {"name": "Камера"}, "object": {"number": "9999"}, "zabbixTemplate": None},
]


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if "__schema" in body["query"]:
            data = {"data": {"__schema": {"queryType": {"name": "Query"}, "types": [
                {"name": "Query", "kind": "OBJECT", "fields": [{"name": "devices", "args": [
                    {"name": "limit", "type": {"name": "Int", "kind": "SCALAR"}}],
                    "type": {"kind": "LIST", "name": None, "ofType": {"name": "Device", "kind": "OBJECT"}}}]}]}}}
        else:
            v = body.get("variables") or {}
            off, lim = v.get("offset", 0), v.get("limit", 1000)
            rows = DEVICES
            if v.get("node"):  # запрос «устройства объекта», как из шаблона
                rows = [d for d in DEVICES if d["object"]["number"] == str(v["node"])]
            data = {"data": {"devices": rows[off:off + lim]}}
        raw = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer((sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8099), H).serve_forever()
