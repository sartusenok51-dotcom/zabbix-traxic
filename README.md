# zbx-traxic

Один шаблон на узел сети (микротик с именем из 4 цифр), который сам берёт из Traxic
устройства объекта и мониторит их **с этого же хоста** — без отдельных хостов под каждую
камеру, комп или е-реле. Traxic — источник правды: устройство появилось в Traxic → через
`{$TRAXIC.DISCOVERY.INTERVAL}` его проверки появились на узле, пропало → ушли через `lost_resources_period`.

Проверено на Zabbix 7.4 (поддерживается 6.0–7.x) на реальных шаблонах «Mikrotik LTAP», «IP-relay UPS», «Gateway_STR».

## Как устроен мегашаблон

```
Узел «1234» ─ шаблон «Traxic Node»
   ├─ (вложен) Mikrotik LTAP                        ← базовый мониторинг самого микротика, как был
   ├─ traxic.devices  [Script]                      ← GraphQL Traxic: устройства объекта {HOST.HOST}
   │     └─ LLD «Traxic: устройства объекта»  → {#IP} {#NAME} {#TYPE} {#TRAXIC.ID}
   │          ├─ icmpping/loss/sec[{#IP}]                   все типы
   │          ├─ net.tcp.service[tcp,{#IP},port]            порты типа (камера 80/554…)
   │          ├─ HTTP agent http://{#IP}/                   HTTP-проверки типа
   │          ├─ traxic_poll.py[snmp,erelay-1,{#IP},…OID…]  external: один SNMP-запрос на устройство
   │          │     └─ dependent item'ы (JSONPath + родной препроцессинг из старого шаблона)
   │          └─ триггеры старых шаблонов (в т.ч. на несколько item'ов), «Нет связи» и т.д.
   └─ overrides по {#TYPE}: каждому типу — только его проверки и своя важность
```

Почему так, а не «много интерфейсов на хосте + статические item'ы»:
* шаблонный item всегда берёт **основной** интерфейс своего типа — выбрать «этот опрашивает камеру, а этот реле» нельзя;
* у двух одинаковых камер на объекте совпали бы ключи.

Поэтому IP устройства едет **в ключе** item'а. Для SNMP Zabbix так не умеет, поэтому SNMP идёт
через external check `traxic_poll.py` (у вас уже есть `mikrotik_ip.sh`/`billing.sh` — тот же механизм).
Все OID одной периодичности опрашиваются **одним** snmpget, остальное разбирают dependent item'ы.

## Установка

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml      # поправить url/запрос Traxic, типы
export ZABBIX_TOKEN=...  TRAXIC_TOKEN=...
```

На **Zabbix-сервер и все прокси**, которые опрашивают узлы:

```bash
cp externalscripts/traxic_poll.py /usr/lib/zabbix/externalscripts/ && chmod +x /usr/lib/zabbix/externalscripts/traxic_poll.py
apt install python3 snmp            # snmpget; RHEL: net-snmp-utils
```

Символьные OID (`MIKROTIK-MIB::…`) переводятся через `snmptranslate` с MIB'ами сервера (те же, что
сейчас использует Zabbix); `nsExtendOutputFull."…"` у шлюзов переводится встроенно, без MIB.

## Порядок работ

| Шаг | Команда | Что делает |
|---|---|---|
| 0 | `python -m zbx_traxic introspect` | схема GraphQL Traxic — чтобы вписать в конфиг реальные поля и запрос по объекту |
| 0 | `python -m zbx_traxic traxic` | как устройства из Traxic распознались по типам |
| 1–3 | `python -m zbx_traxic report` | сверка по IP → `out/summary.md` + CSV: есть в обоих / только в Traxic / только в Zabbix / шаблон не тот / к какому узлу привязано / мониторит ли уже узел |
| 4 | `python -m zbx_traxic convert` | как старые шаблоны типов (`source_templates`) переносятся: какие OID, триггеры, что **не** переносится и почему → `out/convert.md` |
| 5 | `python -m zbx_traxic build-template --import` | собрать `out/traxic_mega_template.yaml` и импортировать (повторный импорт обновляет — UUID стабильные) |
| 5 | задать в шаблоне макрос `{$TRAXIC.TOKEN}` (секретный), проверить `{$TRAXIC.URL}` | доступ Zabbix-сервера к Traxic |
| 5 | `python -m zbx_traxic link --only 1234,5678 [--apply]` | привязать к 1–2 тестовым узлам. «Mikrotik LTAP», висящий напрямую, заменяется мегашаблоном (он внутри) — itemid и история LTAP сохраняются |
| 6 | `python -m zbx_traxic migrate --only 1234 [--apply]` | старые отдельные хосты устройств на этих узлах **отключаются** (не удаляются), тег `traxic_migrated` |
| 6 | `python -m zbx_traxic link --apply` | на все узлы |

Все изменяющие команды по умолчанию — dry-run.

## Конфиг: типы устройств

```yaml
types:
  erelay:
    title: Е-реле
    severity: HIGH                         # важность «Нет связи»
    source_templates: ["IP-relay UPS"]     # SNMP-item'ы, препроцессинг, триггеры, value maps → в мегашаблон
    snmp: {version: 2, community: "{$SNMP_COMMUNITY}", timeout: 10s}
    match: {traxic_types: ["Е-реле"], templates: ["IP-relay UPS"]}
  camera:
    tcp: [80, 554]
    http: [{name: web, url: "http://{#IP}/", ok_codes: [200, 401]}]
```

`source_files: [{file: export.yaml, template: "..."}]` — то же из файла экспорта, без API.
Свои SNMP-метрики можно дописать руками в `snmp.items` (`id, name, oid, value_type, units, preprocessing, triggers`),
в выражениях триггеров: `{ITEM}`/`{ITEM:id}` — item этого типа, `{PING}`, `{LOSS}`, `{RTT}` — пинг устройства.

## Что не переносится (выводится в `convert`)

* **LLD внутри старых шаблонов** (у Gateway_STR: CPU, Network, SD card) — это discovery внутри discovery.
  В Zabbix 7.4 появились LLD-прототипы (вложенный LLD) — можно сделать следующим шагом.
* SSH/агент/ODBC/прочие item'ы устройств — опрашиваются только SNMP/ICMP/TCP/HTTP.
* Графики и дашборды старых шаблонов.

## Тесты

```bash
python -m pytest -q
```
`tests/fake_traxic.py` — заглушка GraphQL Traxic для стенда (`python tests/fake_traxic.py 8099 0.0.0.0`).
