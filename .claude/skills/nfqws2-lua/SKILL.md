---
name: nfqws2-lua
description: Строгий справочник Lua-библиотеки zapret2 1.0.6 (zapret-lib, zapret-antidpi, zapret-auto, zapret-obfs, zapret-pcap) — все функции --lua-desync, их аргументы и умолчания, стандартные блоки fooling/ipid/ipfrag/rawsend/reconstruct, маркеры позиций, tls_mod, блобы, оркестраторы, написание своих функций. Читать перед генерацией, мутацией или проверкой любой стратегии.
---

# Lua-библиотека zapret2 (compat 6, v1.0.6)

Источник истины: `lua/zapret-antidpi.lua` (комментарии `-- arg :` над каждой
функцией), `lua/zapret-auto.lua`, `docs/manual.en.md` (главы «zapret-antidpi»,
«zapret-auto»). Генератор стратегий AutoTuner держит **машиночитаемую копию**
этой таблицы (`src/ZapretAutoTuner.Core/Catalog/Data/functions.json` и `protocols.json`) и юнит-тест,
который сверяет её с бандлимыми lua: каждое имя функции и каждый `arg` есть в
исходнике.

## 1. Синтаксис вызова

```
--lua-desync=имя_функции[:арг1[=знач1]][:арг2[=знач2]]…
```

- Разделитель — `:`. Литеральное двоеточие в значении экранируется `\:`.
- Аргумент без значения — пустая строка (флаг): `:badsum`, `:optional`.
- Все значения — строки, функции сами делают `tonumber`.
- `%var` подставляет значение `desync.var`, а если его нет, то глобала `var`.
  `#var` подставляет длину. Экранирование: `\%`, `\#`. Если подстановку не
  удалось разрешить, C-код (с 1.0.4) отменяет весь execution plan.
- Имя функции — идентификатор Lua, функция должна быть глобальной после
  всех `--lua-init`.
- Инстансы исполняются **слева направо**. Вердикты агрегируются по правилу
  DROP > MODIFY > PASS. `return nil` — это PASS. Бит `VERDICT_PRESERVE_NEXT`
  сохраняет следующий заголовок IPv6.
- `--payload`, `--in-range` и `--out-range` перед инстансом — фильтры C-уровня.
  Сверх них функции из antidpi проверяют свои `dir=` и `payload=` (§2).

## 2. Стандартные блоки аргументов

Функция принимает блок, только если он указан в её строке «standard args»
(таблица §4). Аргумент из блока, который функция не берёт, молча
игнорируется. Генератор такие аргументы не ставит.

**direction:** `dir=in|out|any`. По умолчанию `out`.

**payload:** `payload=type1,type2` — дополнительный фильтр внутри функции.
`~` в начале инвертирует список. По умолчанию `known` (не empty и не unknown).
Поэтому для нераспознанного протокола (`--payload=unknown`) функции без
`payload=unknown` (или `all`) на каждом инстансе ничего не делают
(`payload_check` в zapret-lib.lua). Генератор ставит его сам (слот
`{lpayload}` в families.yaml).

**fooling** (портит фейк так, чтобы сервер его отбросил, а DPI принял):

| Ключ | Смысл |
|---|---|
| `ip_ttl=N` / `ip6_ttl=N` | Фиксированный TTL / hop limit |
| `ip_autottl=delta,min-max` / `ip6_autottl=…` | TTL по входящему: путь + delta, зажат в min..max. Нужен входящий пакет или ipcache. Если оценить нельзя, фейк не отправляется |
| `ip6_hopbyhop[=hex]`, `ip6_hopbyhop2`, `ip6_destopt[=hex]`, `ip6_destopt2`, `ip6_routing[=hex]` | Ext-заголовки IPv6 (данные 6+N·8 байт, по умолчанию нули) |
| `ip6_ah[=hex]` | AH-заголовок (6+N·4) |
| `tcp_seq=±N` | Сдвиг seq («badseq»), например `tcp_seq=-10000` |
| `tcp_ack=±N` | Сдвиг ack («badack»). Linux-сервер отбрасывает такой сегмент стабильно, только если timestamp-опция идёт первой, поэтому ставится вместе с `tcp_ts_up` |
| `tcp_ts=±N` | Сдвиг TS value. Работает, только если клиент шлёт TCP timestamps. Windows по умолчанию их **не шлёт** (проверять `cond_tcp_has_ts`) |
| `tcp_md5[=hex16]` | MD5-опция, без значения 16 случайных байт (`brandom(16)`). Linux-серверы отбрасывают такие сегменты, многие другие тоже |
| `tcp_flags_set=список`, `tcp_flags_unset=список` | Флаги: FIN,SYN,RST,PSH,ACK,URG,ECE,CWR |
| `tcp_ts_up` | Поднять TS-опцию первой |
| `tcp_nop_del` | Удалить NOP, чтобы освободить место |
| `fool=имя_функции` | Своя функция порчи `fn(dis, fooling_options)` |

**reconstruct:** `badsum` (испортить L4 checksum). Других ключей в блоке нет.

**ipid:** `ip_id=seq|rnd|zero|none`, `ip_id_conn` (продолжать seq между
пакетами, нужен conntrack). Windows заменяет нулевой ip_id своим.

**ipfrag:** `ipfrag[=функция]` (по умолчанию `ipfrag2`), `ipfrag_disorder`,
`ipfrag_pos_tcp=N` (кратно 8, по умолчанию 32), `ipfrag_pos_udp=N` (8),
`ipfrag_pos_icmp=N` (8), `ipfrag_pos=N` (32), `ipfrag_next=proto`.

**rawsend:** `repeats=N` (сколько раз отправить), `ifout=iface` (нужен
`--bind-fix4/6`), `fwmark=N`.

## 3. Маркеры позиций (`pos=`, `seqovl=` у disorder, `midhost=`, `urp=`)

- Абсолютные: `5` (с 1), `-1` (последний байт), `-10`.
- Относительные: `method`, `host`, `endhost` (байт после хоста), `sld`,
  `endsld`, `midsld`, `sniext` (начало данных SNI-расширения), `extlen`
  (поле длины расширений TLS).
- Арифметика: `midsld+1`, `host-2`, `sniext+3`. Список через запятую:
  `1,host,midsld+1,-10`.
- Относительные маркеры работают только на известных пейлоадах
  (`http_req`, `tls_client_hello`, …). Маркер, который не разрешился,
  пропускается. Позиции нормализуются и дедуплицируются.
- `seqovl=` у `multidisorder`, `multidisorder_legacy` и `fakeddisorder` —
  один маркер (`resolve_pos`), величина перекрытия равна разрешённой позиции
  и должна быть меньше первой позиции split (справка v1.0.6 пишет
  `seqovl=<posmarker>`; код тот же, что в 1.0.5.2). Не разрешился — seqovl
  отменяется. У `multisplit`, `fakedsplit`, `tcpseg` `seqovl` — число.

## 4. zapret-antidpi.lua — функции

Сокращения блоков: D=direction, P=payload, F=fooling, I=ipid, Fr=ipfrag,
R=rawsend, Rc=reconstruct. Колонка «verdict» — что функция делает с оригиналом.

### 4.1 Базовые

| Функция | Блоки | Аргументы | verdict / заметки |
|---|---|---|---|
| `drop` | D,P | — | DROP |
| `send` | D,F,I,Fr,R,Rc | `delay=мс` | Отправить копию (с delay — по oneshot-таймеру, повторный send замещает предыдущий). Оригинал PASS |
| `pktmod` | D,F,I | — | Модифицировать сам пакет (fooling на оригинал) → MODIFY |

### 4.2 HTTP (только `http_req`)

| Функция | Аргументы | Заметки |
|---|---|---|
| `http_domcase` | D | `rUtRaCkEr.oRg` в Host |
| `http_hostcase` | D, `spell=XXXX` (ровно 4 символа, по умолчанию `host`) | Регистр заголовка Host |
| `http_methodeol` | D | `\r\n` перед методом. Работает только с nginx, ставится **последней** из http-модификаций |
| `http_unixeol` | D | `0D0A` → `0A`. Только nginx |

### 4.3 Окно и handshake

| Функция | Блоки | Аргументы | Заметки |
|---|---|---|---|
| `wsize` | — | `wsize=N`, `scale=N` | На SYN,ACK, затем cutoff. Устаревшая техника, режет скорость |
| `wssize` | D | `wsize`, `scale`, `forced_cutoff=список` (`no` = никогда) | На все пакеты до cutoff. Фаза 0: с hostlist работает только через `--ipcache-hostname`. Типично `wsize=1:scale=6`. Последнее средство |
| `synack` | Fr,R,Rc | — | SYN,ACK перед SYN (TCB turnaround). **Ломает NAT** |
| `synack_split` | Fr,R,Rc | `mode=syn\|synack\|acksyn` (по умолчанию synack) | Серверная техника, клиенту AutoTuner не нужна |
| `syndata` | F,Fr,R,Rc | `blob` (по умолчанию 16 нулей, влезает в 1 пакет), `tls_mod` | Данные в SYN. Фаза 0 |

### 4.4 Фейки

| Функция | Блоки | Аргументы | Заметки |
|---|---|---|---|
| `fake` | D,P,F,I,Fr,R,Rc | `blob=имя` (**обязателен**), `optional`, `tls_mod=…` | Отдельный пакет(ы) до оригинала, сегментация автоматическая. Без fooling или seqovl фейк дойдёт до сервера и сломает соединение. Оригинал PASS |
| `rst` | D,P,F,I,Fr,R,Rc | `rstack` | Пустой RST или RST,ACK. Нужен fooling |
| `tls_client_hello_clone` | D | `blob=имя_результата`, `fallback=блоб`, `sni_del_ext`, `sni_del`, `sni_snt=N`, `sni_snt_new=N`, `sni_first=host`, `sni_last=host` | Готовит `desync.<blob>` из текущего CH. Трафик не трогает. Порядок операций: del_ext → del → snt → first → last |

`tls_mod` (список через запятую): `rnd` (random и session id),
`dupsid` (session id из оригинала, после rnd), `rndsni` (случайный SNI),
`sni=домен` (поддерживает `sni=%var`), `padencap` (оригинал становится
padding-расширением). У `syndata` доступны только `rnd`, `rndsni`, `sni=`.

### 4.5 TCP-сегментация

| Функция | Блоки | Аргументы | Заметки |
|---|---|---|---|
| `multisplit` | D,P,F,I,Fr,R,Rc | `pos=список` (по умолчанию `2`), `seqovl=N` (**число**), `seqovl_pattern=блоб` (0x00), `blob`, `optional`, `nodrop` | Сегменты по порядку, seqovl к первому. DROP оригинала |
| `multidisorder` | D,P,F,I,Fr,R,Rc | `pos=список` (2), `seqovl=маркер` (< первой позиции), `seqovl_pattern`, `blob`, `optional`, `nodrop` | Сегменты с последнего. seqovl перезаписывает буфер сокета. **Не работает с Windows-серверами** |
| `multidisorder_legacy` | D,P,F,I,Fr,R,Rc | `pos`, `seqovl=маркер`, `seqovl_pattern`, `optional` | Как в nfqws1, по частям replay |
| `fakedsplit` | D,P,F,I,R,Rc | `pos=маркер` (один, 2), `nofake1..4`, `pattern=блоб`, `seqovl=N`, `seqovl_pattern`, `blob`, `optional`, `nodrop` | Порядок: fake1, real1, fake1, fake2, real2, fake2. **Fooling обязателен** (идёт только на фейки, на оригиналы — только `tcp_ts_up`). ipfrag не используется |
| `fakeddisorder` | D,P,F,I,R,Rc | `pos=маркер`, `nofake1..4`, `pattern`, `seqovl=маркер` (< pos), `seqovl_pattern`, `blob`, `optional`, `nodrop` | Порядок: fake2, real2, fake2, fake1, real1, fake1. Fooling обязателен |
| `hostfakesplit` | D,P,F,I,R,Rc | `host=шаблон` (фейк «random.шаблон»), `midhost=маркер` (в host+1..endhost-1), `disorder_after=маркер` (> endhost, пусто = `-1`), `nofake1`, `nofake2`, `blob`, `optional`, `nodrop` | Для `http_req` и `tls_client_hello`. Fooling обязателен |
| `tcpseg` | D,P,F,I,Fr,R,Rc | `pos=м1,м2` (**ровно 2, обязателен**), `seqovl=N`, `seqovl_pattern`, `blob`, `optional` | Отправляет кусок. Вердикта нет: для замены оригинала нужен `drop` следом. `pos=0,-1` + seqovl = seqovl без сплита |
| `oob` | F,I,Fr,R,Rc | `char=c` \| `byte=0..255`, `urp=маркер\|b\|e` (b по умолчанию) | Сдвигает seq на handshake. **Нужен `--in-range=-s1`**. Нельзя фильтровать по payload и hostlist. Нельзя сочетать с multisplit и другими ресендерами. «Длящаяся» техника: при смене профиля её надо продублировать |

**seqovl** — скрытый фейк: часть данных левее окна TCP сервер отбрасывает,
DPI без отслеживания seq её принимает. Fooling не нужен. Типичный приём:
`multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000`, или паттерн —
блоб настоящего чужого ClientHello (`seqovl=681:seqovl_pattern=tls_google`).

### 4.6 UDP

| Функция | Блоки | Аргументы |
|---|---|---|
| `udplen` | D,P | `min=N`, `max=N`, `increment=N` (по умолчанию 2, может быть отрицательным), `pattern=блоб`, `pattern_offset=N` |
| `dht_dn` | D | `dn=N` (3) — только payload `dht` |

Для QUIC и прочего UDP основной приём — `fake` с блобом `quic_initial_*`
и `repeats=N`. Fooling по TTL на UDP опасен: ICMP time-exceeded возвращается
клиенту, Safari/Network.framework закрывают сокет. Для QUIC TTL не
используем, мусорный Initial сервер и так отбросит.

## 5. zapret-auto.lua — оркестрация

### 5.1 `circular` — ротация стратегий по неудачам

```
--out-range=-s34228 --in-range=-s5556 --lua-desync=circular[:fails=3][:time=60][:hostkey=…][:nld=N][:reqhost][:key=…][:failure_detector=…][:success_detector=…][+арги детекторов]
--in-range=x
--payload=tls_client_hello
--lua-desync=fake:blob=fake_default_tls:tcp_md5:strategy=1
--payload=all --in-range=x --out-range=a --payload=tls_client_hello
--lua-desync=multidisorder:pos=1,midsld:strategy=2
```

- Каждый подчинённый инстанс несёт `strategy=N`. Номера идут с 1 **без
  пропусков** (иначе error). Ротация начинается со стратегии 1.
- `final` на инстансе стратегии N останавливает ротацию, когда до неё дошли:
  проверка неудач идёт только при `hrec.final~=hrec.nstrategy`. Значит,
  `final` на стратегии 1 отключает ротацию совсем. Автотюнер `final` не
  ставит, лучшую стратегию кладёт первой.
- Фильтры `--payload`/`--in-range`/`--out-range` действуют до следующего
  такого же фильтра, а подчинённые инстансы сохраняют свои. Стратегия без
  своих фильтров унаследует фильтры предыдущей, поэтому перед ней ставится
  сброс к умолчаниям движка: `--payload=all --in-range=x --out-range=a`
  (nfqws.c: `payload_type=0` это all, `range_in` NEVER, `range_out` ALWAYS).
- `fails` (3) — порог неудач, `time` (60 с) — окно сброса.
- Состояние хранится per-host: ключ из `standard_hostkey` (`nld=N` режет до
  N-уровня, `reqhost` требует hostname, без hostname IP не используется).
- `key=строка` — имя таблицы внутри `autostate[hostkey]` (по умолчанию имя
  инстанса `func_instance`). Одинаковый `key` у нескольких оркестраторов даёт
  им общее хранилище хоста (в справке описан с v1.0.6, в коде есть и в 1.0.5.2).
- Детекторам нужны входящие (`--in-range=-s5556`, Windows: `--wf-tcp-in`).
- `standard_failure_detector`: `maxseq` (32768), `retrans` (3), `reset`,
  `inseq` (4096), `no_rst`, `no_http_redirect`, `udp_out` (4), `udp_in` (1).
- `standard_success_detector`: `maxseq` (32768), `inseq` (4096), `udp_out`,
  `udp_in`.

Для AutoTuner `circular` — **кандидат на экспорт**, а не средство поиска.
Поиск идёт перебором с явной проверкой. `circular` предлагается, когда для
группы доменов есть 2–3 разных рабочих стратегии, а разделить домены по
hostlist нельзя (например, CDN с меняющимися IP).

### 5.2 Прочие оркестраторы

| Функция | Аргументы |
|---|---|
| `repeater` | `instances=N` (1), `repeats=N`, `iff=cond`, `neg`, `stop`, `clear` |
| `condition` | `iff=cond`, `neg`, `instances=N` (все) |
| `per_instance_condition` | `instances=N`; у подчинённых `cond=fn`, `cond_neg` |
| `stopif` | `iff=cond`, `neg` |

iff-функции: `cond_true`, `cond_false`, `cond_random` (`percent=50`),
`cond_payload_str` (`pattern=строка`), `cond_tcp_has_ts`, `cond_lua`
(`cond_code=lua`).

## 6. zapret-obfs.lua и zapret-pcap.lua

- `wgobfs` (`secret`, `padmin`=0, `padmax`=16), `ippxor` (`ippxor`, `dataxor`,
  `rebuild`), `udp2icmp` (`ctype`, `ccode`, `stype`, `scode`, `dataxor`,
  `server`), `synhide` (`ghost`, `ghost6`, `synack`, `magic`, `x2`, `kind`,
  `opt`, `xorseq`). Двусторонние, нужна вторая сторона. AutoTuner их не
  предлагает.
- `pcap:file=имя[:keep]` пишет pcap. Нужен `--writable`. Мы пишем pcap
  своим tshark/dumpcap, поэтому это не используем.

## 7. Отладочные функции zapret-lib.lua

`luaexec:code=…`, `pass`, `pktdebug`, `argdebug`, `posdebug`,
`detect_payload_str`, `desync_orchestrator_example`. Утилиты `var_debug(t)`,
`deepcopy`. Функции `luaexec` и `posdebug` полезны в режиме «Анализ»:
показывают, куда реально попали маркеры.

## 8. Своя Lua-функция (если генератор её добавляет)

```lua
function zt_example(ctx, desync)
  if not desync.dis.tcp then instance_cutoff_shim(ctx, desync) return end
  if not payload_check(desync) or not direction_check(desync) then return end
  local dis = deepcopy(desync.dis)
  dis.payload = blob(desync, desync.arg.blob)
  apply_fooling(desync, dis)
  rawsend_dissect_segmented(desync, dis, desync.tcp_mss, desync.arg)
  -- nil = VERDICT_PASS, оригинал уходит
end
```

Правила:
- Префикс имён наших функций — `zt_`. Пользовательские скрипты (PLAN 4a.5)
  хранятся в базе как ресурс `LuaScript` и выгружаются файлом
  `zt-<имя>.lua`. Грузится после штатных (`--lua-init=@…/zt-<имя>.lua`).
- Имя своей функции не может совпадать с функцией каталога (включая
  iff-функции): `ResourceRules`/`LuaScriptCheck` отказывают. Две свои
  функции с одним именем в разных скриптах тоже запрещены.
- Validator принимает вызов своей функции только из **подтверждённого**
  пользователем скрипта (`ValidationContext.UserFunctions`); вызов функции
  из черновика — ошибка `func.unapproved`. Имена аргументов своей функции
  каталогом не проверяются, но `strategy`/`final`/`cond`, `dir`, `payload`,
  блобы (`blob`, `pattern`, `seqovl_pattern`, `fallback`) и подстановки
  `%x`/`#x` проверяются как у штатных. В argv файл скрипта обязан быть в
  `--lua-init`, иначе `func.user_notloaded`. Agent узнаёт функции
  загружаемого файла сам (`ValidateArgv(…, luaFunctions)`).
- Песочница: нет `os.execute`, `io.popen`, `package.loadlib`, `debug`, FFI.
  Нет `sleep`: всё асинхронное делается через `timer_set`. `error` в таймере
  удаляет таймер.
- Свои функции не экспортируются в keenetic и zapret-gui без их lua-файла.
  Экспортёр либо кладёт файл рядом и подключает его, либо подставляет
  эквивалент из штатных функций. По умолчанию генератор пользуется только
  штатными функциями.

## 9. Шаблоны, проверенные в поле (стартовые кандидаты генератора)

```
# HTTP
--filter-tcp=80 --filter-l7=http --out-range=-d10 --payload=http_req
  --lua-desync=fake:blob=fake_default_http:tcp_md5
  --lua-desync=multisplit:pos=method+2

# TLS: fake + multidisorder
--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello
  --lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000
  --lua-desync=multidisorder:pos=1,midsld

# TLS: seqovl без fooling
--payload=tls_client_hello --lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000

# TLS: дефолт nfqws2-keenetic, стратегия 1
--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up

# TLS: hostfakesplit
--lua-desync=hostfakesplit:host=ozon.ru:midhost=host-2:tcp_md5:tcp_ts_up

# QUIC
--filter-udp=443 --filter-l7=quic --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6

# WireGuard/STUN/Discord
--filter-l7=wireguard,stun,discord --payload=wireguard_initiation,stun,discord_ip_discovery
  --lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=2
```

## 10. Инварианты генератора (проверяются тестами)

1. Каждому `fake`, `rst`, `fakedsplit`, `fakeddisorder` и `hostfakesplit`
   положен хотя бы один fooling (`tcp_md5`, `tcp_seq`, `tcp_ack`+`tcp_ts_up`,
   `badsum`, `ip_ttl`/`ip_autottl`, ext-заголовок IPv6). Исключение — фейк,
   который сервер отбросит по сути (QUIC Initial с чужим DCID, нулевой UDP).
2. `tcp_ts` не используется, если `cond_tcp_has_ts` на профиле браузера
   ложен (Windows по умолчанию).
3. `multidisorder` с `seqovl`: значение seqovl меньше первой позиции split.
4. `tcpseg` всегда с двумя маркерами. `oob` — только с `--in-range=-s1` и без
   ресендеров в том же профиле.
5. `http_methodeol` идёт последней из http-функций.
6. Блобы, которые использует стратегия, объявлены или встроены (см.
   nfqws2-engine §9).
7. `wssize`, `synack`, `syndata`, `oob` — фаза 0. Их профиль не должен
   зависеть только от hostlist (или включается `--ipcache-hostname`).
