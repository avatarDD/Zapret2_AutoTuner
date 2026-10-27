---
name: nfqws2-engine
description: "Строгий справочник движка zapret2 (nfqws2 / winws2 / dvtws2) v1.0.6: все ключи CLI, фильтры WinDivert, профили, диапазоны, пейлоады, лимиты, перехват трафика. Читать перед любым кодом, который собирает argv движка, запускает его или разбирает его вывод."
---

# nfqws2 / winws2 — движок zapret2 (v1.0.6)

Источник истины: `bol-van/zapret2` → `docs/manual.en.md`, `nfq2/nfqws.c`
(`exithelp()`), `nfq2/protocol.c`, `nfq2/params.h`. Если факт в этом файле
расходится с исходником той версии zapret2, которую мы бандлим, прав исходник.
Тогда исправь этот файл в том же PR.

Бандлим последний **релиз** zapret2 — v1.0.6 (`tools/bundle/zapret2.lock.json`,
исходники для сверки — `third_party/zapret2`). Новые правки из master
учитываем только после следующего релиза и обновления lock.

## 0. Жёсткие правила (нарушение = «тихий 0%» или падение движка)

1. **Только синтаксис nfqws2.** `--dpi-desync=…`, `--dpi-desync-split-pos=…`,
   `--dpi-desync-fooling=…` — это nfqws1/zapret1. Их не генерировать никогда.
   Все действия делаются через `--lua-desync=функция:арг=знач:…`.
2. **Порядок `--lua-init`:** `zapret-lib.lua` первым, затем
   `zapret-antidpi.lua`, затем `zapret-auto.lua`, затем остальные
   (`zapret-obfs.lua`, `zapret-pcap.lua`, свои). Порядок исполнения
   совпадает с порядком в argv.
3. **Совместимость lua и бинаря.** Первая строка `zapret-lib.lua` —
   `NFQWS2_COMPAT_VER_REQUIRED=6`. Бинарь v1.0.x имеет `LUA_COMPAT_VER=6`.
   lua и бинарь бандлятся **из одного релиза**. При расхождении в логе будет
   `Incompatible NFQWS2_COMPAT_VER`, и движок не стартует.
4. **Значения — всегда через `=`.** getopt_long_only принимает и
   `--opt value`, но лишнее значение через пробел молча игнорируется.
   Генератор пишет только `--opt=value`.
5. **`--blob=` — глобальная опция.** Все `--blob` и `--lua-init` ставятся
   до первого профильного ключа и до первого `--new`.
6. **Имя блоба — идентификатор Lua:** `[A-Za-z_][A-Za-z0-9_]*`, не
   зарезервированное слово, регистр важен. `my-fake` или `tls.google`
   вызовут «bad identifier» и выход при старте.
7. **Недоступный блоб.** Если `blob=имя` или `%имя` / `#имя` не резолвится,
   C-код (с 1.0.4) обрывает execution plan профиля до входа в Lua. Не
   отработает ни этот инстанс, ни следующие. `--dry-run` и `--intercept=0`
   этого **не ловят**. Блобы проверяет наш валидатор (см. §9).
8. **Один экземпляр на фильтр (Windows).** `--wf-dup-check=1` (по умолчанию)
   не даёт запустить второй winws2 с тем же WinDivert-фильтром. Тестовый
   прогон всегда сначала гасит предыдущий экземпляр.
9. **Linux: `--qnum` == номер очереди в правиле firewall.** Иначе пакеты
   уходят в очередь, которую никто не слушает. У нас по умолчанию это **300**,
   как у zapret2, zapret-gui и nfqws2-keenetic.
10. **`@config` — единственный аргумент.** Если argv[1] начинается с `@`
    (или `$`), остальные аргументы игнорируются. Подробно в §2.

## 1. Бинари и платформы

| Бинарь | ОС | Перехват | Примечание |
|---|---|---|---|
| `nfqws2` | Linux | NFQUEUE (iptables/nftables) | static-сборки в релизе: `binaries/linux-x86_64`, `linux-arm64`, `linux-mips*`, … |
| `winws2.exe` | Windows | WinDivert 2.2.2-A | Cygwin-сборка. Рядом лежат `cygwin1.dll`, `WinDivert.dll`, `WinDivert64.sys`, `killall.exe` (+ `ip2net`, `mdig`) |
| `dvtws2` | FreeBSD/OpenBSD | divert | Для AutoTuner не нужен |

- winws2 требует прав администратора (драйвер). После инициализации процесс
  понижает себя до Low Integrity, удаляет `Se*` привилегии и запрещает
  дочерние процессы. Значит, Lua не может писать файлы вне `--writable`.
- WinDivert **не перехватывает форвардинг** (ICS/NAT Windows). AutoTuner
  тестирует только трафик самого ПК.
- ARM64 Windows 11: x64 winws2 + неподписанный ARM64 `.sys` (test signing).
  Для MVP не поддерживаем, показываем понятную ошибку.
- Антивирусы часто ругаются на WinDivert. UI должен это объяснять, а не
  молча падать.
- Гипервизорный NAT (VMware/VirtualBox) ломает большинство техник. Нужен
  bridge. Детектируем VM и предупреждаем.

## 2. Формат передачи опций

- Командная строка: `nfqws2 --opt1=v --opt2 …`.
- Файл: `nfqws2 @/path/conf.txt`. Как читается файл (`config_from_file`):
  - размер ≤ **16384 байт** (`MAX_CONFIG_FILE_SIZE`), иначе ошибка;
  - `\n`, `\r`, `\t` заменяются на пробел, затем строка режется `wordexp()`
    с `WRDE_NOCMD`. Работают кавычки и `$VAR` из окружения. `$(…)` и
    обратные кавычки запрещены (ошибка);
  - **комментариев `#` в @config нет.** Файл склеивается в одну строку, и
    `#` в начале слова съест всё до конца файла. Генератор @config-файлов
    никогда не пишет `#`;
  - не поддерживается на Android и OpenBSD.
- Значения с пробелами или `$` в @config надо брать в одинарные кавычки.

## 3. Полный список опций

### 3.1 Глобальные и служебные

| Опция | Смысл / по умолчанию |
|---|---|
| `@file` / `$file` | Опции из файла (см. §2) |
| `--debug=0\|1\|syslog\|@file` (`android` на Android) | Лог. `--debug` без значения = 1 (консоль). `@file` обнуляется при старте |
| `--version` | Версия и выход |
| `--dry-run` | Проверить опции и доступ к файлам под сниженными правами. **Lua не грузит**, синтаксис Lua не проверяет. На Linux без `--qnum` завершается с «Need queue number (--qnum)», поэтому для проверки нужен любой номер очереди (перехвата нет) |
| `--comment=text` | Игнорируется (комментарий в argv) |
| `--intercept=0\|1` | `0` — выполнить `--lua-init` и выйти без перехвата. Ловит ошибки Lua-инициализации. Таймеры откладывают выход |
| `--qnum=N` | Linux: номер NFQUEUE |
| `--port=N` | BSD: divert-порт |
| `--daemon`, `--chdir[=path]`, `--pidfile=file` | Демонизация |
| `--user=name`, `--uid=uid[:gid,…]` | Не Windows. Сброс прав (по умолчанию uid `0x7FFFFFFF`) |
| `--bind-fix4`, `--bind-fix6` | Linux: фикс выбора интерфейса для сгенерированных пакетов (несколько WAN) |
| `--fwmark=int\|0xHEX` | Linux: метка сгенерированных пакетов, по умолчанию `0x40000000`. Firewall обязан пропускать помеченные мимо очереди |
| `--sockarg=…` | BSD-аналог fwmark |
| `--ctrack-timeouts=S:E:F[:U]` | Таймауты conntrack SYN:EST:FIN:UDP, по умолчанию `60:300:60:60` |
| `--ctrack-disable[=0\|1]` | Выключить conntrack (ломает почти все стратегии) |
| `--payload-disable[=type,…]` | Не распознавать указанные пейлоады (без значения — никакие) |
| `--server[=0\|1]` | Серверный режим: инвертирует направления (§7) |
| `--ipcache-lifetime=sec` | Время жизни ipcache, по умолчанию 7200, 0 — вечно |
| `--ipcache-hostname[=0\|1]` | Кэш IP→hostname (экспериментально, см. §8) |
| `--reasm-disable[=type,…]` | Выключить сборку `tls_client_hello` / `quic_initial` |

### 3.2 WinDivert-фильтр (только winws2)

| Опция | Смысл |
|---|---|
| `--wf-iface=idx[.sub]` | Числовой индекс интерфейса и подинтерфейса |
| `--wf-l3=ipv4\|ipv6` | L3, список через запятую. По умолчанию оба |
| `--wf-tcp-out=[~]p1[-p2],…` | Перехват исходящих TCP на порты. Плюс **автоматически** входящие SYN+ACK/FIN/RST для conntrack и HTTP-редиректы для autohostlist |
| `--wf-tcp-in=…` | Перехват **всех** входящих TCP с портов. Нужен детекторам `circular` и autohostlist (RST, http_reply, входящая sequence) |
| `--wf-udp-out=…` | Исходящие UDP на порты |
| `--wf-udp-in=…` | Входящие UDP с портов. Нужен UDP-детекторам (`udp_in`) и DNS→ipcache (`--wf-udp-in=53`) |
| `--wf-tcp-empty=0\|1` | Перехват пустых ACK. По умолчанию **0**: экономит ~50% CPU, но счётчик `n` перестаёт быть точным |
| `--wf-icmp-in/out=type[:code],…` | ICMP |
| `--wf-ipp-in/out=proto,…` | Сырые IP-протоколы |
| `--wf-raw-part=filter\|@file` | Частичный фильтр, объединяется по **OR**, можно несколько |
| `--wf-raw-filter=filter\|@file` | Частичный фильтр, объединяется по **AND**, только **один** (например, `ip.DstAddr==1.2.3.4`) |
| `--wf-raw=filter\|@file` | Полный фильтр, заменяет `--wf-tcp*`, `--wf-udp*`, `--wf-raw-part` |
| `--wf-filter-lan=0\|1` | Исключить не-глобальные адреса, по умолчанию 1. Для DNS на роутер нужен 0 |
| `--wf-filter-loopback=0\|1` | Исключить loopback, по умолчанию 1 |
| `--wf-dup-check=0\|1` | Запрет дублей экземпляров с одинаковым фильтром, по умолчанию 1 |
| `--wf-save=file` | Записать собранный фильтр в файл и выйти. Мы используем это в отладке и тестах генератора |
| `--ssid-filter=s1,…`, `--ssid-filter-neg` | Включать перехват только при подключённом Wi-Fi SSID |
| `--nlm-filter=net,…`, `--nlm-filter-neg`, `--nlm-list[=all]` | То же по сетям Network List Manager (имена или GUID) |

Лимиты: длина фильтра ≤ 65536 (`WINDIVERT_MAX`), каждая порт-строка ≤ 4096
(`WINDIVERT_PORTFILTER_MAX`).

Профиль `--filter-tcp=443` в winws2 **ничего не перехватывает сам**. Порт
обязан быть в `--wf-tcp-out` (или в raw-фильтре), иначе пакет до winws2 не
дойдёт. Генератор выводит `--wf-*` из объединения портов всех профилей:
TCP-порты → `--wf-tcp-out`, UDP-порты → `--wf-udp-out`. Если есть `circular`,
autohostlist или детектор, к этому добавляются `--wf-tcp-in` и `--wf-udp-in`.

Эталон тестового запуска из blockcheck2 (Windows):
`--wf-tcp-empty=1 --wf-l3=ipv4 (или ipv6) --wf-tcp-out=PORT --wf-raw-filter="ip.DstAddr==IP …"`
плюс exit-guard таймер. Тест ограничивается адресами цели.

### 3.3 Инициализация Lua

| Опция | Смысл |
|---|---|
| `--writable[=dir]` | Каталог для записи из Lua, путь в env `WRITABLE`. Один на процесс. На Windows без значения — `%USERPROFILE%\AppData\LocalLow\…` |
| `--blob=name:[+ofs]@file\|0xHEX` | Загрузить блоб. Файл ≤ **16 KB** (`MAX_BLOB_SIZE`), `+ofs` — смещение |
| `--lua-init=@file\|code` | Lua-код или файл. Поддерживает `.gz` (сначала ищет `file`, потом `file.gz`) |
| `--lua-gc=sec` | Принудительный GC, по умолчанию 60 с, 0 — выкл. На 1.0/1.0.1 был баг (60 мс) |

**Когда читаются Lua-файлы и где им лежать (Agent).** На Linux nfqws2
сначала сбрасывает root (`droproot`, по умолчанию uid `0x7FFFFFFF`), и только
потом проверяет и читает `--lua-init` файлы (`nfqws.c`, `nfq_main`: `droproot`
→ `test_list_files` → `lua_test_init_script_files` → `lua_init`). Файл в
домашнем каталоге пользователя (часто 0700/0750) движок не прочитает. На
Windows winws2 читает Lua с правами администратора, поэтому файл в
`%LOCALAPPDATA%`, который пользователь может переписать, — подмена между
проверкой и загрузкой. Поэтому Agent никогда не грузит пользовательский Lua с
места: UI передаёт содержимое (`lua_files` в `StartEngine`/`CheckEngineArgs`),
Agent один раз пишет копию в свой каталог (Linux `/run/zapret-autotuner/lua-<guid>`,
root, 0755, файлы 0644; Windows `%ProgramData%\ZapretAutoTuner-agent\lua-<guid>`,
оба уровня создаются защищёнными — только Administrators/SYSTEM, чужой
заранее созданный каталог отклоняется) и запускает движок с путём к копии.
Имя каталога случайное, внутри — маркер `owner` (pid и время старта Agent'а):
при старте Agent удаляет каталоги, чей владелец не жив. Хранилище ограничено
(32 MB, 256 папок; копии, которыми не пользуется ни один запущенный движок,
удаляются первыми). `--lua-init=@file` вне каталога движка и этого каталога
политика Agent'а отклоняет. Нет содержимого файла в запросе (UI не смог его
прочитать) — стадия `engine`, а не `policy`: стратегия тут ни при чём.

**Блобы читаются от root.** `--blob=name:[+ofs]@file` загружается при разборе
опций (`nfqws.c`: `load_blob_to_collection` из цикла getopt), то есть до
`droproot`, с правами root (на Windows — администратора). Симлинк (или junction)
в каталоге данных пользователя мог бы подсунуть движку root-only файл, а блоб
уходит в сеть. Поэтому блобы вне каталога движка идут тем же путём, что Lua:
UI передаёт содержимое (`lua_files`), Agent пишет копию в свой каталог,
`+ofs@` сохраняется; блоб из каталога данных напрямую политика не пропускает.

**Файлы, которые движок пишет.** `--debug=@file`, `--hostlist-auto`,
`--hostlist-auto-debug` движок до `droproot` открывает и отдаёт своему
пользователю (`ensure_file_access`). Они лежат в каталоге данных; путь, где по
дороге встречается симлинк, Agent отклоняет (проверка до старта — сужает окно,
но не закрывает его).

Встроенные блобы (без `--blob`):
- `fake_default_tls` — ClientHello Firefox без kyber, SNI `www.microsoft.com`;
- `fake_default_http` — GET на `www.iana.org`;
- `fake_default_quic` — `0x40` + 619 нулей (620 байт).

Готовые `.bin` лежат в `files/fake/` релиза: `tls_clienthello_www_google_com.bin`,
`tls_clienthello_vk_com(_kyber).bin`, `tls_clienthello_iana_org(_bigsize).bin`,
`tls_clienthello_gosuslugi_ru.bin`, `tls_clienthello_sberbank_ru.bin`,
`tls_clienthello_rutracker_org_kyber.bin`, `quic_initial_www_google_com.bin`,
`quic_initial_vk_com.bin`, `quic_initial_facebook_com(_quiche).bin`,
`quic_initial_rutracker_org(_kyber_1/2).bin`, `quic2_example_com.bin`,
`quic_short_header.bin`, `dtls_clienthello_w3_org.bin`, `stun.bin`,
`wireguard_initiation.bin`, `wireguard_response.bin`,
`discord-ip-discovery-with(out)-port.bin`, `dht_find_node.bin`,
`dht_get_peers.bin`, `http_iana_org.bin`, `zero_256/512/1024.bin`, `tls_alert.bin` и др.
**Имя файла ≠ имя блоба.** Блоб объявляется так:
`--blob=tls_google:@…/tls_clienthello_www_google_com.bin`.

### 3.4 Профили (multi-strategy)

| Опция | Смысл |
|---|---|
| `--new[=name]` | Начать новый профиль |
| `--skip` | Не использовать текущий профиль |
| `--name=name` | Имя профиля (видно в `--debug`) |
| `--template[=name]` | Профиль-шаблон (не рабочий). Без имени бесполезен |
| `--import=name` | Влить шаблон в текущий профиль |
| `--cookie[=str]` | Строка профиля для Lua (`desync.cookie`) |
| `--filter-l3=ipv4\|ipv6` | L3 |
| `--filter-tcp=[~]p1[-p2],…\|*` | TCP-порты |
| `--filter-udp=…\|*` | UDP-порты |
| `--filter-icmp=type[:code],…\|*` | ICMP / ICMPv6 |
| `--filter-ipp=proto,…` | IP-протокол (кроме tcp/udp/icmp) |
| `--filter-l7=proto,…` | L7-протокол (список в §5) |
| `--filter-ssid=…`, `--filter-ssid-neg` | Linux (если собрано): SSID на интерфейсе пакета |
| `--filter-mark=mark[/mask]` | Linux: по fwmark |
| `--ipset=file`, `--ipset-ip=list` | Включающий ipset (IPv4/IPv6, CIDR, gzip, можно несколько) |
| `--ipset-exclude=file`, `--ipset-exclude-ip=list` | Исключающий ipset |
| `--hostlist=file`, `--hostlist-domains=list` | Включающий hostlist (поддомены автоматически, gzip) |
| `--hostlist-exclude=file`, `--hostlist-exclude-domains=list` | Исключающий |
| `--hostlist-auto=file` | Autohostlist. Один на профиль, при импорте шаблона замена запрещена |
| `--hostlist-auto-fail-threshold=N` | 3 |
| `--hostlist-auto-fail-time=sec` | 60 |
| `--hostlist-auto-retrans-threshold=N` | 3 |
| `--hostlist-auto-retrans-maxseq=N` | 32768 |
| `--hostlist-auto-retrans-reset=0\|1` | 1 |
| `--hostlist-auto-incoming-maxseq=N` | 4096 |
| `--hostlist-auto-udp-out=N` | 4 |
| `--hostlist-auto-udp-in=N` | 1 |
| `--hostlist-auto-debug=file` | Глобальная. Лог срабатываний |

### 3.5 Внутрипрофильные фильтры (действуют до следующего переопределения)

| Опция | По умолчанию |
|---|---|
| `--payload=type,…` | `all` |
| `--out-range=…` | `a` |
| `--in-range=…` | `x` (входящие **не** идут в Lua!) |
| `--lua-desync=func[:arg[=val]]…` | Вызов Lua-инстанса |

`--payload`, `--in-range` и `--out-range` относятся ко **всем последующим**
`--lua-desync` до конца профиля или до нового значения.

## 4. Диапазоны `--in-range` / `--out-range`

Форматы: `mX-mY`, `mX<mY`, `-mY`, `<mY`, `mX-`, а также `a` и `x` одной
буквой. `-` — верхняя граница включительно, `<` — исключительно.
Разбор — `packet_range_parse` в `nfq2/filter.c`; в v1.0.6 переписана только
справка (`--out-range=<mode>[<int>][(-|<)<mode>[<int>]]`), разбор не менялся:
пустое начало (`-d10`, `<n2`) по-прежнему означает «с `a`», а одиночная
позиция без `-`/`<` допустима только для `a` и `x`.

| Режим | Счётчик |
|---|---|
| `a` | всегда |
| `x` | никогда |
| `n` | номер пакета (на winws2 при `--wf-tcp-empty=0` неточен) |
| `d` | номер пакета с данными |
| `b` | байтовая позиция переданных данных |
| `s` | TCP: относительный seq начала пакета (в пределах 2 GB) |
| `p` | TCP: относительный seq конца пакета (s + длина) |

Типовые значения: `--out-range=-d10` (первые 10 data-пакетов),
`--out-range=-s34228` и `--in-range=-s5556` для `circular`,
`--out-range=<n2` для UDP «только первый пакет».

**lua cutoff.** Когда все инстансы профиля вышли за верхнюю границу по
направлению или сами сделали cutoff, Lua для этого потока больше не
вызывается. Это экономит CPU. Linux-firewall дополнительно режет поток
через `connbytes` (zapret2: TCP out 20 / in 10, UDP out 5 / in 3; keenetic: 15).

## 5. Протоколы и пейлоады (`nfq2/protocol.c`)

`--filter-l7` (протокол потока):
`all unknown known http tls dtls quic wireguard dht discord stun xmpp dns mtproto bt utp_bt`

`--payload` (тип пейлоада пакета):
`all unknown empty known ipv4 ipv6 icmp http_req http_reply tls_client_hello
tls_server_hello dtls_client_hello dtls_server_hello quic_initial
wireguard_initiation wireguard_response wireguard_cookie wireguard_keepalive
wireguard_data dht discord_ip_discovery stun xmpp_stream xmpp_starttls
xmpp_proceed xmpp_features dns_query dns_response mtproto_initial
bt_handshake utp_bt_handshake`

- `known` — всё, кроме `empty` и `unknown`. `all` — всё.
- Протокол потока назначается по первому известному пейлоаду и остаётся
  до конца потока.
- Пакеты без данных — `empty`, нераспознанные — `unknown`.
- ICMP с вложенным IP-пакетом даёт `ipv4` / `ipv6`, остальные ICMP — `icmp`.
- Любое имя вне этих списков — ошибка разбора опций. Генератор берёт имена
  только из констант, которые сверены с `protocol.c` бандлимой версии.

## 6. Выбор профиля

1. Для нового потока профили проверяются **слева направо**. Побеждает
   **первый** подходящий. Если не подошёл ни один, выбирается профиль 0
   (пустой, ничего не делает).
2. Группы tcp/udp/icmp/ipp объединяются по OR. Если задана хоть одна группа,
   незаданные группы **запрещены**. `--filter-ipp=6` не матчит TCP, для
   этого есть `--filter-tcp=*`.
3. `--filter-l7` и hostlist в начале потока неизвестны. Когда становятся
   известны протокол или hostname, профиль перевыбирается («прыжок»,
   максимум 2). TLS/HTTP/QUIC обычно дают один прыжок, XMPP→TLS — два.
4. **Профиль с hostlist не выбирается, пока нет hostname.** Если стратегия
   должна работать с первого пакета (например, `synack_split`, `wssize`,
   `syndata` на SYN), её надо продублировать в профиль без hostlist или
   включить `--ipcache-hostname`.
5. С autohostlist профиль выбирается всегда, когда есть hostname:
   - host в exclude → ничего не делается;
   - host в include → стратегия применяется;
   - иначе идёт детекция неудач (§10).
6. Пустые hostlist-файлы без autohostlist = фильтра нет (матчит всё).
7. Порядок профилей важен. Специфичные (`--hostlist=youtube`) ставятся раньше
   общих (`--filter-tcp=443` без списка).

Шаблоны: простые параметры импортируются, только если заданы в шаблоне,
списковые дописываются в конец. Номер и имя шаблона не копируются.

## 7. Серверный режим и направление

- Клиент — сторона, пославшая первый SYN или первый UDP. `outgoing` — от
  клиента.
- `--server` инвертирует `in`/`out`, `desync.outgoing` и порт-фильтры.
  ipset всегда матчит удалённую сторону.
- Для AutoTuner (клиент на ПК) `--server` не используется.

## 8. ipcache

- IP+iface → входящий TTL. Нужен `autottl` с первого пакета.
- IP → hostname (`--ipcache-hostname`). Источники: L7 и DNS-ответы с порта
  53 по UDP (DoH не годится). На Windows нужны `--wf-udp-in=53
  --wf-filter-lan=0` (и `--wf-filter-loopback=0` при локальном DNS-прокси).
  Коллизии CDN возможны, это экспериментальная функция.

## 9. Лимиты и константы (`params.h`, `conntrack.h`)

| Константа | Значение | Следствие |
|---|---|---|
| `MAX_CONFIG_FILE_SIZE` | 16384 | @config не больше 16 KB |
| `MAX_BLOB_SIZE` | 16 KB | файл `--blob` не больше 16 KB |
| `BLOB_EXTRA_BYTES` | 128 | запас под tls_mod |
| `RAW_PACKET_QUEUE_DELAYED_MAX` | 64 | при сборке многопакетного CH/QUIC больше 64 пакетов → `rawpacket_queue failed !`, reasm отменён, payload = unknown |
| `DEFAULT_MSS` | 1220 | если MSS неизвестен |
| `RECONSTRUCT_MAX_SIZE` | 65536 | |
| `Q_MAXLEN` / `Q_RCVBUF` | 4096 пак. / 1 MB | NFQUEUE |
| `MAX_GIDS` | 64 | `--uid` |
| `IPCACHE_LIFETIME` | 7200 | |
| `LUA_GC_INTERVAL` | 60 | |
| fwmark по умолчанию | `0x40000000` | |
| conntrack | `60:300:60:60` | |

Валидатор AutoTuner перед запуском обязан проверить:
1. Каждое имя в `blob=`, `pattern=`, `seqovl_pattern=`, `fallback=`, `%x` и
   `#x` — встроенный блоб, объявленный `--blob`, или поле, которое создаёт
   предыдущий инстанс (например, `tls_client_hello_clone:blob=x`).
2. Каждая функция `--lua-desync` определена в загруженных lua (список
   строится парсингом `^function name(` в бандлимых файлах).
3. `--payload` и `--filter-l7` содержат только имена из §5.
4. Размер @config ≤ 16384, каждый блоб ≤ 16 KB.
5. `winws2 --dry-run`, затем `--intercept=0` (ловит ошибки Lua-init).

## 10. Autohostlist: детектор неудач

Неудача:
- TCP: ≥ `retrans-threshold` ретрансмиссий в пределах исходящего rseq
  `retrans-maxseq` (если `retrans-reset=1`, ретрансмиттеру отправляется RST);
- TCP: RST при входящем rseq от 1 до `incoming-maxseq`;
- TCP: `http_reply` 302/307 на абсолютный URL с другим SLD (DPI-заглушка;
  с v1.0.6 хост в URL заканчивается на `/`, `?` или `#`);
- UDP: отправлено ≥ `udp-out` пакетов, получено ≤ `udp-in`.

Успех: исходящий rseq > `retrans-maxseq`, входящий rseq > `incoming-maxseq`
или UDP-входящих > `udp-in`. Счётчик неудач сбрасывается при успехе или по
`fail-time`. При `fail-threshold` хост добавляется в autolist. Детекторам
нужны **входящие** пакеты (`--in-range`, на Windows `--wf-tcp-in`/`--wf-udp-in`).

## 11. Списки (hostlist / ipset)

- Одна запись на строку. Пустые строки и строки с `#`, `;`, `/` в начале
  игнорируются. gzip поддерживается.
- Поддомены матчатся автоматически. `*` не поддерживается. `^domain` —
  без поддоменов.
- `--hostlist-domains` и `--ipset-ip` — через запятую.
- Файлы перечитываются при изменении. SIGHUP — принудительная перезагрузка.
- Сигналы: SIGUSR1 — дамп conntrack, SIGUSR2 — счётчики autohostlist и
  ipcache.

## 12. Перехват на Linux (для тестов на Linux-ПК)

- nftables (POSTNAT по умолчанию у zapret2) или iptables (PRENAT): правила
  с `queue num 300 bypass`. Исключаются пакеты с меткой `0x40000000`.
  Выход ограничивается `connbytes` или `ct original packets`.
- Для теста на ПК достаточно цепочки OUTPUT/POSTROUTING на `oif` по
  dst-адресам цели. Входящие идут через INPUT/PREROUTING, если они нужны
  детекторам.
- sysctl: `net.netfilter.nf_conntrack_tcp_be_liberal=1` (иначе ядро режет
  out-of-window сегменты десинка), `net.netfilter.nf_conntrack_checksum=0`.
- Тестовые правила AutoTuner ставятся в **свою таблицу** (`inet ztuner`) и
  гарантированно удаляются при выходе (finally + обработчик сигналов +
  чистка при старте).

## 13. Отладка

- `--debug` (консоль) или `--debug=@file`. Видно выбор профиля,
  применённые инстансы и `DELAY desync until reasm is complete (#N)`.
- Отладочные Lua-функции: `pktdebug`, `argdebug`, `posdebug`, `luaexec`,
  `var_debug`.
- Типовые строки лога, которые разбирает AutoTuner:
  `Incompatible NFQWS2_COMPAT_VER`, `rawpacket_queue failed !`,
  `blob '…' unavailable`, `bad identifier`, `profile N (name)`, `lua cutoff`.
