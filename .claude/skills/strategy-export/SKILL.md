---
name: strategy-export
description: Строгие форматы экспорта стратегий AutoTuner — нативный zapret2 (config NFQWS2_OPT с <HOSTLIST>, @config-файл, .cmd/.bat для winws2), nfqws2-keenetic 1.3.x (nfqws2.conf, lists, blobs, lua) и zapret-gui (импорт текстом, JSON стратегии, бэкап, REST API, пакет-«бандл»). Читать перед любой правкой экспортёров, импортёров и формы «Экспорт».
---

# Экспорт стратегий

Внутренняя модель AutoTuner (то, из чего экспортируем):

```
Solution
  profiles[]:              # порядок = порядок в движке
    name                   # [a-zA-Z0-9_-]{1,64}
    l4: tcp|udp
    ports: "80,443"        # формат --filter-tcp
    l7: [tls, http, ...]   # --filter-l7
    hostlist: name|null    # ссылка на HostList
    ipset: name|null
    actions[]:             # упорядоченные --payload/--in/out-range/--lua-desync
  hostlists{name: [domains]}
  ipsets{name: [cidr]}
  blobs{name: bytes}       # только НЕ встроенные; имя = идентификатор Lua
  lua_files[]              # штатные + (редко) zapret-autotuner.lua
  meta: {created, autotuner_version, zapret2_version, tested_profiles[], report_ref}
```

Общие правила для всех экспортёров:
1. **Профиль = одна строка аргументов без глобальных опций.** Глобальные
   (`--blob`, `--lua-init`, `--qnum`, `--user`, `--fwmark`, `--debug`,
   `--wf-*`) добавляет каждый экспортёр по правилам своей платформы.
2. Имена блобов, hostlist и ipset проверяются регулярками целевой
   платформы **до** записи (таблица §5).
3. Каждый экспорт сопровождается `README.txt` (что внутри, куда класть,
   как проверить) и отчётом проверки.
4. После генерации экспорт **разбирается обратно** своим же парсером, и
   результат сравнивается с моделью (round-trip тест). Для zapret-gui —
   эмуляцией `profile_import.convert` (Python-логику повторяем в C# и
   держим golden-тесты на примерах из репозитория zapret-gui).
5. Комментарии `#` пишутся только там, где формат их гарантированно
   поддерживает (§1.3, §2.2).

## 1. Нативный zapret2

### 1.1 Linux: файл `/opt/zapret2/config` (фрагмент)

zapret2 сам добавляет `--user`, `--fwmark=$DESYNC_MARK`, `--qnum` и
`--lua-init` для `zapret-lib.lua`, `zapret-antidpi.lua`, `zapret-auto.lua`
(`init.d/sysv/functions`: `NFQWS2_OPT_BASE`). Экспортируем только:

```sh
NFQWS2_ENABLE=1
NFQWS2_PORTS_TCP=80,443
NFQWS2_PORTS_UDP=443
MODE_FILTER=hostlist          # none|ipset|hostlist|autohostlist
NFQWS2_OPT="
--blob=zt_tls_wl:@/opt/zapret2/files/fake/zt_tls_wl.bin
--filter-tcp=443 --filter-l7=tls --hostlist=/opt/zapret2/ipset/zt-youtube.txt --payload=tls_client_hello --lua-desync=fake:blob=zt_tls_wl:tcp_md5 --lua-desync=multidisorder:pos=1,midsld --new
--filter-tcp=80,443 --filter-l7=http,tls <HOSTLIST> --payload=tls_client_hello --lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000 --new
--filter-udp=443 --filter-l7=quic <HOSTLIST_NOAUTO> --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6
"
```

Правила:
- Значение `NFQWS2_OPT` в двойных кавычках, без `"`, `$` и `` ` `` внутри
  (shell). Переводы строк допустимы, профили разделяет `--new`.
- `<HOSTLIST>` раскрывается в `--hostlist=zapret-hosts-user.txt`,
  `--hostlist=zapret-hosts.txt`, `--hostlist-exclude=…-exclude.txt` и при
  `MODE_FILTER=autohostlist` в `--hostlist-auto=…` с параметрами
  `AUTOHOSTLIST_*`. `<HOSTLIST_NOAUTO>` добавляет `zapret-hosts-auto.txt`
  как обычный список. Если `MODE_FILTER` не hostlist или autohostlist,
  маркеры заменяются пустотой.
- Собственные hostlist кладутся в `/opt/zapret2/ipset/zt-<name>.txt` и
  подключаются явным `--hostlist=`. Домены «общего» профиля дописываются в
  `zapret-hosts-user.txt` (идёт через `<HOSTLIST>`).
- Свои блобы — в `/opt/zapret2/files/fake/zt_*.bin` (≤ 16 KB). `--blob`
  ставится в начале `NFQWS2_OPT` до первого профиля.
- Порты `NFQWS2_PORTS_TCP/UDP` = объединение портов профилей. Порт, которого
  там нет, firewall не отправит в очередь.
- Экспорт содержит фрагмент config и инструкцию, а не целый файл. Мерж в
  существующий config делается **заменой только этих переменных**.

### 1.2 Windows: `winws2` .cmd / service

```bat
@echo off
cd /d "%~dp0"
winws2.exe @"%~dp0zt-config.txt"
```

`zt-config.txt` (@config, §2 nfqws2-engine: ≤ 16 KB, **без `#`**, без
`$(…)`):

```
--wf-tcp-out=80,443 --wf-udp-out=443
--lua-init=@lua/zapret-lib.lua --lua-init=@lua/zapret-antidpi.lua --lua-init=@lua/zapret-auto.lua
--blob=zt_tls_wl:@files/zt_tls_wl.bin
--filter-tcp=443 --filter-l7=tls --hostlist=lists/zt-youtube.txt --payload=tls_client_hello --lua-desync=fake:blob=zt_tls_wl:tcp_md5 --lua-desync=multidisorder:pos=1,midsld --new
--filter-udp=443 --filter-l7=quic --hostlist=lists/zt-youtube.txt --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6
```

- Пути относительные: `.cmd` делает `cd /d "%~dp0"`. Пути с пробелами —
  в одинарных кавычках.
- `--wf-*` выводятся из профилей (nfqws2-engine §3.2). Если есть `circular`
  или детекторы, добавляются `--wf-tcp-in` и `--wf-udp-in`.
- Служба: `sc create zt_winws2 binPath= "\"…\winws2.exe\" @\"…\zt-config.txt\"" start= auto`.
  Создание и удаление службы делается из UI с UAC, не в экспорте.
- Комплект: `winws2.exe`, `cygwin1.dll`, `WinDivert.dll`,
  `WinDivert64.sys`, `lua/`, `lists/`, `files/`, `.cmd`, `README.txt`.

### 1.3 Строка запуска

Однострочный argv (для копирования) — профили через `--new`, глобальные
впереди. Это же формат «args», который распознаёт zapret-gui.

## 2. nfqws2-keenetic (1.3.x)

Пакет: `/opt/etc/nfqws2/nfqws2.conf` (shell, `source`-ится init-скриптом
`/opt/etc/init.d/S51nfqws2`), `lists/`, `blobs/`, `lua/`. Бинарь —
патченный nfqws2 с `--fastpath-workaround`.

### 2.1 Переменные

| Переменная | Что кладём | Ограничения |
|---|---|---|
| `ISP_INTERFACE` | **Не трогаем** (у пользователя своё, например `eth3`, `ppp0`, `nwg1`) | Несколько через пробел → init добавит `--bind-fix4/6` |
| `NFQWS_BASE_ARGS` | `--fastpath-workaround=auto`, `--lua-init=@/opt/etc/nfqws2/lua/…` (lib, antidpi, auto), все `--blob=имя:@/opt/etc/nfqws2/blobs/имя.bin` | **`--new` запрещён** |
| `NFQWS_ARGS` | Основной TCP-профиль (HTTP/HTTPS) | `--new` запрещён. Init сам добавит `$NFQWS_EXTRA_ARGS` (режим списков) |
| `NFQWS_ARGS_QUIC` | QUIC-профиль | `--new` запрещён. Получает `$NFQWS_EXTRA_ARGS` |
| `NFQWS_ARGS_UDP` | Прочий UDP (STUN, WG, Discord, игры) | `--new` запрещён. **Не получает списков** — фильтр только портами и l7 |
| `NFQWS_EXTRA_ARGS` | `$MODE_LIST` / `$MODE_ALL` / `$MODE_AUTO` | По умолчанию `$MODE_AUTO` |
| `NFQWS_ARGS_IPSET` | `--ipset=…/ipset.list --ipset-exclude=…/ipset_exclude.list` | Если не пусто, init добавит копию QUIC и TCP профиля с ipset и `--ipset-ip=0.0.0.0` |
| `NFQWS_ARGS_CUSTOM` | **Всё, что не влезает** в 3 профиля: дополнительные профили через `--new` | Единственное место, где `--new` разрешён. Идёт **первым** |
| `TCP_PORTS` / `UDP_PORTS` | Объединение портов профилей. **Диапазоны через `:`** (`590:600`), не `-` | Это порты iptables. Порт вне списка не дойдёт до nfqws2 |
| `IPV6_ENABLED`, `POLICY_NAME`, `POLICY_EXCLUDE`, `LOG_LEVEL`, `LOG_DEBUG_PATH`, `NFQUEUE_NUM` (300), `USER` (nobody), `CONFIG_VERSION` (1) | Не трогаем, берём значения пользователя или дефолт | |

Режимы:
```
MODE_LIST="--hostlist=/opt/etc/nfqws2/lists/user.list"
MODE_ALL="--hostlist-exclude=/opt/etc/nfqws2/lists/exclude.list"
MODE_AUTO="$MODE_LIST --hostlist-auto=/opt/etc/nfqws2/lists/auto.list --hostlist-auto-debug=/opt/var/log/nfqws2.log $MODE_ALL"
```

### 2.2 Итоговый порядок профилей (`_startup_args` в `etc/init.d/common`)

```
--user=$USER --qnum=$NFQUEUE_NUM [--fastpath-workaround=auto] $NFQWS_BASE_ARGS [--bind-fix4 [--bind-fix6]]
[$NFQWS_ARGS_CUSTOM --new]
[$NFQWS_ARGS_UDP --new]
[$NFQWS_ARGS_QUIC $NFQWS_ARGS_IPSET --ipset-ip=0.0.0.0 --new]   # если IPSET не пуст
[$NFQWS_ARGS_QUIC $NFQWS_EXTRA_ARGS --new]
[$NFQWS_ARGS $NFQWS_ARGS_IPSET --ipset-ip=0.0.0.0 --new]        # если IPSET не пуст
$NFQWS_ARGS $NFQWS_EXTRA_ARGS
```

Следствия для экспортёра:
- В `NFQWS_ARGS` и `NFQWS_ARGS_QUIC` может быть **один** профиль. Все
  hostlist-профили, кроме «общего», уходят в `NFQWS_ARGS_CUSTOM` со своими
  `--hostlist=/opt/etc/nfqws2/lists/zt-<name>.list` — тогда они проверяются
  раньше общих.
- «Общая» стратегия → `NFQWS_ARGS` (TCP) и `NFQWS_ARGS_QUIC`. Её домены —
  в `lists/user.list` (режим `MODE_LIST` или `MODE_AUTO`).
- Внутри `NFQWS_ARGS` можно несколько `--payload` блоков (TLS и HTTP в одном
  профиле), как в дефолтном конфиге.
- Значения многострочные в двойных кавычках. Init разворачивает их без
  кавычек, слова-комментарии `# …` попадают в argv и игнорируются getopt
  как позиционные. Поэтому **в комментариях нельзя слов, начинающихся с `-`**
  — они станут опциями. Пишем комментарии только формата `# Strategy N` /
  `# zt <name>`, из букв и цифр.
- Значения не содержат `"`, `$`, `` ` `` (это shell, `source`).
- Блобы: `blobs/<имя>.bin`, объявление в `NFQWS_BASE_ARGS`. В штатной
  поставке уже есть `tls_clienthello` и `quic_initial` (их байты равны
  `tls_clienthello_www_google_com.bin` / `quic_initial_www_google_com.bin`) —
  используем эти имена, если подходит.
- Встроенные `fake_default_*` доступны и без объявления.
- Lua: штатные файлы уже в `/opt/etc/nfqws2/lua/`. Свои — только при
  необходимости, `lua/zapret-autotuner.lua` + строка в `NFQWS_BASE_ARGS`.
- Версию lua пакета сверяем по `NFQWS2_COMPAT_VER_REQUIRED` (сейчас 6).

### 2.3 Поставка

Два варианта на форме:
1. **Файлы**: zip с `nfqws2.conf` (полный, с подставленными нашими
   переменными и дефолтами пакета для остальных), `lists/*.list`,
   `blobs/*.bin`, `README.txt` (scp на роутер, `S51nfqws2 restart`).
2. **Патч-фрагмент**: только наши переменные и инструкция «заменить эти
   строки». Это для тех, у кого конфиг уже настроен.

Прямая заливка по SSH — функция «Отправить на роутер» (с подтверждением,
бэкапом `nfqws2.conf.bak` и откатом, если сервис не поднялся).

## 3. zapret-gui

zapret-gui (avatardd/zapret-gui) — веб-GUI на роутере, по умолчанию
`http://<router>:8080`, опционально Basic-auth (`gui.auth_*`). Внутри движок
zapret2 в `/opt/zapret2` (lua `lua/`, блобы `files/fake/`, hostlist
`lists/`, ipset `ipset/`, очередь 300).

### 3.1 Импорт текстом (без доработок GUI, работает сейчас)

`POST /api/strategies/import` с `{"text": "…"}` (≤ 64000 символов), в UI —
«Стратегии → Импорт». Ответ открывается в редакторе, **сохранение делает
пользователь**. `core/profile_import.convert`:

- Тип определяется по переменным: `NFQWS2_OPT` → zapret2;
  `NFQWS_ARGS*`, `NFQWS_EXTRA_ARGS`, `NFQWS_BASE_ARGS`, `ISP_INTERFACE` →
  keenetic; `NFQWS_OPT` → zapret1 (отказ); `--lua-desync`/`--filter-` в
  тексте → args.
- Удаляются опции движка: `--user`, `--uid`, `--qnum`, `--fwmark`,
  `--daemon`, `--pidfile`, `--writable`, `--writeable`, `--intercept`,
  `--dry-run`, `--debug=@файл`.
- Удаляются маркеры `<HOSTLIST>`, `<HOSTLIST_NOAUTO>` (списки подставит
  режим фильтра GUI).
- Пути переписываются: `--lua-init=@…/x.lua` → `@lua/x.lua`,
  `--blob=n:@…/f.bin` → `n:@bin/f.bin`, `--hostlist=…/f` → `lists/f`,
  `--ipset=…/f` → `lists/f` (резолвится в ipset_path). Если файла на
  роутере нет, выдаётся предупреждение.
- Текст режется по `--new`. Части без `--lua-desync` (только объявления)
  переносятся в первый профиль. Части только со списками добавляются ко
  всем профилям.
- **Файлы списков, блобов и lua не передаются.** Их надо создать в GUI
  отдельно.

Экспортёр «zapret-gui (текст)» формирует **keenetic-подобный** или
`NFQWS2_OPT` текст с путями вида `/opt/zapret2/lists/zt-x.txt` и
`/opt/zapret2/files/fake/zt_x.bin`, чтобы после конвертации ссылки стали
`lists/zt-x.txt` и `@bin/zt_x.bin`. К тексту прилагаются инструкции «создайте
списки X, Y и блоб Z» и сами файлы.

### 3.2 JSON стратегии (через API, без доработок GUI)

`POST /api/strategies`:

```json
{
  "id": "zt_youtube_2026_10_17",
  "name": "AutoTuner: YouTube + Discord",
  "description": "Подобрано Zapret2_AutoTuner 0.1 …",
  "version": 1,
  "type": "combined",
  "profiles": [
    {"id": "p1", "name": "TLS youtube", "enabled": true,
     "args": "--filter-tcp=443 --filter-l7=tls --hostlist=lists/zt-youtube.txt --payload=tls_client_hello --lua-desync=fake:blob=zt_tls_wl:tcp_md5 --lua-desync=multidisorder:pos=1,midsld"}
  ]
}
```

- `id` → `[a-zA-Z0-9_-]` (иначе символы заменяются на `_`), не должен
  совпадать со встроенной стратегией (иначе 409). `name` и `profiles`
  обязательны, у каждого профиля есть `id` и `args`.
- `args` — строка **без** `--new`. Один профиль GUI — один профиль nfqws2.
  Пути — в плейсхолдерах GUI: `@lua/`, `@bin/`, `lists/` (для `--ipset`
  резолвится в ipset_path).
- Глобальные `--blob` можно положить в args первого профиля (GUI так же
  поступает при импорте) или не класть вовсе: реестр блобов GUI сам
  объявит блобы, загруженные через «Блобы», по имени.
- Перед этим: `POST /api/hostlists/create {"name"}` + `PUT
  /api/hostlists/<name> {"domains":[…]}`. Имя `[a-zA-Z0-9_-]{1,64}`, не
  `other`, `other2`, `netrogat`, не из пространства ipset. Аналогично
  `/api/ipsets/create`, `/api/ipsets/<name>` (имя по `IPSET_NAMESPACE_RE`:
  `ipset-*`, `my-ipset*`, `*-ipset`). `POST /api/blobs {"name","hex"}` (имя —
  идентификатор Lua, не встроенное, 409 если существует).
- Применение: `POST /api/strategies/<sid>/apply`. Проверка:
  `POST /api/strategies/<sid>/validate`. Из AutoTuner — **только по
  явной кнопке** пользователя.
- Ещё есть MCP-сервер `POST /api/mcp` (Bearer-токен) с инструментами
  стратегий, списков и блобов. Его можно использовать вместо REST, если
  токен выдан.

### 3.3 Бэкап zapret-gui (файл, без сети)

```json
{"format": "zapret-gui-backup", "format_version": 1, "created_at": 1760000000,
 "app_version": "…", "strategies": [ {…JSON стратегии…} ],
 "hostlists": [ {"name": "zt-youtube", "domains": ["youtube.com", "googlevideo.com"]} ]}
```

- Секции `settings`, `singbox`, `mihomo` **не включаем**: восстановление
  `settings` перезапишет конфиг пользователя.
- Встроенные hostlist (`other`, `other2`, `netrogat`) при восстановлении
  пропускаются, поэтому в них не пишем.
- **Блобов, ipset и lua в бэкапе нет** — это ограничение формата (см. §4).
- Пользователь загружает файл в «Бэкап → Восстановить» и выбирает секции
  strategies и hostlists.

### 3.4 Каталожная секция (INI)

zapret-gui читает каталоги `catalogs/*.txt` (INI-секции стратегий) и
отдаёт `/api/strategies/<sid>/export-catalog`. Формат см. `catalogs/README.md`
в zapret-gui. Экспортёр «для каталога» нужен для публикации стратегий в
репозиторий GUI. Это вторичная функция.

## 4. Доработки zapret-gui, которые нужны AutoTuner (отдельный PR в zapret-gui)

1. **Импорт бандла** `zapret-autotuner-bundle` v1 — один файл со
   стратегией, hostlist, ipset, блобами (base64) и lua:
   ```json
   {"format": "zapret-autotuner-bundle", "format_version": 1,
    "generator": {"name": "Zapret2_AutoTuner", "version": "0.1.0"},
    "zapret2_compat": 6,
    "strategy": {…JSON стратегии…},
    "hostlists": [{"name": "zt-youtube", "domains": [...]}],
    "ipsets": [{"name": "zt-ipset", "cidrs": [...]}],
    "blobs": [{"name": "zt_tls_wl", "base64": "…"}],
    "lua": [{"name": "zapret-autotuner.lua", "text": "…"}],
    "report": {"tested_at": "…", "targets": [...], "client_profiles": [...]}}
   ```
   Эндпоинт `POST /api/strategies/import-bundle` и вкладка UI. Валидация
   через существующие менеджеры (hostlist, ipset, blob, lua, strategy).
   Конфликт имён: спросить «заменить / переименовать». Ничего не
   применяется без подтверждения.
2. Ответ `POST /api/strategies/import` расширить полем `missing_files`
   (какие списки, блобы и lua нужно создать). AutoTuner показывает это
   пользователю.
3. Секция `blobs` (и `ipsets`) в бэкапе — по желанию, тот же формат.
4. (Опционально) «Обратная связь»: эндпоинт статистики стратегии
   (успехи/неудачи `circular`, autohostlist), чтобы AutoTuner мог показать,
   как стратегия работает на роутере, и предложить доподбор.

До слияния этих доработок AutoTuner экспортирует §3.1/§3.2/§3.3 и честно
пишет, какие файлы создать вручную.

## 5. Регулярки и лимиты целевых платформ (сводка)

| Сущность | zapret2 | keenetic | zapret-gui |
|---|---|---|---|
| Имя блоба | `[A-Za-z_][A-Za-z0-9_]*`, не Lua-keyword | то же | то же, не встроенное |
| Размер блоба | ≤ 16 KB | ≤ 16 KB | ≤ 16 KB |
| Имя hostlist | файл, любое | файл `*.list` | `[a-zA-Z0-9_-]{1,64}`, не other/other2/netrogat, не ipset-имя |
| Имя ipset | файл | `ipset.list`, `ipset_exclude.list` | `IPSET_NAMESPACE_RE` |
| Имя стратегии / профиля | — | — | id `[a-zA-Z0-9_-]` |
| `--new` | между профилями | только в `NFQWS_ARGS_CUSTOM` | нельзя в args профиля |
| Комментарии | в `config` (shell) — да; в @config — **нет** | `# слова` без `-…` | нет |
| Диапазон портов (firewall) | `NFQWS2_PORTS_*`: `a-b` | `TCP_PORTS`/`UDP_PORTS`: `a:b` | настройки GUI |
| Опции движка | добавляет init | добавляет init | вырезает GUI |
