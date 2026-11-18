---
name: geneva
description: Второй движок обхода — geneva_c (avatarDD/geneva_c, v2.0.1, протокол proto 1, расширения --ext). Язык стратегий Geneva, команды run/evolve/check/library/db/fw, события JSON Lines, внешний пробник evolve, управляющий сокет, очереди и firewall, как AutoTuner его бандлит, запускает в Agent и показывает в UI и MCP. Читать перед любой правкой Geneva-кода, бандла geneva и MCP-инструментов geneva_*.
---

# geneva_c в AutoTuner

Факты берутся из исходников и `docs/` закреплённого релиза geneva_c
(`tools/bundle/geneva.lock.json`): `docs/STRATEGY.md` (язык),
`docs/PROTOCOL.md` (события и сокет), `docs/EVOLVE.md`, `docs/EVAL.md`,
`docs/INTEGRATION.md`, `docs/EXT.md` (расширения 2.0). Если skill расходится с ними, исправь skill.

## 1. Что это и когда

geneva_c — статический C-порт Geneva: применяет к пакетам стратегию на
языке Geneva (NFQUEUE на Linux, WinDivert на Windows) и умеет генетически
выводить стратегию. Это **отдельный движок**, а не формат nfqws2: строки
Geneva никогда не попадают в argv nfqws2/winws2 и в экспорт zapret2.

Windows договаривается об ECN, и её SYN несут флаги `SEC`, а не `S`:
деревья `[TCP:flags:S]` из библиотеки Geneva (найденные на Linux) на Windows
не срабатывают. Подбор на самом ПК это учитывает (geneva штрафует
несработавшие деревья).

Выбор движка — `BypassEngine {Nfqws2, Geneva}` в `GenevaState.Engine`
(страница «Движок», MCP `engine_select`). Одновременно перехватывает трафик
только один: geneva не стартует, пока идёт защита nfqws2, мастер или
эксперимент MCP (`GenevaController.Busy`), а Монитор не включает защиту,
пока работает обход или подбор geneva; мастер и локальная работа MCP —
тоже.

## 2. Язык стратегий (кратко)

```
strategy := out-forest "\/" in-forest
tree     := "[" proto ":" field ":" value [":" gas] "]-" [action] "-|"
action   := name ["{" params "}"] ["(" [left] "," [right] ")"]
```

Действия: `tamper`, `duplicate`, `fragment{tcp|ip:size:True|False}`, `drop`,
`sleep`, `trace`. Во входящем лесе — только `tamper` и `drop`. Пример:
`[TCP:flags:PA]-fragment{tcp:8:True}-| \/`.

Перед запуском (правило 4) строка проходит:
- `GenevaStrategyText.Problem` — одна печатная ASCII-строка до 2048 символов
  с `\/`;
- `geneva check --json -f -` в Agent (стратегии через stdin, а не argv).

## 3. Команды и argv (`GenevaArgv`)

| режим | argv | очередь |
|---|---|---|
| обход | `run [--ext] -s S -p PORTS -q 330 -c tcp:PORT -e - --stats-interval 2 --quiet [--ipset-exclude-ip F --hostlist-exclude-domains D]` | 330 |
| подбор | `evolve --probe external --host H --port P --population N --generations G --workers W --local-ports 30000 -q 331 --checkpoint C --db D --target external:H:P --top 10 -e - --quiet` + `--resume` или `--load-from seeds.txt` | 331 |

`--ext` (geneva_c 2.0) ставится, когда стратегия содержит x-действие или
триггер `[L7:|FLOW:|META:` (`GenevaStrategyText.NeedsExt`) или заданы
исключения пользователя (`GenevaRunSettings.ExcludeSubnets/ExcludeDomains`:
VPN, прокси, банк — их трафик ручной обход не трогает). `evolve --ext`
ставится сразу после `evolve`, если семена требуют расширений, и всегда,
если у geneva_c есть фича `ext_xgen` (`GenevaSearchSettings.XGen`): тогда
подбор сам делает x-действия и мутирует их параметры (`docs/EVOLVE.md`
geneva_c, «x-действия»), без неё x-действия семян только скрещиваются;
продолжение подбора помнит это в файле `<dir>/ext`. `geneva check --ext` — для x-строк
(`GenevaBundle.CheckAsync` делит список на обычные и расширенные). Сетка
zapret2-методов: `blockcheck --ext --print-grid --test tls12|http3 --level
quick` (`GenevaBundle.GridAsync`, равномерная выборка колонки geneva).

`W` — «Потоков подбора» (1–8, `GenevaSearchSettings.Workers`). Больше 1
только при фиче `external_workers` (geneva_c 1.2): Agent иначе ставит 1.
Каждый поток geneva шлёт свой `eval_request` с блоком портов
`30000+64*i`; контроллер отвечает на них параллельно (`Task.Run`), при
одном потоке — по-старому, последовательно.

Очереди zapret2: 300 (пробы), 310/311 (защита), 320 (починка) — geneva их не
трогает. Метка своих пакетов geneva — `0x20000000`.

Токен управляющего сокета передаётся только через env
`GENEVA_CONTROL_TOKEN`, никогда через argv. Порт сокета — свободный на
loopback. Команды сокета (allowlist в Agent): `status`, `stats`, `pause`,
`resume`, `reset_stats`, `set_strategy`, плюс `stop` при остановке.

Коды выхода: 0 — готово или остановлено, 7 — ресурс не заблокирован
(подбирать нечего), остальные — ошибки (тексты в `GenevaText.Exit`).

## 4. События (proto 1)

JSON Lines в stdout: `start`, `eval_request`, `eval`, `baseline`,
`generation`, `result`, `stats`, `ready`, `state`, `strategy`, `error`,
`exit`. Строка, начинающаяся с `{`, — событие (`GenevaEvent.Parse`), прочее —
лог. `proto` в `start` и `version --json` должен быть 1.

## 5. Подбор: успех — полная загрузка (правило 5)

`--probe external`: geneva сама не судит. На каждый кандидат она пишет
`eval_request {id, strategy, run, lports:"30000-30063"}`, перехватывает
только соединения с этих локальных портов, а UI делает L2 HttpProbe
(полная загрузка тела) с порта из блока (`GenevaArgv.LocalPort`) и отвечает
в stdin `{"id":N,"fitness":F,"detail":"..."}`. Первый запрос — с пустой
стратегией: это baseline. Если baseline загрузился, geneva выходит с кодом
7, и подбор не идёт.

Fitness (`GenevaFitness.FromProbe`) повторяет шкалу Geneva:
+400 полная загрузка, −360 reset/подмена (сертификат не того имени),
−400 нет соединения, −480 таймаут, оборванная загрузка или шейпер. Только
handshake — не успех.

Критерий страницы (`ProbeCriteria`, `PageCheck.RunAsync`) учитывает шейпер и
обрыв 16 КБ (dpi-diagnostics §2.16, §2.4). Его даёт классификатор
(`ClassifierVerdict.Criteria`) или узнаёт сама проба baseline: она меряет
скорость (`HttpProbeOptions.RateBytes`, окна по 500 мс, `RateShelf`) и, если
страница пришла полкой ниже четверти ёмкости канала (`LinkCapacity`, без
неё — ниже 64 КБ/с), считает baseline неуспехом (`ProbeError.Throttled`), а
каждой стратегии ставит `MinRate` (`RateShelf.Threshold`: 3 полки, не
больше половины канала, не меньше 1,5 полки). Страница короче 128 КБ
проверяется ещё раз с добивкой (`VolumePad`): обрыв на ней → все стратегии
судятся по 128 КБ с добивкой. Без этого подбор хвалил бы стратегию, которая
грузит маленькую страницу, а видео остаётся на полке.

Закрытие stdin = остановка: checkpoint сохранён в начале текущего
поколения, но geneva сообщает это как неудачную оценку (`exit` с кодом 1,
`reason: error`, без `result`). Контроллер, который сам попросил
остановку, показывает «остановлено». SIGTERM дал бы `reason: signal`, но
на Windows его нет. `resume` продолжает тот же поиск: geneva отказывает,
если изменилась популяция (её берём из сохранённого прогресса),
поколений можно добавить; seeds при resume не передаются.

Порт для пробы берётся по кругу из блока `lports`. Если порт не
привязывается (занят, TIME_WAIT, на Windows — диапазон, зарезервированный
Hyper-V), TcpConnector отдаёт `ProbeDetail.LocalPortPrefix` с кодом
ошибки (не локализованный текст ОС). Контроллер пробует другие порты, а
если весь блок недоступен, останавливает подбор, а не ставит стратегиям
выдуманный провал.

Ручной подбор на странице geneva (`EngineViewModel`): галочка «Добавить
методы zapret2» (при `ext_xact`) кладёт в семена `AutoCandidates.XTcp`
(для порта 80 — `XHttp`) после найденных и до библиотеки Geneva;
«Библиотека» показывает и TCP-методы zapret2 (`XTcp`, `XTcpWide`, `XHttp`,
`XTcpAny`) — ручной `run` работает только по TCP, QUIC и UDP остаются «Авто».
Смена списка «Не трогать» перезапускает работающий ручной `run`
(`GenevaController.Lists`, исключения задаются при старте).

## 6. Где что хранится

- Checkpoint и база оценок: защищённый каталог Agent
  (`ProgramData\ZapretAutoTuner-geneva`, `/var/lib/zapret-autotuner/geneva`
  0700), по подкаталогу на цель (sha256 ключа `host:port`).
- Прогресс для UI, найденные стратегии, выбор движка и активный обход
  (с флагом автозапуска): KB, ключ `geneva.state` (`GenevaState`,
  snake_case JSON). Сохраняется сразу при каждом изменении. Там же
  `imported` — стратегии, импортированные из файлов обмена (≤ 200,
  никогда не заменяют найденное, только добавляют сервисы), и `workers`.
- KB и все данные UI — в `<папка программы>/data` (`PortableData.Resolve`:
  env `ZT_DATA_DIR`, затем `data` рядом с exe, если туда можно писать,
  иначе старый `LocalAppData/ZapretAutoTuner`; старый каталог переносится
  при первом запуске, без `*.sock`/`*.token`). Каталоги Agent выше не
  переносятся: то, что работает с правами, лежит в защищённом месте.
- Стартовый набор — `Core/Geneva/Data/geneva-preset.json` (встроенный
  ресурс, `GenevaShare.Preset`).

### Обмен стратегиями (`Core/Geneva/GenevaShare.cs`)

Формат zapret-gui (`core/geneva_share.py`), один на оба проекта:
`{"format":"zapret-gui/geneva-strategies","version":2,"exported_at",
"items":[{"strategy","transport","services","fitness","ext","blobs"}]}`.
Версия 2 (zapret-gui тоже на geneva_c 2.0): у x-стратегии `"ext": true` и
`"blobs": ["z2_…"]` — фейки zapret2, которые она называет
(`GenevaBlobs.Refs`). Поля — подсказка; читатель считает их заново по
строке. Версия 1 и простой текст читаются как раньше. Имена фейков —
общий договор (`GenevaBlobs.NameOf` = `core/geneva_ext.blob_name`
zapret-gui: `z2_` + имя файла без расширения, только ASCII A–Z → a–z,
прочее вне `[a-z0-9_]` → `_`, ≤ 63), проверяется одним файлом в обоих
репозиториях (`tests/testdata/geneva-share/z2-blob-names.json`). Golden
обоих направлений: `zapret-gui-export-v2.json` (записан zapret-gui) и
`autotuner-export-v2.json` (записан `Build`, его читает zapret-gui).
Кандидаты «Авто» (`AutoCandidates.For`) пропускают общие и найденные
x-стратегии, чьих фейков нет среди загруженных Agent (`blobs` ответа
`AutoApply`): geneva с неизвестным блобом не стартует. Лимиты: 200
стратегий, 20 сервисов на стратегию, 512 КБ. Импорт принимает и простой
текст (одна стратегия на строку, `#` — комментарий); каждая строка
проходит `geneva check`. Экспорт объединяет сервисы по стратегии и
называет их доменом или протоколом (`DNS`, `wireguard`), никогда адресом.
Golden-тест — `tests/testdata/geneva-share/zapret-gui-export.json`,
записанный самим zapret-gui.

## 7. Бандл и права

- Бинарник — только из релиза avatarDD/geneva_c (правило 10):
  `tools/bundle/bundle_geneva.py` качает архив, сверяет его с SHA256SUMS и
  с пином в `geneva.lock.json`, пишет `runtimes/<rid>/geneva/bundle.json`.
  На Windows рядом лежат `WinDivert.dll` и `WinDivert64.sys` из того же
  архива; их SHA-256 закреплены отдельно (`file_sha256` в lock) по
  официальному релизу WinDivert (basil00/WinDivert v2.2.2), и бандл не
  собирается, если байты отличаются.
- Версия geneva в релизе — последняя опубликованная в avatarDD/geneva_c:
  `release.yml` (job `draft`) находит её через
  `tools/bundle/update_geneva_lock.py`, и каждый job `package` пинит в lock
  этот тег перед `bundle_geneva.py`. Скрипт сверяет каждый архив с
  SHA256SUMS релиза, а WinDivert — с уже закреплённым официальным релизом
  WinDivert (новый WinDivert пинится только вручную). Обновить lock в
  репозитории: `python3 tools/bundle/update_geneva_lock.py`; проверить, не
  отстал ли он: `--check`. Смена `proto` ловится в `bundle_geneva.py`
  (`geneva version --json` на нативном раннере) и требует правки кода.
- Agent копирует бандл в защищённую папку (`ProtectedBundle.CopyAndVerify`)
  и запускает geneva только оттуда.
- Правила firewall geneva (`inet geneva_<queue>`, цепочки
  `GENEVA_<queue>_*`) снимаются `geneva fw down -p 1 -q <queue>` при остановке,
  при выходе Agent и при восстановлении после аварии (`AgentState.GenevaQueues`).

## 8. MCP

Чтение: `geneva_status`, `geneva_library`, `geneva_check`,
`geneva_auto_status`. Управление: `engine_select`, `geneva_search_start`
(только цель из `targets_list`), `geneva_search_stop`, `geneva_run_start`
(ждёт «Да» пользователя в окне), `geneva_run_pause`, `geneva_run_stop`,
`geneva_auto_enable` (ждёт «Да»), `geneva_auto_disable`, `geneva_auto_reset`,
`geneva_auto_check_now`, `geneva_auto_priority` (important/auto/unimportant),
`geneva_auto_pin`, `geneva_auto_lists` (важные, неважные, исключения,
known_important, by_name).

## 9. Режим «Авто»

Пользователь включает один переключатель; дальше всё решает программа.
Код: `Core/Geneva/Auto/*` (наблюдение, книга сервисов, план групп,
кандидаты), `Tuning/Geneva/GenevaAuto.cs` (цикл), `AutoProbes.cs` (пробы),
Agent `GenevaManager.AutoApplyAsync` (gRPC `GenevaAutoApply`).

1. **Наблюдение.** Захват Agent (весь ПК) срезами по 15 с →
   `FlowAnalyzer` → `AutoObserver.Observe`. Пропускаются LAN, loopback,
   multicast и блок локальных портов подбора geneva. Ключи сервисов:
   `web:<регистрируемый домен>` (TLS/HTTP по TCP), `quic:<домен>`,
   `dns:<IP резолвера>`, `ep:<протокол>:<tcp|udp>:<ip>:<порт>` (WireGuard,
   OpenVPN по опкоду 7/10, DTLS, STUN, MTProto, неизвестное),
   `port:<tcp|udp>:<локальный порт>` (DHT по bencode `1:y1:q/r/e`).
2. **Оценка потока.** TCP: SYN без SYN-ACK ≥ 3 с → нет соединения; иначе
   `FlowVerdict` (RST не от сервера, зависание, обрыв 16 КБ). UDP: любой
   ответ — успех; без ответа ≥ 5 с — провал, если клиент спросил ≥ 2 раз
   (DNS — 1 раз). DHT: ответ любого узла — успех.
3. **Подозрение** (`AutoBook.Evaluate`): в окне 10 мин нет ни одного успеха и
   провалов ≥ 3 (TCP), ≥ 2 (UDP), ≥ 20 (DHT). QUIC при работающем TCP того
   же сайта — `Fallback`, ничего не делается. Второй источник — детектор
   geneva (geneva_c с фичами `ext` и `ext_auto`): Agent держит рядом с
   группами `run --ext --ext-auto observe -s "\/" -p 9` (трафик не
   меняет; Linux — очередь 349, NFLOG-правила geneva снимаются при выходе;
   Windows — `--priority 1000`, хэндл SNIFF выше всех групп), режим раз в
   цикл читает `ext_status` (`GenevaAuto.Detected`). Ключ `impaired` с
   классом `THROTTLE` (полка скорости) или `FREEZE_N` (замирание на
   8–64 КБ) — то, что 15-секундный срез не видит, — делает подозреваемым
   сайт по имени (`host`) или сервис по адресу (`ip`), если тот не
   применён и не в подборе (`AutoBook.Detect`, одна отметка в минуту);
   `capacity` питает `LinkCapacity`. Остальные классы детектора режим
   оставляет своим срезам. Лечение geneva (`--ext-auto apply/propose`) не
   используется: оно меняет пакеты тех же потоков, что и группы, и судит
   по рукопожатию, а не по полной загрузке (правило 5).
4. **Подтверждение без обхода** (правило 5): сайт — L2-загрузка страницы с
   увиденного IP с его именем; прочее — повтор первых пакетов программы
   (`ReplayProbe`, 2 попытки). Страница проверяется `PageCheck`: полка
   скорости или обрыв на добивке — тоже блокировка, и найденный критерий
   (`AutoService.Criteria`) получает подбор этого сервиса. Нет соединения → `IpBlocked` (пауза 6 ч,
   пакетами не обойти). Открылось → `NotBlocked` (пауза 1 ч). WireGuard,
   Discord, ICE и DHT не повторяются (anti-replay, сессия): блокировка
   признаётся, если подозрение держится два среза подряд. Повторяются и
   хранятся только рукопожатия `AutoObserver.ReplayableApps` (tls, quic,
   dtls, dns, stun, openvpn, mtproto): открытый HTTP (cookies) и
   неизвестные протоколы (могут нести логин) не сохраняются и не
   отправляются повторно; такие сервисы судятся по их собственному трафику.
5. **Подбор** (по одному сервису; очередь `AutoBook.Queue`: важность
   `AutoPriorities.Effective`, затем деградировавшие, затем сайт, DNS, QUIC,
   сервер, свежесть и трафик; см. п. 10): сначала до 12 известных стратегий на трафике самого сервиса
   (`AutoCandidates.For`, по порядку: общие стратегии, в которых назван
   этот сервис (импорт, затем стартовый набор), стратегии работающих
   групп, найденные раньше, прочие общие и шаблоны; у DNS шаблоны идут
   раньше прочих общих — все проходят `geneva check`); для сервиса с пробой —
   затем `evolve` (популяция 20, 10 поколений; при повторе — продолжение с
   +5 поколений), `--protos` по транспорту (`TCP`, `UDP,IP`,
   `UDP,IP,DNS,DNSQR`), проба страницы или повтор с локального порта
   (`--probe external`, ключ цели `replay:`). Лучшие 3 найденные стратегии
   ещё раз проверяются на трафике сервиса. **Широкий раунд:** после
   `AutoRules.WideAfter` (2) пустых подборов кандидатов до 40 (добавляется
   библиотека бандла по рейтингу), а законченный подбор с популяцией < 40
   начинается заново: популяция 40, 15 поколений, `--protos TCP,IP` для
   TCP, найденное — семенами. Продолжение подбора всегда идёт с теми
   `--protos`, что сохранены в прогрессе (иначе geneva откажет). Без пробы (WireGuard, DHT)
   успех — хотя бы один успешный поток программы за 50 с.
   С geneva_c 2.0 (`ext_xact`) к кандидатам добавляются x-стратегии
   (`AutoCandidates.XFor`): в обычном раунде — основные (`XTcp`, `XQuic`,
   для сайта только на 80 `XHttp`, для UDP `XUdp`, для DHT `XDht`, для
   прочего TCP `XTcpAny`), в широком — все клиентские x-действия
   (`XTcpWide`, `XQuicWide`: seqovl, tcpseg, fakeddisorder, tlsclone,
   repeat, rst, drip, ipfrag, syndata, oob, synack, wsize/wssize, все
   fooling, xwhen/xcutoff…) и фейки zapret2 по `AutoRules.FakesPerRound`
   (8) за раунд, каждый раунд следующие (`GenevaBlobs`: `files/fake/*.bin`
   бандла zapret2 → блобы `z2_<имя>` до 63 символов, по протоколу:
   ClientHello для сайтов, Initial для QUIC, WireGuard/STUN/DTLS/нули для
   UDP, DHT для DHT). Agent отдаёт каждому geneva с `--ext` все фейки
   (`GenevaManager.WithBlobs`: `--ext-blob z2_X:@файл` из проверенной
   копии zapret2, `FakeDir`) и называет их в ответе `AutoApply`
   (`blobs`): кандидаты берут имена только оттуда. `xsend{ipfrag}` всегда
   с `(drop,)`: иначе целый пакет уходит вслед за фрагментами. `Fits`
   пропускает триггеры `[FLOW:`, `[L7:`, `[META:` для любого транспорта.
   Затем в широком раунде — срез сетки zapret2 из `blockcheck
   --print-grid --max-ttl 0` (с autottl, без фиксированных TTL; 48 строк
   TCP, 13 QUIC; `tls12`, для сайта только на 80 — `http`; `tls13` —
   часть `tls12`): раунд N сдвигает срез, раунды вместе обходят всю сетку;
   строки проходят `Problem`, пробуются, но в семена подбора не идут.
   Первой пробуется стратегия семейства (`AutoBook.FamilyStrategy`). Пробная стратегия
   засчитывается после `AutoRules.TrialPasses` (2) успешных проверок подряд
   и, для сайта, повтора записанного ClientHello браузера (`WorksAsync`,
   `HandshakesAsync`); сайт хранит два ClientHello разной длины
   (`Replay`/`ReplayAlt`, например Chrome с Kyber и без).
6. **Применение.** Активные сервисы (`Applied`, `Degraded`) группируются
   по стратегии; ≤ 8 групп, одна `geneva run` на группу, очереди 340–347.
   Linux: `--firewall none` + правила в таблице `inet ztuner` через
   `FirewallManager.Replace("geneva-auto/", …)`: адреса и порты сервиса
   (DNS — tcp и udp 53; DHT — по исходному порту), первые 12 исходящих и
   6 входящих пакетов соединения, пропуск пакетов с меткой geneva
   `0x20000000`. Windows: нужна geneva_c с фичами `filter` и `set_filter`
   (`--filter-file`, `set_filter` при смене целей, `--first 12` при фиче
   `first`); иначе ответ `limited`, ничего не применяется; если `set_filter`
   не прошёл, группа перезапускается с новым фильтром. Сервис в подборе
   не применяется: две стратегии на одном пакете не судят ни одну. По той же
   причине пара «адрес + транспорт» (или локальный порт) достаётся только
   первой группе (`AutoPlan.Groups`: пробная, затем крупные): сайты за одним
   адресом CDN с разными стратегиями не делят пакеты. Пробная стратегия
   считается сработавшей, только если её группа запущена (`requested` в
   ответе Agent). **По имени** (geneva_c 2.0 с `ext`, `ext_profile`,
   `ext_lists`, `ext_l7`; на Windows ещё `filter`): кроме групп Agent
   держит один процесс `run --ext --ext-profile profiles.ini
   --ext-ipcache-hostname` (Linux — очередь 348, ключ правил
   `geneva-auto/~host` идёт последним; Windows — `--priority -100`) на
   TCP 80/443 (+ UDP 443 при `ext_crypto`), который не трогает адреса групп
   (`exclude-ip.txt`) и исключения пользователя, а сайтам применяет их
   стратегию по имени: профиль `[profile N]` = стратегия + `hostlist`
   (`AutoPlan.HostProfiles`, ≤ 24, домен — одному профилю, домены
   семейства — если у них нет своей судьбы). Так новый адрес CDN работает
   сразу. Файлы — в `StateDir/auto-host`, пишутся атомарно; при смене
   только списков — `reload_lists`, иначе перезапуск. Пустой hostlist в
   geneva_c значит «всё», поэтому профиль без доменов не пишется. Когда
   процесс по имени запущен (`reply.Host`), адрес web, общий для сайтов с
   разными стратегиями, из групп убирается, если все сайты на нём покрыты
   именами (`AutoPlan.ByNameCovers`: в профиле и только порты 80/443) —
   его ведёт процесс по имени; иначе адрес остаётся группам. Ответ
   `AutoApply` несёт `ext`/`by_name` и на пустой запрос: режим знает о
   x-действиях до первого применения. Ручной `run` с исключениями без
   `ext_lists` не стартует (обещание «не трогать» не нарушается молча).
   Группами «Авто» управляет только `AutoApply`: через
   `GenevaControl` им доступны лишь `status`, `stats` и `ext_status`.
7. **Мониторинг.** У применённого сервиса считаются только потоки после
   `AppliedAt`: провалы без успехов → `Degraded` → проверка с обходом →
   работает (`Applied`) или новый подбор. Ничего не найдено → `NotFound`,
   повтор через 1 ч, удваивая до 24 ч. Сервис без потоков 30 дней
   забывается (кроме применённых), адрес — через 7 дней.
8. **Состояние** — `geneva.state.auto` (включён ли режим, сервисы с
   адресами, стратегиями, счётчиками). Сохраняется при каждом переходе и
   раз в минуту; после перезапуска режим восстанавливается. Сервис,
   сохранённый «в подборе» (пропало питание, процесс убит), при загрузке
   становится `Blocked` и подбирается снова: сам подбор перезапуск не
   переживает, а `NextToSearch` берёт только `Blocked`. Списки
   пользователя (`AutoLists`) — в `GenevaState.Lists`, флаг «по имени» —
   `GenevaState.ByName`.
9. **Взаимоисключения.** «Авто» не стартует при защите nfqws2, мастере,
   опытах MCP и обходе geneva с одной стратегией; пока он работает, они
   ждут. Ручной подбор на странице занимает слот подбора — «Авто» ждёт.
10. **Важность** (`Core/Geneva/Auto/AutoPriorities.cs`, issue 28).
    `AutoPriority`: Important (метка пользователя, список «важные»,
    семейства `AutoFamilies` — YouTube, Discord, Telegram, WhatsApp,
    Instagram/Facebook, X — при `KnownImportant`), Normal (сайт, QUIC,
    DNS), Low (сервер), Background (локальный порт, «голый» пир: без имени,
    протокол не распознан, порт ≥ 10000; список «неважные»). Фоновый
    сервис, ждущий ≥ `StarvationStep` (30 мин), поднимается до Low.
    Важный заблокированный сервис прерывает подбор менее важного
    (`Preempting` → отмена подбора, сервис снова `Blocked`). Места в книге:
    пирам — не больше `MaxServices − ReservedPlaces`, вытесняются сначала
    фоновые и давно не виденные. Провалы на адресе, которого ещё нет в
    наборе применённого сервиса, не считаются деградацией (новый адрес CDN
    сначала добавляется в группу). «Закрепить» (`Pin`) — сервис не уходит
    в `Degraded`; «Проверить сейчас» (`CheckNow`) — подтверждение вне
    очереди; «Своя стратегия» (`TryStrategyAsync`) — пробуется как найденная
    и закрепляется. Список «исключения» (адреса, подсети, домены) убирает
    сервисы из «Авто» и передаётся ручному обходу.
