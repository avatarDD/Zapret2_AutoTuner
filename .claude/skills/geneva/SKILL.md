---
name: geneva
description: Второй движок обхода — geneva_c (avatarDD/geneva_c, v1.0.0, протокол proto 1). Язык стратегий Geneva, команды run/evolve/check/library/db/fw, события JSON Lines, внешний пробник evolve, управляющий сокет, очереди и firewall, как AutoTuner его бандлит, запускает в Agent и показывает в UI и MCP. Читать перед любой правкой Geneva-кода, бандла geneva и MCP-инструментов geneva_*.
---

# geneva_c в AutoTuner

Факты берутся из исходников и `docs/` закреплённого релиза geneva_c
(`tools/bundle/geneva.lock.json`): `docs/STRATEGY.md` (язык),
`docs/PROTOCOL.md` (события и сокет), `docs/EVOLVE.md`, `docs/EVAL.md`,
`docs/INTEGRATION.md`. Если skill расходится с ними, исправь skill.

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
| обход | `run -s S -p PORTS -q 330 -c tcp:PORT -e - --stats-interval 2 --quiet` | 330 |
| подбор | `evolve --probe external --host H --port P --population N --generations G --workers 1 --local-ports 30000 -q 331 --checkpoint C --db D --target external:H:P --top 10 -e - --quiet` + `--resume` или `--load-from seeds.txt` | 331 |

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
−400 нет соединения, −480 таймаут или оборванная загрузка. Только
handshake — не успех.

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

## 6. Где что хранится

- Checkpoint и база оценок: защищённый каталог Agent
  (`ProgramData\ZapretAutoTuner-geneva`, `/var/lib/zapret-autotuner/geneva`
  0700), по подкаталогу на цель (sha256 ключа `host:port`).
- Прогресс для UI, найденные стратегии, выбор движка и активный обход
  (с флагом автозапуска): KB, ключ `geneva.state` (`GenevaState`,
  snake_case JSON). Сохраняется сразу при каждом изменении.

## 7. Бандл и права

- Бинарник — только из релиза avatarDD/geneva_c (правило 10):
  `tools/bundle/bundle_geneva.py` качает архив, сверяет его с SHA256SUMS и
  с пином в `geneva.lock.json`, пишет `runtimes/<rid>/geneva/bundle.json`.
  На Windows рядом лежат `WinDivert.dll` и `WinDivert64.sys` из того же
  архива; их SHA-256 закреплены отдельно (`file_sha256` в lock) по
  официальному релизу WinDivert (basil00/WinDivert v2.2.2), и бандл не
  собирается, если байты отличаются.
- Agent копирует бандл в защищённую папку (`ProtectedBundle.CopyAndVerify`)
  и запускает geneva только оттуда.
- Правила firewall geneva (`inet geneva_<queue>`, цепочки
  `GENEVA_<queue>_*`) снимаются `geneva fw down -p 1 -q <queue>` при остановке,
  при выходе Agent и при восстановлении после аварии (`AgentState.GenevaQueues`).

## 8. MCP

Чтение: `geneva_status`, `geneva_library`, `geneva_check`. Управление:
`engine_select`, `geneva_search_start` (только цель из `targets_list`),
`geneva_search_stop`, `geneva_run_start` (ждёт «Да» пользователя в окне),
`geneva_run_pause`, `geneva_run_stop`.
