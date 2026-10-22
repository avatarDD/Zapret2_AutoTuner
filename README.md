# Zapret2_AutoTuner

Кроссплатформенное (Windows, Linux) приложение на C# для подбора рабочих
стратегий [zapret2](https://github.com/bol-van/zapret2) (nfqws2 / winws2) на ПК
с проверкой в реальных браузерах и экспортом в zapret2,
[nfqws2-keenetic](https://github.com/nfqws/nfqws2-keenetic) и
[zapret-gui](https://github.com/avatarDD/zapret-gui).

Как пользоваться — [docs/USER.md](docs/USER.md). План — [docs/PLAN.md](docs/PLAN.md). Правила для разработки — [AGENTS.md](AGENTS.md).

## Сборка

Нужны .NET SDK 10 и Python 3 (для скрипта бандла).

```sh
dotnet build ZapretAutoTuner.slnx
dotnet test ZapretAutoTuner.slnx
# движок zapret2 закреплённой версии для своей платформы
python3 tools/bundle/bundle.py --rid linux-x64      # или win-x64, linux-arm64
dotnet publish src/ZapretAutoTuner.App -c Release -r linux-x64 --self-contained -o out
dotnet publish src/ZapretAutoTuner.Agent -c Release -r linux-x64 --self-contained -o out
```

Интеграционные тесты (настоящий движок через Agent) требуют прав root на
Linux (network namespace, nft/iptables) или администратора на Windows
(WinDivert). Без прав они пропускаются, в CI идут в отдельной джобе:

```sh
sudo -E env "PATH=$PATH" ZT_ZAPRET2_DIR=$PWD/runtimes/linux-x64/zapret2 \
  dotnet test tests/ZapretAutoTuner.Agent.Tests
```

Если Agent упал и оставил правила firewall, их снимает
`sudo ztuner-agent --cleanup --data-dir=<каталог данных>`.

## Структура

| Путь | Что |
|---|---|
| `src/ZapretAutoTuner.Core` | модель, каталог функций zapret2, генератор, валидатор, экспорт |
| `src/ZapretAutoTuner.Agent` | привилегированный помощник: движок, firewall, захват |
| `src/ZapretAutoTuner.Protocol` | gRPC-контракт UI ↔ Agent |
| `src/ZapretAutoTuner.Probes` | пробы: DNS, curl, браузер |
| `src/ZapretAutoTuner.Tools` | бандл zapret2 и внешние инструменты |
| `src/ZapretAutoTuner.App` | интерфейс (Avalonia) |
| `third_party/zapret2` | lua, `protocol.c` и `nfqws.c` бандлимой версии zapret2 (MIT), с ними сверяется каталог |
| `tools/bundle` | скачивание и проверка закреплённого релиза zapret2 |
| `tests/pcaps`, `tools/pcaps` | корпус пакетов и эталон tshark для разбора TLS, JA4, QUIC, RST |

## Релиз

Тег `v1.2.3` запускает `.github/workflows/release.yml`: тесты на Windows и
Linux, бандл zapret2 по закреплённому SHA-256, self-contained publish, пакеты
(Windows: установщик Inno Setup и portable zip; Linux x64/arm64: .deb, .rpm,
tar.gz), `SHA256SUMS.txt` и GitHub-релиз. AppImage в релизе 1 нет (см.
`docs/PLAN.md`, фаза 9). Ручной запуск
(workflow_dispatch) собирает пакеты без релиза.

Телеметрии нет и при сборке: статистика Avalonia.BuildServices отключена в
`Directory.Build.targets`.
