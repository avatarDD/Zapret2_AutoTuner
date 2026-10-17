# Zapret2_AutoTuner

Кроссплатформенное (Windows, Linux) приложение на C# для подбора рабочих
стратегий [zapret2](https://github.com/bol-van/zapret2) (nfqws2 / winws2) на ПК
с проверкой в реальных браузерах и экспортом в zapret2,
[nfqws2-keenetic](https://github.com/nfqws/nfqws2-keenetic) и
[zapret-gui](https://github.com/avatarDD/zapret-gui).

План — [docs/PLAN.md](docs/PLAN.md). Правила для разработки — [AGENTS.md](AGENTS.md).

## Сборка

Нужны .NET SDK 10 и Python 3 (для скрипта бандла).

```sh
dotnet build ZapretAutoTuner.slnx
dotnet test ZapretAutoTuner.slnx
# движок zapret2 закреплённой версии для своей платформы
python3 tools/bundle/bundle.py --rid linux-x64      # или win-x64, linux-arm64
dotnet publish src/ZapretAutoTuner.App -c Release -r linux-x64 --self-contained -o out
```

## Структура

| Путь | Что |
|---|---|
| `src/ZapretAutoTuner.Core` | модель, каталог функций zapret2, генератор, валидатор, экспорт |
| `src/ZapretAutoTuner.Agent` | привилегированный помощник: движок, firewall, захват |
| `src/ZapretAutoTuner.Protocol` | gRPC-контракт UI ↔ Agent |
| `src/ZapretAutoTuner.Probes` | пробы: DNS, curl, браузер |
| `src/ZapretAutoTuner.Tools` | бандл zapret2 и внешние инструменты |
| `src/ZapretAutoTuner.App` | интерфейс (Avalonia) |
| `third_party/zapret2` | lua и `protocol.c` бандлимой версии zapret2 (MIT), с ними сверяется каталог |
| `tools/bundle` | скачивание и проверка закреплённого релиза zapret2 |
