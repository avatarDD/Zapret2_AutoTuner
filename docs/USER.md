# Zapret2 AutoTuner — руководство пользователя

*English version below.*

## Установка

- **Windows 10/11 x64:** `ZapretAutoTuner-<версия>-win-x64-setup.exe` или
  portable-архив `…-portable.zip` (распаковать и запустить `ZapretAutoTuner.exe`).
- **Linux x64 и arm64:** `.deb` (Debian, Ubuntu), `.rpm` (Fedora, openSUSE)
  или `.tar.gz`. Нужны nftables (или iptables) и polkit (`pkexec`). AppImage
  нет: агент с правами root не может запуститься из её FUSE-образа.

Файлы можно сверить с `SHA256SUMS.txt` из релиза. Движок zapret2 внутри —
официальная сборка bol-van/zapret2 без изменений.

## Как пользоваться

1. **Главная → «Проверить блокировки».** Программа проверит популярные сайты и
   покажет светофор: зелёный — работает, жёлтый — частично, красный — блок.
2. **«Подобрать стратегию».** Впишите сайты (или нажмите готовый набор:
   YouTube, Discord, Telegram, Instagram) и нажмите «Начать». Программа
   определит тип блокировки, переберёт стратегии и проверит найденное полной
   загрузкой. Видно этап, процент, прошедшее и оставшееся время. Подбор
   можно остановить в любой момент.
3. **Экспорт.** Выберите, куда установить: этот компьютер, Keenetic
   (nfqws2-keenetic), zapret-gui, zapret2 на Linux/OpenWrt или просто строку
   аргументов. Без адреса роутера сохраняется файл. На роутер и в zapret-gui
   ничего не уходит без вашего «Да», а применение в zapret-gui — отдельная
   вторая кнопка.
4. **Монитор.** «Включить защиту» держит стратегию запущенной и следит за её
   сайтами. Если сайт перестал открываться, программа ищет исправление и
   спрашивает, применить ли его (или применяет сама, если вы это разрешили в
   настройках). Кнопка «Не работает сейчас» запускает починку сразу.
5. **Отчёты.** Если подобрать не вышло, «Собрать отчёт» сохранит архив для
   разбора: ваши IP скрыты, домены можно скрыть галочкой. Есть готовый промт
   для Claude. Ничего не отправляется само.
6. **Эксперт.** Импорт чужой стратегии (config zapret2, nfqws2.conf, .cmd
   winws2, строка аргументов, JSON zapret-gui) с проверкой и использованием.

Права администратора нужны только агенту, который запускает движок и правила
firewall; окно программы работает без них. При выходе агент снимает все свои
правила.

## Частые вопросы

**Антивирус ругается на WinDivert / winws2.** WinDivert — драйвер перехвата
пакетов, на котором работает zapret2 в Windows. Антивирусы часто помечают
его как «потенциально нежелательный» из-за самой возможности перехвата.
Файлы в релизе — официальные из bol-van/zapret2, хэш закреплён в
`tools/bundle/zapret2.lock.json`. Добавьте папку программы в исключения.

**VirtualBox / VMware в режиме NAT.** Внутри виртуалки с NAT стратегии,
завязанные на TTL, ведут себя иначе, чем на реальном ПК, а часть пакетов
переписывает сама виртуальная сеть. Подбирайте на реальной машине или в
режиме сетевого моста (bridge).

**Linux: «не найден pkexec».** Установите polkit (`policykit-1` или
`polkit`) или запустите программу от root.

**Проверка в браузере.** Галочка «Проверять найденное в браузере» открывает
сайт в установленном Chrome, Chromium или Edge (или в браузере из папки
`browsers` рядом с программой). Без браузера проверка идёт загрузкой
страницы самой программой.

**Телеметрия.** Её нет. Настройки, база знаний и журнал хранятся только
локально (путь показан в настройках).

---

# Zapret2 AutoTuner — user guide

## Install

- **Windows 10/11 x64:** the `…-setup.exe` installer or the `…-portable.zip`.
- **Linux x64 and arm64:** `.deb`, `.rpm` or `.tar.gz`. Needs nftables (or
  iptables) and polkit (`pkexec`). There is no AppImage: the root agent cannot
  start from its FUSE mount.

Check files against `SHA256SUMS.txt`. The bundled zapret2 is the unmodified
official bol-van/zapret2 build.

## Use

1. **Home → Check for blocks** shows what is blocked.
2. **Find a strategy:** enter sites or pick a ready set and press Start. You
   see the stage, percent, elapsed and remaining time; you can stop any time.
3. **Export** to this PC, Keenetic, zapret-gui, zapret2 or an argument line.
   Nothing goes to a router or zapret-gui without your Yes; applying in
   zapret-gui is a separate second button.
4. **Monitor** keeps the strategy running and repairs it when a site breaks,
   asking first unless you allowed automatic fixes.
5. **Reports** builds an archive for analysis with your IPs masked. Nothing is
   sent anywhere.
6. **Expert** imports and validates someone else's strategy.

Only the agent runs with administrator rights; it removes its firewall rules
on exit.

## FAQ

- **Antivirus flags WinDivert:** it is zapret2's packet capture driver, the
  official file; add the program folder to exclusions.
- **VirtualBox NAT:** tune on the real machine or in bridged mode.
- **Linux "pkexec not found":** install polkit or run as root.
- **No telemetry.** All data stays local.
