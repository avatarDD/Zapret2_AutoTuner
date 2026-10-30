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

**Права администратора и portable-архивы.** Агент запускает движок с правами
администратора (root). Безопаснее всего установщик, `.deb` или `.rpm`: они кладут
программу в каталог, который могут менять только администраторы. Portable-архив
(`.zip`, `.tar.gz`) распакуйте в такую же папку (например, `C:\Program Files\…`
или `/opt/…` с владельцем root), а не в «Загрузки» или домашний каталог. Если папка
движка доступна на запись обычному пользователю, агент запускает движок только из
своей защищённой копии, сверенной с `bundle.json`, и отказывает при расхождении,
но сам файл агента так защитить нельзя: подменённый агент получит права при
следующем запуске.

## Как пользоваться

1. **Главная → «Проверить блокировки».** Программа проверит популярные сайты и
   покажет светофор: зелёный — работает, жёлтый — частично, красный — блок.
2. **«Подобрать стратегию».** Впишите сайты (или нажмите готовый набор:
   YouTube, Discord, Telegram, Instagram) и нажмите «Начать». Программа
   определит тип блокировки, переберёт стратегии и проверит найденное полной
   загрузкой. Видно этап, процент, прошедшее и оставшееся время. Подбор
   можно остановить в любой момент («Остановить» берёт лучшее найденное) или
   поставить на паузу: текущая проба доработает, и движок остановится.
   Проверенное сохраняется по ходу, поэтому после паузы, закрытия программы
   или перезагрузки компьютера на первом шаге будет кнопка «Продолжить
   подбор»: уже проверенные стратегии заново не запускаются.
   Найденное перепроверяется в конце: пять полных загрузок (одна случайная
   неудача допускается) и, с галочкой браузера, открытие страницы. Если
   странице нужны другие домены (CDN, картинки), программа назовёт их:
   добавьте их отдельными целями, стратегия для основного сайта при этом
   сохраняется.
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
   Если стратегия ссылается на файл списка, которого нет рядом (например
   `--hostlist=C:\zapret\lists\list-general.txt`), программа берёт список
   из «Ресурсов» с тем же именем (`list-general`).
7. **Ресурсы.** Свои хостлисты, ipset'ы, блобы и Lua-скрипты. Имя можно
   ввести с расширением: «youtube.txt» сохранится как «youtube».

Под каждым пунктом меню написано, для чего он. При закрытии программы
вместе с ней завершаются все запущенные ею процессы (браузер проверки и
другие), агент сам останавливает движок и снимает правила.

Права администратора нужны только агенту, который запускает движок и правила
firewall; окно программы работает без них. При выходе агент снимает все свои
правила.

## Чат claude.ai через расширение браузера (мост MCP)

claude.ai не может сам достучаться до программ на вашем ПК и до роутера за
NAT. Мостом служит стороннее расширение браузера, которое умеет подключать
MCP-серверы к веб-чату, а AutoTuner — MCP-сервер, к которому оно
подключается. Цепочка: claude.ai → расширение → AutoTuner (127.0.0.1) →
zapret-gui на роутере (например, 192.168.2.1).

1. **Настройки → MCP-сервер:** включите сервер и «Streamable HTTP на
   127.0.0.1». Отметьте нужные разрешения (чтение доступно всегда).
2. **Раздел «Мост для расширения браузера»:**
   - `router_proxy` — чтобы в чате были инструменты zapret-gui роутера (с
     префиксом `gui_`). Нужны адрес и MCP-токен zapret-gui выше; модель их не
     видит. Всё, что zapret-gui не помечает как «только чтение», перед
     выполнением спросит вас в окне AutoTuner с именем инструмента и
     аргументами. Пока AutoTuner сам ставит эксперимент на роутере, такие
     инструменты ждут.
   - Если расширение подключается к AutoTuner напрямую, впишите его Origin
     (`chrome-extension://<id>` — id виден на странице `chrome://extensions`,
     `moz-extension://<uuid>` в Firefox). Остальные сайты и расширения
     получают отказ (403). Токен нужен всегда.
   - Скопируйте готовый фрагмент настройки: URL и заголовок
     `Authorization: Bearer <токен>` (галочка «Показать токен» подставит его).
3. **MCP-SuperAssistant** (расширение с открытым кодом) обычно работает
   через свой локальный прокси `npx @srbhptl39/mcp-superassistant-proxy
   --config mcpconfig.json` (по умолчанию `http://localhost:3006/sse`; в
   расширении укажите адрес прокси). В `mcpconfig.json` добавьте один из
   фрагментов из настроек: через stdio (`ZapretAutoTuner mcp` — подключится
   к уже открытому окну) или через HTTP с заголовком `Authorization`. Прокси
   ходит без Origin, поэтому список разрешённых расширений ему не нужен.
   Внимание: в README проекта (на момент написания) claude.ai нет в списке
   поддерживаемых сайтов — проверьте актуальную версию или используйте форк,
   который его поддерживает.
4. **Другие расширения-мосты** (например, форки «MCP Bridge for Claude.ai»,
   «Claude MCP Client / Injector») подключаются так же: тот же URL
   (Streamable HTTP `/mcp` или legacy SSE `/mcp/sse`) и тот же заголовок.
   Расширение должно уметь отправлять заголовок `Authorization`. Совместимость
   с конкретными расширениями мы не проверяли.

Безопасность: стороннее расширение видит весь обмен, а ответы роутера уходят
в чат claude.ai (адреса в них замаскированы). Подключайте только то
расширение, которому доверяете. Каждый вызов записывается в журнал MCP и
попадает в «Собрать отчёт»; кнопка «Остановить» на баннере обрывает и мост.

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
сайт во встроенном браузере программы: Chromium без окна из Playwright в
папке `browsers` рядом с программой, каждый раз с чистым временным профилем.
Установленные у вас браузеры, их профили и настройки программа не трогает.
Если папки `browsers` нет, проверка идёт загрузкой страницы самой программой.

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

**Administrator rights and portable archives.** The agent runs the engine as
Administrator (root). The installer, `.deb` or `.rpm` are the safe choice: they put
the program into a folder only administrators can change. Unpack a portable archive
(`.zip`, `.tar.gz`) into such a folder too (for example `C:\Program Files\…`, or
`/opt/…` owned by root), not into Downloads or your home. When the engine folder is
writable by a normal user, the agent runs the engine only from its protected copy
verified against `bundle.json` and refuses on a mismatch, but the agent binary itself
cannot be protected that way: a replaced agent gets the rights on its next start.

## Use

1. **Home → Check for blocks** shows what is blocked.
2. **Find a strategy:** enter sites or pick a ready set and press Start. You
   see the stage, percent, elapsed and remaining time. Stop any time (Stop takes
   the best found so far) or Pause: the current trial finishes and the engine
   stops. What was tried is saved as it goes, so after a pause, closing the
   program or restarting the computer the first step offers "Continue the
   search", and strategies already tried are not run again.
   What was found is checked again at the end: five full loads (one stray miss
   is allowed) and, with the browser box ticked, the page. When the page needs
   other domains (a CDN, images), the program names them: add them as targets
   of their own, the strategy for the main site is kept.
3. **Export** to this PC, Keenetic, zapret-gui, zapret2 or an argument line.
   Nothing goes to a router or zapret-gui without your Yes; applying in
   zapret-gui is a separate second button.
4. **Monitor** keeps the strategy running and repairs it when a site breaks,
   asking first unless you allowed automatic fixes.
5. **Reports** builds an archive for analysis with your IPs masked. Nothing is
   sent anywhere.
6. **Expert** imports and validates someone else's strategy. A list file the
   strategy names but that is not there (`--hostlist=C:\zapret\lists\list-general.txt`)
   is taken from Resources under the same name (`list-general`).
7. **Resources** keeps your hostlists, ipsets, blobs and Lua scripts. A name may
   have an extension: "youtube.txt" is saved as "youtube".

Every menu item says what it is for. Closing the program ends every process it
started (the check's browser and others); the agent stops the engine and
removes its rules by itself.

Only the agent runs with administrator rights; it removes its firewall rules
on exit.

## The claude.ai chat through a browser extension (MCP bridge)

claude.ai cannot reach programs on your PC or a router behind NAT. A
third-party browser extension that connects MCP servers to the web chat is the
bridge, and AutoTuner is the MCP server it connects to: claude.ai → extension
→ AutoTuner (127.0.0.1) → zapret-gui on the router (e.g. 192.168.2.1).

1. **Settings → MCP server:** turn the server and "Streamable HTTP on
   127.0.0.1" on and pick the permissions (reading is always allowed).
2. **"Browser extension bridge":**
   - `router_proxy` puts the router's zapret-gui tools (prefix `gui_`) in the
     chat. It needs zapret-gui's address and MCP token above; the model never
     sees them. Anything zapret-gui does not mark read-only asks you in the
     AutoTuner window first, with the tool's name and arguments, and waits
     while AutoTuner runs its own experiment on the router.
   - If the extension connects to AutoTuner itself, add its Origin
     (`chrome-extension://<id>`, the id is on `chrome://extensions`;
     `moz-extension://<uuid>` in Firefox). Other sites and extensions get 403.
     The token is always required.
   - Copy the ready snippet: the URL and the `Authorization: Bearer <token>`
     header ("Show the token" fills it in).
3. **MCP-SuperAssistant** (open source) usually goes through its local proxy
   `npx @srbhptl39/mcp-superassistant-proxy --config mcpconfig.json` (default
   `http://localhost:3006/sse`; point the extension at the proxy). Add one of
   the snippets from Settings to `mcpconfig.json`: stdio (`ZapretAutoTuner
   mcp`, which joins the open window) or HTTP with the `Authorization`
   header. The proxy sends no Origin, so it needs no allowed-extension entry.
   Note: at the time of writing, the project's README does not list claude.ai
   among the supported sites; check the current version or use a fork that
   supports it.
4. **Other bridge extensions** (e.g. forks of "MCP Bridge for Claude.ai" or
   "Claude MCP Client / Injector") connect the same way: the same URL
   (Streamable HTTP `/mcp` or legacy SSE `/mcp/sse`) and the same header. The
   extension must be able to send the `Authorization` header. We have not
   tested specific extensions.

Security: the third-party extension sees all traffic, and the router's answers
go to the claude.ai chat (with addresses masked). Connect only an extension you
trust. Every call is logged in the MCP audit and goes into "Collect report";
Stop on the banner cuts the bridge too.

## FAQ

- **Antivirus flags WinDivert:** it is zapret2's packet capture driver, the
  official file; add the program folder to exclusions.
- **VirtualBox NAT:** tune on the real machine or in bridged mode.
- **Linux "pkexec not found":** install polkit or run as root.
- **Browser check:** the site opens in the program's own browser (Playwright's
  headless Chromium in the `browsers` folder next to the program), with a fresh
  temporary profile each time. Your installed browsers, their profiles and
  settings are never touched. Without the `browsers` folder the program checks
  by loading the page itself.
- **No telemetry.** All data stays local.
