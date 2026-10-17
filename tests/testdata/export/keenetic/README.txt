Zapret2_AutoTuner 0.1.0, zapret2 1.0.5.2, 2026-10-17
Цели / targets: discord.com, youtube.com, googlevideo.com

Экспорт для nfqws2-keenetic 1.3.x.
Вариант 1 (файлы): скопируйте nfqws2.conf, lists/ и blobs/ в /opt/etc/nfqws2/ и выполните
  /opt/etc/init.d/S51nfqws2 restart
nfqws2.conf — полный файл пакета с нашими переменными. Проверьте ISP_INTERFACE (у вас он свой).
lists/user.list заменит ваш список: если в нём есть свои домены, допишите наши к ним.
Вариант 2 (фрагмент): в существующем /opt/etc/nfqws2/nfqws2.conf замените только строки из
nfqws2.conf.fragment, положите lists/ и blobs/ и перезапустите сервис.

Export for nfqws2-keenetic 1.3.x.
Option 1 (files): copy nfqws2.conf, lists/ and blobs/ into /opt/etc/nfqws2/ and restart S51nfqws2.
nfqws2.conf is the package's full file with our variables; check ISP_INTERFACE.
lists/user.list replaces yours: append our domains if you keep your own.
Option 2 (fragment): replace only the lines of nfqws2.conf.fragment in your nfqws2.conf.

Закреплённые IP / pinned addresses
Адреса CDN меняются: закрепления надо перепроверять (AutoTuner делает это в мониторинге).
CDN addresses change: re-check the pins (AutoTuner does it in monitoring).

ip host discord.com 162.159.128.233
system configuration save
