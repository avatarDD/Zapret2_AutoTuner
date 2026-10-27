Zapret2_AutoTuner 0.1.0, zapret2 1.0.6, 2026-10-17
Цели / targets: discord.com, youtube.com, googlevideo.com

Экспорт для zapret2 (Linux).
1. Скопируйте ipset/ и files/ в /opt/zapret2/ (сохраняя пути).
2. В /opt/zapret2/config замените только переменные из config.fragment:
   NFQWS2_ENABLE, NFQWS2_PORTS_TCP, NFQWS2_PORTS_UDP, MODE_FILTER, NFQWS2_OPT.
   --user, --qnum, --fwmark и --lua-init добавит сам zapret2.
3. Перезапустите: /opt/zapret2/init.d/sysv/zapret2 restart (или systemctl restart zapret2).

Export for zapret2 (Linux).
1. Copy ipset/ and files/ into /opt/zapret2/ keeping the paths.
2. In /opt/zapret2/config replace only the variables from config.fragment.
3. Restart zapret2.

Закреплённые IP / pinned addresses
Адреса CDN меняются: закрепления надо перепроверять (AutoTuner делает это в мониторинге).
CDN addresses change: re-check the pins (AutoTuner does it in monitoring).

# BEGIN ZapretAutoTuner
162.159.128.233 discord.com
# END ZapretAutoTuner

Закреплённые IP / pinned addresses
Адреса CDN меняются: закрепления надо перепроверять (AutoTuner делает это в мониторинге).
CDN addresses change: re-check the pins (AutoTuner does it in monitoring).

address=/discord.com/162.159.128.233
