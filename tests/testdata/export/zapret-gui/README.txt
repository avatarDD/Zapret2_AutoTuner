Zapret2_AutoTuner 0.1.0, zapret2 1.0.6, 2026-10-17
Цели / targets: discord.com, youtube.com, googlevideo.com

Экспорт для zapret-gui. Ничего не применяется само: стратегию сохраняете и включаете вы.
Способ 1: «Стратегии → Импорт», вставьте zapret-gui-import.txt.
Способ 2: «Бэкап → Восстановить» файлом zapret-gui-backup.json (секции strategies и hostlists).
Способ 3: импорт бандла zapret-autotuner-bundle.json (если ваша версия zapret-gui его умеет).
Перед способами 1 и 2 создайте в GUI:

Export for zapret-gui. Nothing is applied by itself: you save and enable the strategy.
1: Strategies → Import, paste zapret-gui-import.txt.
2: Backup → Restore with zapret-gui-backup.json (strategies and hostlists sections).
3: bundle import of zapret-autotuner-bundle.json, if your zapret-gui supports it.
Before 1 and 2 create in the GUI:
  - список / hostlist zt-quic1 (lists/zt-quic1.txt)
  - список / hostlist zt-tcp1 (lists/zt-tcp1.txt)
  - список / hostlist zt-tcp2 (lists/zt-tcp2.txt)
  - блоб / blob tls_wl (blobs/tls_wl.bin)

Закреплённые IP / pinned addresses
Адреса CDN меняются: закрепления надо перепроверять (AutoTuner делает это в мониторинге).
CDN addresses change: re-check the pins (AutoTuner does it in monitoring).

address=/discord.com/162.159.128.233
