
# Triage Collector Kit

Набор скриптов для первичного сбора артефактов инцидент-реагирования с хостов под управлением Windows и Linux.

## Возможности

### Windows
- Сбор процессов и командных строк
- Сбор сетевых соединений
- Сбор служб и запланированных задач
- Сбор локальных администраторов
- Экспорт журналов событий (Security, System, Sysmon, PowerShell)
- Сетевой дамп через `netsh trace`
- SHA256-хэши собранных файлов

### Linux / Unix
- Сбор процессов и командных строк
- Сбор сетевых соединений
- Сбор пользователей и сессий
- Сбор артефактов закрепления (cron, at, systemd)
- Сбор SSH-артефактов
- Сбор системных логов и `journalctl`
- Сетевой дамп через `tcpdump`
- SHA256-хэши собранных файлов

## Быстрый старт

### Windows

```powershell
.\collectors\windows\Get-TriageData.ps1

### Linux 
chmod +x collectors/unix/unix_triage.sh
sudo collectors/unix/unix_triage.sh
