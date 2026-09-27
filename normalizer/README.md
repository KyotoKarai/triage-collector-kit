# Normalizer (v0.2.0) / Нормализатор (v0.2.0)

Converts Windows collector output (CSV) into a unified NDJSON event schema.
Standard library only, no external dependencies.

Превращает вывод Windows-коллектора (CSV) в единую схему событий NDJSON.
Только стандартная библиотека Python, внешних зависимостей нет.

## Usage / Запуск

```bash
python normalizer/normalize.py --input ./Triage_HOST_TS
python normalizer/normalize.py --input ./Triage_HOST_TS --output events.ndjson
```

Default output file: `<case_id>.events.ndjson` in the current directory.

## Event schema / Схема события

```json
{
  "case_id": "Triage_HOST_20260927_050922",
  "hostname": "HOST",
  "os": "windows",
  "collector": "windows_triage",
  "collected_at": "2026-09-27T05:09:22",
  "artifact_type": "process",
  "event_time": "2026-09-26T09:52:23",
  "data": { "...": "artifact-specific fields" },
  "tags": ["temp_execution"]
}
```

## Artifact types / Типы артефактов

- `process` — from `01_Processes.csv`
- `network` — from `02_NetworkConnections.csv`
- `service` — from `03_Services_Auto.csv`
- `task` — from `04_ScheduledTasks.csv`
- `user` — from `05_LocalAdmins.csv` (skipped when empty)

## Suspicion tags / Теги подозрительности

- `temp_execution` — binary/command in temp or public directories
- `binary_in_windows_root` — exe directly in `C:\Windows\` / `%WINDIR%\`
- `known_hacktool_name` — name matches kmsauto/kmspico/activator/crack/keygen
- `script_interpreter` — cmd/powershell/pwsh/wscript/cscript/mshta
- `encoded_command` — `-enc`, `-EncodedCommand`, `FromBase64String`
- `office_parent` — parent process is an Office application
- `missing_image_path` — process without an executable path
- `listening_all_interfaces` — socket listening on 0.0.0.0 / ::
- `external_connection` — established connection to a non-private IP
- `runs_as_system` — owner is SYSTEM (informational)

## Limitations / Ограничения (v0.2.0)

- Windows CSV output only; Unix parsers planned for v0.2.1
- EVTX parsing not implemented yet (planned via `python-evtx`)
- Empty or missing files are skipped gracefully

See [ROADMAP](../docs/ROADMAP.md).
