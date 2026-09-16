# Contributing / Участие в проекте

Contributions are welcome! / Приветствуются любые улучшения!

## What you can improve / Что можно улучшить

- macOS / BSD support in the Unix collector;
- JSON / NDJSON structured output (needed for the normalizer, v0.2.0);
- more log sources (web servers, databases, containers);
- tests and CI (shellcheck, PSScriptAnalyzer);
- documentation and translations;
- integration examples (OpenSearch, ELK, Loki, Wazuh).

## Rules / Правила

1. Collectors must stay **read-only**: they collect data and must not modify,
   delete or "fix" anything on the target host.
2. No new hard dependencies without a fallback: if a tool is missing,
   the script must skip it gracefully and record it in `dependencies.txt`.
3. Never commit collected artifacts: triage folders, archives, EVTX, PCAP,
   logs. The `.gitignore` already covers them — keep it that way.
4. Keep bilingual docs in sync: if you change `docs/X.md`, update `docs/X.ru.md`.

## Local checks / Локальные проверки

Bash:

```bash
bash -n collectors/unix/unix_triage.sh
bash -n collectors/unix/install_deps.sh
shellcheck collectors/unix/unix_triage.sh
```

PowerShell:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\collectors\windows\Get-TriageData.ps1
```

Test collectors only in isolated VMs or labs.

## Commit style / Стиль коммитов

Use short imperative subjects:

```text
Add JSON output for process artifacts
Fix cron spool collection on Alpine
Update ROADMAP for v0.2.0
```
