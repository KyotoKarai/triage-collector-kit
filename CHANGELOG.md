# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2025-09-16

### Added
- Windows collector: processes, network, services, tasks, local admins,
  EVTX export (Security, System, Sysmon, PowerShell, PrintService,
  TerminalServices), netsh network trace, SHA256 manifest.
- Unix collector: processes, network, users/sessions, persistence
  (cron, at, systemd, init, shell startup), SSH artifacts, system logs,
  journald, auditd, packages, configs, optional tcpdump capture,
  SHA256 manifest, archive packaging.
- Dependency installer for Linux (`collectors/unix/install_deps.sh`).
- Bilingual README (English / Russian).
- Project meta files: LICENSE, SECURITY, CONTRIBUTING, CHANGELOG.
