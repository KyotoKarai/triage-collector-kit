# Triage Collector Kit

**English** | [Русский](README.ru.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/YOUR_USERNAME/triage-collector-kit/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)]()

A collection of scripts for initial incident response artifact collection from Windows and Linux hosts. Designed for triage and investigation scenarios, not for continuous monitoring.

---

## About

**Triage Collector Kit** is a set of scripts designed to quickly collect forensic and incident response artifacts from endpoints. The project is built around a simple workflow:

```text
Suspicious activity detected
        ↓
Run collector script on the host
        ↓
Artifacts saved to a structured folder
        ↓
Analyze manually or import into a log analysis platform
        ↓
Identify suspicious processes, network connections, persistence mechanisms
```

This project is **not** a SIEM or continuous monitoring solution. It is a rapid triage tool for incident responders and SOC analysts.

---

## Features

### Windows Collector

| Category | Details |
|----------|---------|
| Processes | Full process list with command lines, parent processes, owners |
| Network | Active connections and listening ports |
| Services | Services with automatic startup |
| Scheduled Tasks | All registered scheduled tasks |
| Users | Local administrators group members |
| Event Logs | Security, System, PowerShell, Sysmon, PrintService, TerminalServices |
| Network Capture | Short network trace via `netsh trace` |
| Integrity | SHA256 hashes of all collected files |

### Linux / Unix Collector

| Category | Details |
|----------|---------|
| Processes | Full process list with command lines and parent processes |
| Network | Active connections, listening ports, firewall rules |
| Users & Sessions | Current sessions, login history, failed logins |
| Persistence | cron, at, systemd units, init scripts, shell startup files |
| SSH | sshd_config, authorized_keys |
| Logs | syslog, auth.log, journalctl, auditd |
| Filesystem | Mounts, recently modified files |
| Packages | Installed packages list |
| Network Capture | Optional pcap capture via `tcpdump` |
| Integrity | SHA256 hashes of all collected files |

---

## Quick Start

### Windows

```powershell
# Run as Administrator
.\collectors\windows\Get-TriageData.ps1
```

If execution policy blocks the script:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\collectors\windows\Get-TriageData.ps1
```

### Linux

```bash
# Make executable
chmod +x collectors/unix/unix_triage.sh

# Run with root privileges
sudo collectors/unix/unix_triage.sh
```

With network capture:

```bash
sudo collectors/unix/unix_triage.sh --pcap 30
```

Full collection:

```bash
sudo collectors/unix/unix_triage.sh \
  --pcap 30 \
  --recent-files \
  --app-logs \
  --full-journal \
  --include-shell-history
```

---

## Project Structure

```text
triage-collector-kit/
├── README.md
├── README.ru.md
├── LICENSE
├── .gitignore
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
│
├── docs/
│   ├── PROJECT_OVERVIEW.md
│   ├── PROJECT_OVERVIEW.ru.md
│   ├── WINDOWS_TRIAGE.md
│   ├── WINDOWS_TRIAGE.ru.md
│   ├── UNIX_TRIAGE.md
│   ├── UNIX_TRIAGE.ru.md
│   ├── LOG_INTEGRATION.md
│   ├── LOG_INTEGRATION.ru.md
│   ├── ROADMAP.md
│   └── ROADMAP.ru.md
│
├── collectors/
│   ├── windows/
│   │   └── Get-TriageData.ps1
│   └── unix/
│       └── unix_triage.sh
│
└── examples/
    └── README.md
```

---

## Documentation

- [Project Overview](docs/PROJECT_OVERVIEW.md)
- [Windows Triage Script](docs/WINDOWS_TRIAGE.md)
- [Unix Triage Script](docs/UNIX_TRIAGE.md)
- [Log Integration Guide](docs/LOG_INTEGRATION.md)
- [Roadmap](docs/ROADMAP.md)

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                        Endpoint                             │
│                   Windows / Linux / Unix                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Triage Collector                         │
│              PowerShell / Bash script                       │
│  Collects: processes, network, users, logs, persistence    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Triage Archive                            │
│          Structured folder with artifacts                   │
│     CSV / EVTX / logs / configs / pcap / hashes            │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      Analysis                               │
│  Manual analysis / Log platform import / Viewer tool        │
└─────────────────────────────────────────────────────────────┘
```

---

## Integration

The collected artifacts can be imported into various log analysis platforms:

| Platform | Status | Description |
|----------|--------|-------------|
| OpenSearch | Planned | Dashboards and search |
| Elastic Stack (ELK) | Planned | Full ELK integration |
| Grafana Loki | Planned | Lightweight log viewing |
| Wazuh | Planned | SIEM integration |
| Graylog | Planned | Log management |

See [Log Integration Guide](docs/LOG_INTEGRATION.md) for details.

---

## Roadmap

- [x] **v0.1.0** — Windows and Unix collector scripts, basic documentation
- [ ] **v0.2.0** — JSON/CSV structured output, unified data schema
- [ ] **v0.3.0** — Python normalizer, local viewer (Streamlit)
- [ ] **v0.4.0** — OpenSearch integration, dashboards, Docker examples
- [ ] **v0.5.0** — macOS/BSD support, memory collection guidance

See [full roadmap](docs/ROADMAP.md).

---

## Security Notice

These scripts collect sensitive data including:

- User login history
- Process information and command lines
- Network connections
- Configuration files
- Shell history (when enabled)

**Do not publish collected archives publicly.** Store them securely and share only with authorized personnel.

See [SECURITY.md](SECURITY.md) for more details.

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Author

Created as a pet project for SOC / Incident Response portfolio.

---

**English** | [Русский](README.ru.md)
