# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Sensitive Data Warning

The collectors in this repository are designed for incident response and
forensic triage. By design, they collect sensitive information, including:

- user login history and session data;
- process lists with full command lines;
- active network connections;
- system and application logs;
- configuration files (sudoers, sshd_config, cron, systemd units);
- shell history and password hashes (only when explicitly enabled via flags).

**Do not publish collected archives.** Store them encrypted and share only
with authorized personnel.

## Reporting a Vulnerability

If you find a security issue in the scripts themselves (for example, a way
the script can be abused to damage a host or leak data unintentionally):

1. Open a private security advisory in this repository, or
2. Contact the maintainer directly.

Please do not publish exploit details in public issues.
