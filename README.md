# Metasploit Methodology Engine (MME)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-2.0.0-green.svg)
![Ruby](https://img.shields.io/badge/Ruby-3.0%2B-CC342D.svg)

A Metasploit Framework plugin that automates basic penetration testing
methodology using YAML-driven playbooks. Built as a learning project
to explore Metasploit's plugin API and offensive automation.

> **For authorized use only** — only run this against systems you own
> or have explicit permission to test.

---

## What it does

MME automates the repetitive parts of a basic pentest workflow inside
`msfconsole` — scanning a target, identifying open services, and running
relevant Metasploit modules based on what's found.

Instead of manually running modules one by one, you define a playbook
in YAML and MME handles the execution order.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/RadhakrishnanSA/msf-extension
cd msf-extension && ./install.sh

# Load inside msfconsole
msfconsole -q -x "load mme"

# Scan a single IP
msf6 > mme_scan 192.168.1.10

# Scan a web app URL (host is extracted automatically)
msf6 > mme_scan https://example.com/login

# Scan specific ports
msf6 > mme_scan 192.168.1.10 -p 80,443,445
```

---

## Usage

### Basic Scan
```bash
msf6 > mme_scan 192.168.1.10
```

### Parallel Scanning
Scan multiple services simultaneously — useful for larger networks:
```bash
msf6 > mme_scan 10.0.0.0/24 --threads 5
```

### Stealth Mode
Drops Nmap timing to `-T2` and adds randomized delays between
module executions to reduce noise:
```bash
msf6 > mme_scan 192.168.1.10 --profile stealth
```

### Enable Brute Force
Brute forcing is off by default. Enable with `--brute`:
```bash
msf6 > mme_scan 192.168.1.10 --brute
```

### Combining Flags
```bash
msf6 > mme_scan 10.0.0.0/24 --threads 3 --profile stealth --brute -p 21,22,80,443
```

### Import Existing Nmap XML
Skip the scan phase and run methodology against a saved Nmap result:
```bash
msf6 > mme_import scan.xml
```

### Persist Config
```bash
msf6 > mme_config set threads 5
```

### Manage Scope
```bash
msf6 > mme_scope add 192.168.1.0/24
```

### Checkpointing
MME auto-saves state on crash or interrupt:
```bash
msf6 > mme_sessions            # list interrupted scans
msf6 > mme_resume <session_id> # resume from where it stopped
```

---

## Command Reference

| Command               | Description                          |
|-----------------------|--------------------------------------|
| `mme_scan <target>`   | Nmap scan + full methodology         |
| `mme_import <file>`   | Import Nmap XML and run methodology  |
| `mme_status`          | Show current engine status           |
| `mme_report [format]` | Generate report (html / json / md)   |
| `mme_playbooks`       | List available playbooks             |
| `mme_findings`        | Show findings summary                |
| `mme_stop`            | Stop current scan                    |
| `mme_sessions`        | List paused/interrupted sessions     |
| `mme_resume <id>`     | Resume a paused session              |
| `mme_scope`           | Manage target scope                  |
| `mme_config`          | Manage persistent config             |
| `mme_help`            | Show help                            |

---

## Supported Services

| Service    | Port  | What it checks                     |
|------------|-------|------------------------------------|
| FTP        | 21    | Version, anonymous login           |
| SSH        | 22    | Version, user enumeration          |
| SMTP       | 25    | Version, user enum, relay check    |
| DNS        | 53    | Amplification check, enumeration   |
| HTTP       | 80    | Headers, dir scan, robots.txt      |
| HTTPS      | 443   | SSL version, cert info, dir scan   |
| SMB        | 445   | Version, shares, EternalBlue check |
| MySQL      | 3306  | Version, default credentials       |
| PostgreSQL | 5432  | Version, default credentials       |
| Redis      | 6379  | Info, unauthenticated access       |
| SNMP       | 161   | Enumeration, login check           |

---

## Features

- YAML playbooks — add new attack modules without touching Ruby
- Stealth mode — throttled timing for quieter scans
- Multi-target support with parallel threads
- Session checkpointing — resume interrupted scans
- Report generation in HTML, JSON, and Markdown
- Zero external gem dependencies — runs in MSF's existing Ruby env

---

## Stack

Ruby — runs entirely within Metasploit's existing environment.

## License

MIT — see [LICENSE](LICENSE)
