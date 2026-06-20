# Metasploit Methodology Engine (MME) 🚀

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)
![Metasploit](https://img.shields.io/badge/Metasploit-Framework-red.svg)

MME is a Metasploit Framework plugin that automates eJPT, PNPT, and OSCP-style penetration testing methodologies. It acts like a junior penetration tester inside your `msfconsole`.

## Features
* **Automated Enumeration**: Runs comprehensive scans and enumeration modules based on discovered services.
* **Service-Driven Architecture**: Uses YAML playbooks to determine which modules to run.
* **Evidence Collection**: Captures module outputs and stores them in the Metasploit database.
* **Report Generation**: Automatically generates professional HTML and JSON reports.

## Quick Start

### Installation
1. Clone this repository.
2. Run the install script: `./install.sh`
3. Start Metasploit and load the plugin: `msfconsole -q -x "load mme"`

### Usage
```bash
msf6 > mme_scan 192.168.1.10
[*] Starting Nmap scan...
[+] Scan complete. Found 7 open services.
[*] [1/7] Processing FTP on 192.168.1.10:21...
[+] Methodology complete.
msf6 > mme_report html
[+] HTML report saved!
```

## Architecture Overview
The MME engine orchestrates Metasploit modules using a queue of discovered services. It matches each service to a corresponding YAML playbook in `~/.msf4/mme/playbooks/`. See [Architecture](docs/architecture.md) for details.

## Supported Services
| Service | Port | Playbook Modules |
|---------|------|------------------|
| FTP     | 21   | Version, Anonymous Check |
| SSH     | 22   | Version, User Enum |
| SMTP    | 25   | Version, User Enum, Relay Check |
| DNS     | 53   | Amp Check, Enum |
| HTTP    | 80   | Version, Title, Dir Scan, Robots |
| HTTPS   | 443  | Version, Title, Cert, SSL Version |
| SMB     | 445  | Version, Shares, Users, EternalBlue |
| MySQL   | 3306 | Version, Default Login |
| PostgreSQL| 5432 | Version, Default Login |
| Redis   | 6379 | Info, Unauthenticated Login |
| SNMP    | 161  | Enum, Login Check |

## Command Reference
* `mme_scan <target>`: Run Nmap scan + full methodology
* `mme_import <file>`: Import scan results (XML) and run methodology
* `mme_status`: Show current engine status
* `mme_report [format]`: Generate report (html/json)
* `mme_playbooks`: List available playbooks
* `mme_findings`: Display collected findings summary
* `mme_stop`: Stop the current engine run
* `mme_help`: Show help text

## License
MIT License. See [LICENSE](LICENSE) for details.
