# Metasploit Methodology Engine (MME) 🚀

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.1.0-green.svg)
![Metasploit](https://img.shields.io/badge/Metasploit-Framework-red.svg)

MME is an **Enterprise-Grade** Metasploit Framework plugin that automates eJPT, PNPT, and OSCP-style penetration testing methodologies. It acts like an automated junior penetration tester directly inside your `msfconsole`.

## Key Features
* **Automated Enumeration**: Runs comprehensive scans and enumeration modules based on discovered services.
* **Service-Driven Architecture**: Uses YAML playbooks to determine which modules to run. Add new attacks without knowing Ruby!
* **Multi-Threading (Enterprise)**: Scan multiple services simultaneously to cut down scan times on massive networks.
* **Stealth Profiles**: Built-in timing delays and throttled Nmap scans to evade blue teams and IDS/IPS.
* **Evidence Collection & Reporting**: Parses Metasploit module output automatically, catches false positives, and generates professional HTML and JSON reports.
* **Exploit Auto-Suggestions**: When vulnerable software versions are found, MME searches the MSF Database and injects the exact `use exploit/...` commands directly into your final report.

---

## ⚡ Quick Start

### Installation
1. Clone this repository.
2. Run the install script: `./install.sh`
3. Start Metasploit and load the plugin:
   ```bash
   msfconsole -q -x "load mme"
   ```

### Basic Usage
To run a standard automated methodology against a single IP:
```bash
msf6 > mme_scan 192.168.1.10
```

To specify custom ports (just like Nmap):
```bash
msf6 > mme_scan 192.168.1.10 -p 80,443,445
```

---

## 🏢 Enterprise Usage (Advanced)

MME now supports advanced flags for professional engagements.

### 1. Parallel Processing (Speed)
Use the `--threads` flag to scan multiple services simultaneously. Perfect for large `/24` networks.
```bash
msf6 > mme_scan 10.0.0.0/24 --threads 5
```

### 2. Stealth Mode (Evasion)
Use the `--profile stealth` flag to drop Nmap timing to `-T2` and introduce randomized sleep delays (2-5 seconds) between Metasploit module executions to avoid triggering rate-limits or IDS alarms.
```bash
msf6 > mme_scan 192.168.1.10 --profile stealth
```

### 3. Combining Flags
You can combine all options together:
```bash
msf6 > mme_scan 10.0.0.0/24 --threads 3 --profile stealth -p 21,22,80,443
```

---

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
* `mme_scan <target> [options]`: Run Nmap scan + full methodology
* `mme_import <file>`: Import scan results (XML) and run methodology
* `mme_status`: Show current engine status
* `mme_report [format]`: Generate report (html/json)
* `mme_playbooks`: List available playbooks
* `mme_findings`: Display collected findings summary
* `mme_stop`: Stop the current engine run
* `mme_help`: Show help text

## License
MIT License. See [LICENSE](LICENSE) for details.
