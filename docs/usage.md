# Usage Guide

## Loading the Plugin
Start `msfconsole` and load the plugin:
```bash
msf6 > load mme
```

## Database Connection
MME relies heavily on the Metasploit Database. Ensure you are connected to a database and have an active workspace:
```bash
msf6 > db_connect [user]:[pass]@[host]/[db]
msf6 > workspace -a my_project
```

## Running Scans
To scan a target and execute the methodology automatically:
```bash
msf6 > mme_scan 192.168.1.10
```

## Importing Existing Scans
If you have an Nmap XML output file, import it to start the methodology:
```bash
msf6 > mme_import /path/to/nmap_scan.xml
```

## Monitoring Progress
Check the status of the engine and the service queue:
```bash
msf6 > mme_status
```

## Reviewing Findings
To see a summary of findings collected so far:
```bash
msf6 > mme_findings
```

## Generating Reports
Once the methodology completes, generate a report:
```bash
msf6 > mme_report html
msf6 > mme_report json
```
Reports are saved in `~/.msf4/mme/reports/`.
