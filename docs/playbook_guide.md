# Playbook Guide

MME playbooks are written in YAML and define the sequence of Metasploit modules to run against a specific service.

## Structure
A playbook consists of metadata and a list of steps.

```yaml
---
service: "service_name" # e.g., ftp
ports: [port_numbers]   # e.g., [21, 2121]
description: "Playbook Description"

steps:
  - name: "Step Name"
    module: "path/to/module" # e.g., auxiliary/scanner/ftp/ftp_version
    options:
      KEY: "value" # Override default module options
    evidence:
      type: "misconfiguration"
      severity: "high"
      title: "Title for Report"
      description: "Description for Report"
```

## Adding Custom Playbooks
1. Create a `.yml` file in the `~/.msf4/mme/playbooks/` directory.
2. Ensure the `service` and `ports` fields accurately match the target service.
3. The Playbook Engine will automatically load the new file when MME starts.

## Evidence Configuration
The `evidence` block is optional. If included, MME will parse the module output and create a finding in the report if the module indicates success (e.g., outputs `[+]` or specific keywords like `found`, `vulnerable`).
