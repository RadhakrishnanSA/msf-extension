# Architecture Overview

## Core Components
MME is built on a modular architecture to interact seamlessly with the Metasploit Framework.

1. **Plugin Integration (`mme.rb` & `console_dispatcher.rb`)**: Hooks into `msfconsole`, providing custom commands and managing the lifecycle of the engine.
2. **Scanner (`scanner.rb`)**: Wraps Nmap for scanning targets or imports existing XML scan results.
3. **Engine (`engine.rb`)**: The main orchestrator that manages the state machine and coordinates other components.
4. **Service Queue (`service_queue.rb`)**: A robust, thread-safe queue that tracks discovered services and their processing status.
5. **Playbook Engine (`playbook_engine.rb` & `playbook.rb`)**: Parses YAML playbooks, matches them to services, and constructs the module execution workflow.
6. **Module Runner (`module_runner.rb`)**: Wraps the Metasploit module creation, datastore configuration, and execution. Handles timeout and error management.
7. **Output Capture (`output_capture.rb`)**: Intercepts and records module output for evidence collection while ensuring the user still sees progress in the console.
8. **Evidence Collector (`evidence_collector.rb` & `finding.rb`)**: Analyzes module output, extracts evidence, generates structured findings, and stores them in the MSF database.
9. **Report Generator (`report_generator.rb`)**: Uses ERB templates to convert findings and evidence into polished HTML or JSON reports.

## Data Flow
`User Command (mme_scan) -> Nmap -> MSF Database -> Service Queue -> Playbook Engine -> Module Runner -> Output Capture -> Evidence Collector -> Report Generator -> Output Report`
