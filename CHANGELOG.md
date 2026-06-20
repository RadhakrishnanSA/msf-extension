# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-20

### Added
- Configuration system with persistent YAML config (`mme_config`)
- Workspace-scoped target boundaries (`mme_scope`)
- Session checkpointing and resume (`mme_sessions`, `mme_resume`)
- Playbook conditional branching (`condition`, `on_success`, `on_failure`)
- Severity-aware exploit auto-suggestions with confidence scoring
- Parallel execution with global thread caps and connection backpressure
- Markdown report output format
- Audit logging to `~/.msf4/mme/logs/mme_audit.log`
- `mme_doctor` environment health check command
- `mme_export` for DefectDojo integration
- `--webhook` option for scan completion notifications
- PDF report generation via wkhtmltopdf
- Centralized input validation (`Mme::Validator`)
- Module execution timeout enforcement (configurable)
- Credential redaction in reports (default: enabled)
- OptionParser-based CLI parsing with `-h`/`--help` support
- Thread-safe database writes via shared mutex
- SECURITY.md with responsible disclosure policy
- CONTRIBUTING.md with development guidelines
- Architecture documentation with data flow diagram
- Playbook authoring guide with worked examples
- RSpec test suite foundation

### Changed
- Brute-force modules disabled by default (use `--brute` to enable)
- Module runner now streams output in real-time via OutputCapture
- Playbook YAML files validated with structured error messages on load

### Security
- Command injection prevention via array-form Open3 execution
- HTML output escaping in all report templates
- Workspace name sanitization in file paths
- Zero third-party gem dependencies (supply-chain hardening)

## [1.0.0] - 2026-06-19

### Added
- Initial release with automated methodology scanning
- YAML-based service playbooks
- Nmap integration and scan import
- HTML and JSON report generation
- Multi-threaded service processing
- Stealth scan profile
- Interactive configuration wizard (`mme_ui`)
