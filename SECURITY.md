# Security Policy

## Reporting Vulnerabilities in MME

If you discover a security vulnerability in MME itself (e.g., command injection,
path traversal, credential leakage in logs), please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email: [security contact email or use GitHub Security Advisories]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

**Expected response time:** Acknowledgment within 48 hours, fix within 7 days for critical issues.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | ✅ Active support   |
| 1.x.x   | ❌ End of life      |

## Security Design Decisions

- **No shell interpolation**: All external command execution uses array-form `Open3.capture2e` to prevent command injection.
- **Input validation**: All user input is validated through `Mme::Validator` before reaching the engine.
- **Credential redaction**: Passwords are redacted from reports by default (`redact_credentials: true`).
- **YAML safe loading**: All YAML parsing uses `YAML.safe_load` to prevent deserialization attacks.
- **HTML escaping**: All user-controlled data in HTML reports is escaped via `ERB::Util#h`.
- **No third-party gems**: MME has zero gem dependencies beyond MSF itself, eliminating supply-chain risk.
