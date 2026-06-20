# Contributing to MME

Thank you for your interest in contributing to the Metasploit Methodology Engine!

## How to Add a Playbook

1. Create a new YAML file in `playbooks/` (e.g., `playbooks/redis.yml`)
2. Follow the schema in [docs/playbook_guide.md](docs/playbook_guide.md)
3. Test it: `load mme` then `mme_playbooks` to verify it loads
4. Run against a target to validate: `mme_scan <target>`

## Code Style

- Follow existing Ruby conventions in the codebase
- Use `Mme` module namespace for all classes
- Use Struct-based data objects with `keyword_init: true`
- Private logging helpers: `log_status`, `log_good`, `log_error`, `log_warning`
- All user input must go through `Mme::Validator` before reaching the engine
- All HTML output must be escaped via `ERB::Util#h`

## Running Tests Locally

```bash
gem install rspec rubocop
rspec spec/
rubocop lib/ spec/
```

## Branch Protection (Recommended)

For teams maintaining a fork:
- Require pull request reviews before merging to `main`
- Require `lint` and `test` status checks to pass
- Require branches to be up to date before merging

## Pull Request Checklist

- [ ] Code follows project style conventions
- [ ] New features include playbook/test coverage
- [ ] CHANGELOG.md updated
- [ ] No credentials or sensitive data in commits
- [ ] Existing tests pass (`rspec spec/`)
