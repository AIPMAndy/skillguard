# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on Keep a Changelog.

## [0.4.1] - 2026-03-21

### Added
- Added real `.safeskill.yml` config loading
- Added support for file and directory exclusions
- Added custom rule loading and severity overrides
- Added `--quiet` and `--config` CLI flags
- Added bilingual README (`README.md` + `README_EN.md`)
- Added `CONTRIBUTING.md`
- Added issue templates for bug reports and feature requests
- Added `SECURITY.md`
- Added demo sample skill under `examples/dangerous-skill/`

### Changed
- Stabilized GitHub Actions workflows
- Switched CI commands to more reliable Python invocations
- Improved project positioning and onboarding docs
- Reduced self-scan false positives for the SafeSkill repo itself
- Unified version handling

### Fixed
- Fixed workflows that could fail because the `safeskill` entrypoint was not available in PATH
- Fixed config file being present but not actually used
- Fixed noisy self-referential findings in README/tests/repo files
