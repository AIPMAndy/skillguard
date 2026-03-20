#!/usr/bin/env python3
"""SkillGuard - Skill Security Scanner.

Focus on one thing: securing AI Skills.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

__version__ = "0.4.1"

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency for config parsing
    yaml = None


@dataclass
class SecurityRule:
    """Security detection rule."""

    id: str
    name: str
    level: str  # CRITICAL, HIGH, MEDIUM, LOW
    pattern: str
    description: str
    remediation: str


@dataclass
class Finding:
    """Security finding."""

    rule_id: str
    rule_name: str
    level: str
    file: str
    line: int
    match: str
    description: str
    remediation: str


class RiskLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


DEFAULT_EXTENSIONS = ["*.py", "*.md", "*.sh", "*.yml", "*.yaml", "*.json", "*.js", "*.ts"]
DEFAULT_EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".cache",
    ".tox",
    ".pytest_cache",
}
DEFAULT_EXCLUDE_FILES = set()


# Security rules database
SECURITY_RULES = [
    SecurityRule(
        "dangerous_command",
        "Dangerous System Command",
        RiskLevel.CRITICAL,
        r"^\s*(rm\s+-rf\s+/|curl\s+.*\|\s*bash|wget\s+.*\|\s*sh|mkfs|dd\s+if=/dev/zero|>:/dev/sda)",
        "Dangerous command that can destroy system or execute remote code",
        "Avoid executing commands from untrusted sources. Use package managers instead.",
    ),
    SecurityRule(
        "reverse_shell",
        "Reverse Shell Detection",
        RiskLevel.CRITICAL,
        r"(bash\s+-i|/bin/sh\s+-i|nc\s+-e|python.*socket.*connect|ruby.*TCPSocket)",
        "Potential reverse shell for unauthorized remote access",
        "Remove reverse shell code. Use legitimate remote management tools.",
    ),
    SecurityRule(
        "credential_exposure",
        "Hardcoded Credentials",
        RiskLevel.HIGH,
        r"(\bapi[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{10,}|\bpassword\s*=\s*['\"]\S{8,}|\btoken\s*=\s*['\"]sk-[a-zA-Z0-9]{10,})",
        "Hardcoded credentials in source code",
        "Use environment variables or secure vaults for credentials.",
    ),
    SecurityRule(
        "prompt_injection",
        "Prompt Injection Attack",
        RiskLevel.HIGH,
        r"(ignore\s+previous\s+instructions|system\s*override|ignore\s+above|forget\s+prior|new\s+persona:)",
        "Attempt to override system instructions or persona",
        "Validate and sanitize all user inputs. Use prompt boundaries.",
    ),
    SecurityRule(
        "data_exfiltration",
        "Potential Data Exfiltration",
        RiskLevel.HIGH,
        r"(requests\.post\s*\(.*\s*json\s*=|urllib\.request\.urlopen.*data=|\.sendall\s*\(.*password)",
        "Sending sensitive data to external endpoints",
        "Audit all network requests. Encrypt sensitive data in transit.",
    ),
    SecurityRule(
        "sensitive_file_access",
        "Sensitive File Access",
        RiskLevel.MEDIUM,
        r"open\s*\(\s*['\"](~\/\.ssh\/|~\/\.aws\/|~\/\.config\/|\/etc\/passwd|\/etc\/shadow)",
        "Accessing sensitive system or credential files",
        "Limit file access to necessary paths. Use proper access controls.",
    ),
    SecurityRule(
        "eval_exec",
        "Dynamic Code Execution",
        RiskLevel.MEDIUM,
        r"(\beval\s*\(|\bexec\s*\(|\bexecfile\s*\(|__import__\s*\(\s*['\"]os)",
        "Dynamic code execution can lead to code injection",
        "Avoid eval/exec. Use safer alternatives like ast.literal_eval.",
    ),
    SecurityRule(
        "network_request",
        "Unrestricted Network Request",
        RiskLevel.MEDIUM,
        r"(requests\.(get|post)|urllib\.request|http\.client|socket\.connect)\s*\(\s*['\"]http",
        "Unrestricted network requests to external services",
        "Validate URLs. Use allowlists for external domains.",
    ),
    SecurityRule(
        "debug_mode",
        "Debug Mode Enabled",
        RiskLevel.LOW,
        r"(debug\s*=\s*True|DEBUG\s*=\s*True|app\.run.*debug\s*=\s*True)",
        "Debug mode may expose sensitive information",
        "Disable debug mode in production environments.",
    ),
    SecurityRule(
        "todo_fixme",
        "TODO/FIXME Comments",
        RiskLevel.LOW,
        r"(#\s*(TODO|FIXME|XXX|HACK):.*)",
        "Incomplete or temporary code that may have security implications",
        "Review and address all TODO/FIXME items before production.",
    ),
    SecurityRule(
        "privilege_escalation",
        "Privilege Escalation",
        RiskLevel.CRITICAL,
        r"(sudo\s+|chmod\s+777|chown\s+root|setuid|setgid)",
        "Attempt to escalate privileges or change sensitive permissions",
        "Avoid privilege escalation. Use least privilege principle.",
    ),
    SecurityRule(
        "backdoor_code",
        "Potential Backdoor",
        RiskLevel.CRITICAL,
        r"(backdoor|bind\s*shell|connect\s*back|spawn\s*shell|pty\s*spawn)",
        "Potential backdoor or unauthorized access mechanism",
        "Remove backdoor code immediately. Audit all network-facing code.",
    ),
    SecurityRule(
        "insecure_deserialization",
        "Insecure Deserialization",
        RiskLevel.HIGH,
        r"(pickle\.loads|yaml\.load\s*\(|json\.load.*object_hook|marshal\.loads)",
        "Insecure deserialization can lead to remote code execution",
        "Use safe alternatives like json.loads() or yaml.safe_load().",
    ),
    SecurityRule(
        "sql_injection",
        "SQL Injection",
        RiskLevel.HIGH,
        r"(cursor\.execute\s*\(\s*['\"].*%s|cursor\.execute\s*\(\s*['\"].*\+|\.execute\s*\(\s*f['\"])",
        "SQL injection vulnerability",
        "Use parameterized queries. Never concatenate SQL strings.",
    ),
    SecurityRule(
        "xss_vulnerability",
        "Cross-Site Scripting (XSS)",
        RiskLevel.HIGH,
        r"(innerHTML\s*=|document\.write\s*\(|\.html\s*\(.*\+|render_template_string)",
        "Potential XSS vulnerability",
        "Use template auto-escaping. Sanitize all user input.",
    ),
    SecurityRule(
        "weak_crypto",
        "Weak Cryptography",
        RiskLevel.HIGH,
        r"(\bmd5\s*\(|\bsha1\s*\(|\bhashlib\.md5|\bhashlib\.sha1|DES\s*\(|RC4|ECB_MODE)",
        "Use of weak or broken cryptographic algorithms",
        "Use strong cryptography: SHA-256, AES-GCM, secrets module.",
    ),
    SecurityRule(
        "path_traversal",
        "Path Traversal",
        RiskLevel.MEDIUM,
        r"(open\s*\(\s*.*\+.*\)|\.\./|\.\.\\\\|/etc/passwd|\.%00)",
        "Path traversal vulnerability",
        "Validate and sanitize all file paths. Use path normalization.",
    ),
    SecurityRule(
        "command_injection",
        "Command Injection",
        RiskLevel.MEDIUM,
        r"(os\.system\s*\(|subprocess\.call\s*\(.*\+|popen\s*\(.*\$)",
        "Command injection vulnerability",
        "Use subprocess with list arguments. Never shell=True with user input.",
    ),
    SecurityRule(
        "hardcoded_ip",
        "Hardcoded IP/Domain",
        RiskLevel.MEDIUM,
        r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|https?://\d+\.\d+\.\d+\.\d+)",
        "Hardcoded IP address or domain",
        "Use configuration files or environment variables for endpoints.",
    ),
    SecurityRule(
        "insecure_random",
        "Insecure Randomness",
        RiskLevel.MEDIUM,
        r"(random\.randint|random\.choice|random\.shuffle|Math\.random\s*\(\s*\))",
        "Insecure random number generation for security purposes",
        "Use secrets module (Python) or crypto.randomBytes (Node.js).",
    ),
    SecurityRule(
        "http_not_https",
        "HTTP Instead of HTTPS",
        RiskLevel.LOW,
        r"(http://(?!localhost|127\.0\.0\.1|192\.168\.|10\.\.))",
        "Using HTTP instead of HTTPS for external connections",
        "Always use HTTPS for external API calls.",
    ),
    SecurityRule(
        "broad_exception",
        "Broad Exception Handling",
        RiskLevel.LOW,
        r"(except\s*:\s*$|except\s+Exception\s*:\s*$|except\s*\(\s*\)\s*:)",
        "Overly broad exception handling may hide security issues",
        "Catch specific exceptions. Log and handle errors appropriately.",
    ),
    SecurityRule(
        "disabled_verification",
        "Disabled SSL Verification",
        RiskLevel.LOW,
        r"(verify\s*=\s*False|verify_ssl\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)",
        "SSL certificate verification disabled",
        "Never disable SSL verification in production.",
    ),
]


class SkillGuard:
    """Main security scanner."""

    def __init__(
        self,
        skill_path: Path,
        rules: Optional[List[SecurityRule]] = None,
        config_path: Optional[Path] = None,
        quiet: bool = False,
    ):
        self.skill_path = skill_path
        self.config_path = config_path
        self.config = self._load_config(config_path or self._find_config())
        self.rules = self._build_rules(rules or SECURITY_RULES)
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.quiet = quiet

        scan_cfg = self.config.get("scan", {})
        configured_extensions = scan_cfg.get("extensions") or DEFAULT_EXTENSIONS
        self.extensions = [self._normalize_extension_pattern(ext) for ext in configured_extensions]
        self.exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(scan_cfg.get("exclude_dirs", []))
        self.exclude_files = set(DEFAULT_EXCLUDE_FILES) | set(scan_cfg.get("exclude_files", []))

    def _find_config(self) -> Optional[Path]:
        candidates = [
            self.skill_path / ".safeskill.yml",
            self.skill_path / ".skillguard.yml",
            self.skill_path / ".safeskill.yaml",
            self.skill_path / ".skillguard.yaml",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def _load_config(self, config_path: Optional[Path]) -> Dict[str, Any]:
        if not config_path or not config_path.exists():
            return {}
        if yaml is None:
            raise RuntimeError(
                "PyYAML is required to read .safeskill.yml config files. Install with: pip install pyyaml"
            )
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        return data or {}

    def _build_rules(self, rules: List[SecurityRule]) -> List[SecurityRule]:
        rule_cfg = self.config.get("rules", {})
        disabled = set(rule_cfg.get("disabled", []))
        severity_overrides = rule_cfg.get("severity", {})
        custom_rules = rule_cfg.get("custom", [])

        built: List[SecurityRule] = []
        for rule in rules:
            if rule.id in disabled:
                continue
            built.append(
                SecurityRule(
                    id=rule.id,
                    name=rule.name,
                    level=str(severity_overrides.get(rule.id, rule.level)).upper(),
                    pattern=rule.pattern,
                    description=rule.description,
                    remediation=rule.remediation,
                )
            )

        for rule in custom_rules:
            built.append(
                SecurityRule(
                    id=rule["id"],
                    name=rule["name"],
                    level=str(rule["level"]).upper(),
                    pattern=rule["pattern"],
                    description=rule["description"],
                    remediation=rule["remediation"],
                )
            )
        return built

    def _normalize_extension_pattern(self, extension: str) -> str:
        extension = extension.strip()
        if not extension:
            return extension
        if extension.startswith("*"):
            return extension
        if extension.startswith("."):
            return f"*{extension}"
        return f"*.{extension}"

    def _iter_files(self) -> List[Path]:
        files: List[Path] = []
        for pattern in self.extensions:
            files.extend(self.skill_path.rglob(pattern))

        deduped: List[Path] = []
        seen = set()
        for file_path in sorted(files):
            if file_path in seen or not file_path.is_file():
                continue
            seen.add(file_path)
            relative = file_path.relative_to(self.skill_path)
            if any(part in self.exclude_dirs for part in relative.parts[:-1]):
                continue
            relative_str = str(relative)
            name = file_path.name
            if any(
                fnmatch.fnmatch(relative_str, pattern) or fnmatch.fnmatch(name, pattern)
                for pattern in self.exclude_files
            ):
                continue
            deduped.append(file_path)
        return deduped

    def _should_ignore_match(self, file_path: Path, content: str, match_start: int) -> bool:
        if file_path.name == "README.md":
            line_start = content.rfind("\n", 0, match_start) + 1
            line_end = content.find("\n", match_start)
            if line_end == -1:
                line_end = len(content)
            line = content[line_start:line_end]
            if "`" in line:
                return True
        return False

    def scan(self) -> List[Finding]:
        """Scan skill for security issues."""
        import time

        start_time = time.time()
        if not self.quiet:
            print(f"🔍 SkillGuard v{__version__} - Scanning: {self.skill_path}")
            print("-" * 50)

        files = self._iter_files()
        self.files_scanned = len(files)

        compiled_rules = [(rule, re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)) for rule in self.rules]
        for file_path in files:
            self._scan_file_optimized(file_path, compiled_rules)

        elapsed = time.time() - start_time
        if not self.quiet:
            print(f"✅ Scanned {self.files_scanned} files in {elapsed:.2f}s")
        return self.findings

    def _scan_file_optimized(self, file_path: Path, compiled_rules):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        relative_path = file_path.relative_to(self.skill_path)
        for rule, pattern in compiled_rules:
            for match in pattern.finditer(content):
                if self._should_ignore_match(file_path, content, match.start()):
                    continue
                line_num = content[: match.start()].count("\n") + 1
                self.findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        level=rule.level,
                        file=str(relative_path),
                        line=line_num,
                        match=match.group(0)[:80],
                        description=rule.description,
                        remediation=rule.remediation,
                    )
                )

    def calculate_risk_score(self) -> int:
        score = 100
        for finding in self.findings:
            if finding.level == RiskLevel.CRITICAL:
                score -= 25
            elif finding.level == RiskLevel.HIGH:
                score -= 10
            elif finding.level == RiskLevel.MEDIUM:
                score -= 3
            elif finding.level == RiskLevel.LOW:
                score -= 1
        return max(0, score)

    def get_summary(self) -> Dict[str, Any]:
        counts = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0,
        }
        for finding in self.findings:
            counts[finding.level] = counts.get(finding.level, 0) + 1
        return {
            "scan_time": datetime.now().isoformat(),
            "skill_path": str(self.skill_path),
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "risk_score": self.calculate_risk_score(),
            "risk_level": self._get_risk_level(),
            "counts": counts,
            "version": __version__,
        }

    def _get_risk_level(self) -> str:
        score = self.calculate_risk_score()
        if score >= 80:
            return RiskLevel.CLEAN
        if score >= 60:
            return RiskLevel.LOW
        if score >= 40:
            return RiskLevel.MEDIUM
        if score >= 20:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    def generate_report(self, format: str = "text") -> str:
        if format == "json":
            return self._generate_json_report()
        if format == "markdown":
            return self._generate_markdown_report()
        if format == "sarif":
            return self._generate_sarif_report()
        return self._generate_text_report()

    def _generate_json_report(self) -> str:
        return json.dumps({"summary": self.get_summary(), "findings": [asdict(f) for f in self.findings]}, indent=2, ensure_ascii=False)

    def _generate_sarif_report(self) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/AIPMAndy/safeskill",
                        "rules": [],
                    }
                },
                "results": [],
            }],
        }

        rules_dict = {}
        for finding in self.findings:
            if finding.rule_id not in rules_dict:
                rule = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {"text": finding.description},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": finding.level.lower()},
                    "help": {"text": finding.remediation},
                }
                rules_dict[finding.rule_id] = rule
                sarif["runs"][0]["tool"]["driver"]["rules"].append(rule)

        for finding in self.findings:
            sarif["runs"][0]["results"].append(
                {
                    "ruleId": finding.rule_id,
                    "level": finding.level.lower(),
                    "message": {"text": f"{finding.description}\n\nRemediation: {finding.remediation}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file},
                            "region": {"startLine": finding.line, "snippet": {"text": finding.match}},
                        }
                    }],
                }
            )
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _generate_markdown_report(self) -> str:
        summary = self.get_summary()
        lines = [
            "# 🔒 SkillGuard Security Report",
            "",
            "## 📊 Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Risk Score | {summary['risk_score']}/100 |",
            f"| Risk Level | {summary['risk_level']} |",
            f"| Files Scanned | {summary['files_scanned']} |",
            f"| Total Findings | {summary['total_findings']} |",
            "",
            "### Findings by Severity",
            "",
        ]
        for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = summary["counts"].get(level, 0)
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")
            lines.append(f"- {emoji} **{level}**: {count}")
        lines.extend(["", "---", ""])

        if self.findings:
            lines.extend(["## 🚨 Detailed Findings", ""])
            for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
                findings = [f for f in self.findings if f.level == level]
                if not findings:
                    continue
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")
                lines.extend([f"### {emoji} {level} ({len(findings)})", ""])
                for i, finding in enumerate(findings, 1):
                    lines.extend([
                        f"#### {i}. {finding.rule_name}",
                        f"- **File**: `{finding.file}:{finding.line}`",
                        f"- **Match**: `{finding.match}`",
                        f"- **Description**: {finding.description}",
                        f"- **Remediation**: {finding.remediation}",
                        "",
                    ])
        else:
            lines.extend(["## ✅ No Security Issues Found", "", "Great job! No security risks were detected in this Skill."])

        lines.extend(["", "---", "", f"*Report generated by SkillGuard v{__version__}*"])
        return "\n".join(lines)

    def _generate_text_report(self) -> str:
        summary = self.get_summary()
        lines = [
            "=" * 50,
            "🔒 SkillGuard Security Report",
            "=" * 50,
            "",
            f"Risk Score: {summary['risk_score']}/100 ({summary['risk_level']})",
            f"Files Scanned: {summary['files_scanned']}",
            f"Total Findings: {summary['total_findings']}",
            "",
        ]
        for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = summary["counts"].get(level, 0)
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")
                lines.append(f"{emoji} {level}: {count}")
        lines.extend(["", "-" * 50, ""])
        for finding in self.findings:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding.level, "⚪")
            lines.extend([
                f"{emoji} [{finding.level}] {finding.rule_name}",
                f"   File: {finding.file}:{finding.line}",
                f"   Match: {finding.match}",
                f"   {finding.description}",
                "",
            ])
        return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SkillGuard - Skill Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 safeskill.py ./my-skill/
  python3 safeskill.py ./my-skill/ --format markdown -o report.md
  python3 safeskill.py ./my-skill/ --format json | jq '.summary.risk_score'
        """,
    )
    parser.add_argument("path", help="Path to skill directory")
    parser.add_argument("--format", "-f", choices=["text", "json", "markdown", "sarif"], default="text", help="Output format")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--config", help="Explicit path to .safeskill.yml config file")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress logs for clean machine-readable output")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="critical",
        help="Exit with error if findings at this level or higher (default: critical)",
    )

    args = parser.parse_args()
    skill_path = Path(args.path)
    if not skill_path.exists():
        print(f"❌ Error: Path not found: {skill_path}", file=sys.stderr)
        sys.exit(1)

    guard = SkillGuard(skill_path, config_path=Path(args.config) if args.config else None, quiet=args.quiet)
    findings = guard.scan()
    report = guard.generate_report(args.format)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(report, encoding="utf-8")
        if not args.quiet:
            print(f"\n📄 Report saved: {output_path}")
    else:
        print(report)

    level_priority = {RiskLevel.CRITICAL: 4, RiskLevel.HIGH: 3, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 1}
    fail_priority = level_priority.get(args.fail_on.upper(), 4)
    max_priority = max((level_priority.get(finding.level, 0) for finding in findings), default=0)
    sys.exit(1 if max_priority >= fail_priority else 0)


if __name__ == "__main__":
    main()
