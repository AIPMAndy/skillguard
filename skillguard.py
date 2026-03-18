#!/usr/bin/env python3
"""SkillGuard - Skill Security Scanner

Focus on one thing: securing AI Skills.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import re


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


# Security rules database
SECURITY_RULES = [
    # Critical - Immediate threat
    SecurityRule(
        "dangerous_command",
        "Dangerous System Command",
        RiskLevel.CRITICAL,
        r"(rm\s+-rf\s+/|curl\s+.*\|\s*bash|wget\s+.*\|\s*sh|mkfs|dd\s+if=/dev/zero|>:/dev/sda)",
        "Dangerous command that can destroy system or execute remote code",
        "Avoid executing commands from untrusted sources. Use package managers instead."
    ),
    SecurityRule(
        "reverse_shell",
        "Reverse Shell Detection",
        RiskLevel.CRITICAL,
        r"(bash\s+-i|/bin/sh\s+-i|nc\s+-e|python.*socket.*connect|ruby.*TCPSocket)",
        "Potential reverse shell for unauthorized remote access",
        "Remove reverse shell code. Use legitimate remote management tools."
    ),
    
    # High - Significant risk
    SecurityRule(
        "credential_exposure",
        "Hardcoded Credentials",
        RiskLevel.HIGH,
        r"(api[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}|password\s*[=:]\s*['\"]\S+|token\s*[=:]\s*['\"]sk-[a-zA-Z0-9]{20,})",
        "Hardcoded credentials in source code",
        "Use environment variables or secure vaults for credentials."
    ),
    SecurityRule(
        "prompt_injection",
        "Prompt Injection Attack",
        RiskLevel.HIGH,
        r"(ignore\s+previous\s+instructions|system\s*override|ignore\s+above|forget\s+prior|new\s+persona:)",
        "Attempt to override system instructions or persona",
        "Validate and sanitize all user inputs. Use prompt boundaries."
    ),
    SecurityRule(
        "data_exfiltration",
        "Potential Data Exfiltration",
        RiskLevel.HIGH,
        r"(requests\.post\s*\(.*\s*json\s*=|urllib\.request\.urlopen.*data=|\.sendall\s*\(.*password)",
        "Sending sensitive data to external endpoints",
        "Audit all network requests. Encrypt sensitive data in transit."
    ),
    
    # Medium - Moderate risk
    SecurityRule(
        "sensitive_file_access",
        "Sensitive File Access",
        RiskLevel.MEDIUM,
        r"open\s*\(\s*['\"](~\/\.ssh\/|~\/\.aws\/|~\/\.config\/|\/etc\/passwd|\/etc\/shadow)",
        "Accessing sensitive system or credential files",
        "Limit file access to necessary paths. Use proper access controls."
    ),
    SecurityRule(
        "eval_exec",
        "Dynamic Code Execution",
        RiskLevel.MEDIUM,
        r"(eval\s*\(|exec\s*\(|execfile|compile\s*\(|__import__\s*\(\s*['\"]os)",
        "Dynamic code execution can lead to code injection",
        "Avoid eval/exec. Use safer alternatives like ast.literal_eval."
    ),
    SecurityRule(
        "network_request",
        "Unrestricted Network Request",
        RiskLevel.MEDIUM,
        r"(requests\.(get|post)|urllib\.request|http\.client|socket\.connect)\s*\(\s*['\"]http",
        "Unrestricted network requests to external services",
        "Validate URLs. Use allowlists for external domains."
    ),
    
    # Low - Minor concern
    SecurityRule(
        "debug_mode",
        "Debug Mode Enabled",
        RiskLevel.LOW,
        r"(debug\s*=\s*True|DEBUG\s*=\s*True|app\.run.*debug\s*=\s*True)",
        "Debug mode may expose sensitive information",
        "Disable debug mode in production environments."
    ),
    SecurityRule(
        "todo_fixme",
        "TODO/FIXME Comments",
        RiskLevel.LOW,
        r"(#\s*(TODO|FIXME|XXX|HACK):.*)",
        "Incomplete or temporary code that may have security implications",
        "Review and address all TODO/FIXME items before production."
    ),
]


class SkillGuard:
    """Main security scanner."""
    
    def __init__(self, skill_path: Path, rules: Optional[List[SecurityRule]] = None):
        self.skill_path = skill_path
        self.rules = rules or SECURITY_RULES
        self.findings: List[Finding] = []
        self.files_scanned = 0
        
    def scan(self) -> List[Finding]:
        """Scan skill for security issues."""
        print(f"🔍 SkillGuard v0.2.0 - Scanning: {self.skill_path}")
        print("-" * 50)
        
        # Find all relevant files
        extensions = ['*.py', '*.md', '*.sh', '*.yml', '*.yaml', '*.json', '*.js']
        files = []
        for ext in extensions:
            files.extend(self.skill_path.rglob(ext))
        
        self.files_scanned = len(files)
        
        for file_path in files:
            self._scan_file(file_path)
        
        return self.findings
    
    def _scan_file(self, file_path: Path):
        """Scan a single file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return
        
        relative_path = file_path.relative_to(self.skill_path)
        
        for rule in self.rules:
            pattern = re.compile(rule.pattern, re.IGNORECASE)
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                
                finding = Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    level=rule.level,
                    file=str(relative_path),
                    line=line_num,
                    match=match.group(0)[:80],
                    description=rule.description,
                    remediation=rule.remediation
                )
                self.findings.append(finding)
    
    def calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
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
        """Get scan summary."""
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
        }
    
    def _get_risk_level(self) -> str:
        """Get overall risk level.""        score = self.calculate_risk_score()
        if score >= 80:
            return RiskLevel.CLEAN
        elif score >= 60:
            return RiskLevel.LOW
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def generate_report(self, format: str = "text") -> str:
        """Generate security report."""
        if format == "json":
            return self._generate_json_report()
        elif format == "markdown":
            return self._generate_markdown_report()
        else:
            return self._generate_text_report()
    
    def _generate_json_report(self) -> str:
        """Generate JSON report."""
        report = {
            "summary": self.get_summary(),
            "findings": [asdict(f) for f in self.findings],
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def _generate_markdown_report(self) -> str:
        """Generate Markdown report."""
        summary = self.get_summary()
        
        lines = [
            "# 🔒 SkillGuard Security Report",
            "",
            "## 📊 Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Risk Score | {summary['risk_score']}/100 |",
            f"| Risk Level | {summary['risk_level']} |",
            f"| Files Scanned | {summary['files_scanned']} |",
            f"| Total Findings | {summary['total_findings']} |",
            "",
        ]
        
        # Add counts
        lines.append("### Findings by Severity")
        lines.append("")
        for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = summary['counts'].get(level, 0)
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")
            lines.append(f"- {emoji} **{level}**: {count}")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # Add findings
        if self.findings:
            lines.append("## 🚨 Detailed Findings")
            lines.append("")
            
            for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
                findings = [f for f in self.findings if f.level == level]
                if not findings:
                    continue
                
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")
                lines.append(f"### {emoji} {level} ({len(findings)})")
                lines.append("")
                
                for i, finding in enumerate(findings, 1):
                    lines.append(f"#### {i}. {finding.rule_name}")
                    lines.append(f"- **File**: `{finding.file}:{finding.line}`")
                    lines.append(f"- **Match**: `{finding.match}`")
                    lines.append(f"- **Description**: {finding.description}")
                    lines.append(f"- **Remediation**: {finding.remediation}")
                    lines.append("")
        else:
            lines.append("## ✅ No Security Issues Found")
            lines.append("")
            lines.append("Great job! No security risks were detected in this Skill.")
        
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(f"*Report generated by SkillGuard v0.2.0*")
        
        return "\n".join(lines)
    
    def _generate_text_report(self) -> str:
        """Generate text report."""
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
        
        # Add counts
        for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = summary['counts'].get(level, 0)
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")
                lines.append(f"{emoji} {level}: {count}")
        
        lines.append("")
        lines.append("-" * 50)
        lines.append("")
        
        # Add findings
        for finding in self.findings:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding.level, "⚪")
            lines.append(f"{emoji} [{finding.level}] {finding.rule_name}")
            lines.append(f"   File: {finding.file}:{finding.line}")
            lines.append(f"   Match: {finding.match}")
            lines.append(f"   {finding.description}")
            lines.append("")
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="SkillGuard - Skill Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 skillguard.py ./my-skill/
  python3 skillguard.py ./my-skill/ --format markdown -o report.md
  python3 skillguard.py ./my-skill/ --format json | jq '.summary.risk_score'
        """
    )
    parser.add_argument("path", help="Path to skill directory")
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="critical",
        help="Exit with error if findings at this level or higher (default: critical)"
    )
    
    args = parser.parse_args()
    
    skill_path = Path(args.path)
    if not skill_path.exists():
        print(f"❌ Error: Path not found: {skill_path}", file=sys.stderr)
        sys.exit(1)
    
    # Scan
    guard = SkillGuard(skill_path)
    findings = guard.scan()
    
    # Generate report
    report = guard.generate_report(args.format)
    
    # Output
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(report, encoding="utf-8")
        print(f"\n📄 Report saved: {output_path}")
    else:
        print(report)
    
    # Exit code based on findings
    level_priority = {
        RiskLevel.CRITICAL: 4,
        RiskLevel.HIGH: 3,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 1,
    }
    fail_priority = level_priority.get(args.fail_on.upper(), 4)
    
    max_priority = 0
    for finding in findings:
        max_priority = max(max_priority, level_priority.get(finding.level, 0))
    
    sys.exit(1 if max_priority >= fail_priority else 0)


if __name__ == "__main__":
    main()
