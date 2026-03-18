#!/usr/bin/env python3
"""SkillGuard - Skill Security Scanner"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any
import re


class RiskLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


class SecurityRule:
    """Security detection rule."""
    
    def __init__(self, id: str, name: str, level: str, pattern: str, description: str):
        self.id = id
        self.name = name
        self.level = level
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.description = description


class SkillGuard:
    """Main scanner engine."""
    
    RULES = [
        SecurityRule(
            "dangerous_command",
            "Dangerous Command",
            RiskLevel.CRITICAL,
            r"(rm\s+-rf\s+/|curl\s+.*\|\s*bash|wget\s+.*\|\s*sh|mkfs|dd\s+if=)",
            "Dangerous system command detected"
        ),
        SecurityRule(
            "credential_exposure",
            "Credential Exposure",
            RiskLevel.HIGH,
            r"(api[_-]?key\s*=\s*['\"]\w+|password\s*=\s*['\"]\w+|token\s*=\s*['\"]sk-)",
            "Hardcoded credentials detected"
        ),
        SecurityRule(
            "prompt_injection",
            "Prompt Injection",
            RiskLevel.HIGH,
            r"(ignore\s+previous\s+instructions|system\s*override|ignore\s+above)",
            "Potential prompt injection attack"
        ),
    ]
    
    def __init__(self, skill_path: Path):
        self.skill_path = skill_path
        self.findings: List[Dict] = []
    
    def scan(self) -> List[Dict]:
        """Scan skill for security issues."""
        print(f"🔍 Scanning: {self.skill_path}")
        
        files = list(self.skill_path.rglob("*.py"))
        files.extend(self.skill_path.rglob("*.md"))
        files.extend(self.skill_path.rglob("*.sh"))
        
        for file_path in files:
            self._scan_file(file_path)
        
        return self.findings
    
    def _scan_file(self, file_path: Path):
        """Scan a single file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return
        
        for rule in self.RULES:
            for match in rule.pattern.finditer(content):
                self.findings.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "level": rule.level,
                    "file": str(file_path.relative_to(self.skill_path)),
                    "line": content[:match.start()].count("\n") + 1,
                    "match": match.group(0)[:50],
                    "description": rule.description,
                })
    
    def generate_report(self, format: str = "text") -> str:
        """Generate security report."""
        if format == "json":
            return json.dumps({
                "findings": self.findings,
                "risk_score": self._calculate_risk_score(),
            }, indent=2)
        else:
            return self._generate_text_report()
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
        score = 100
        for finding in self.findings:
            if finding["level"] == RiskLevel.CRITICAL:
                score -= 30
            elif finding["level"] == RiskLevel.HIGH:
                score -= 15
            elif finding["level"] == RiskLevel.MEDIUM:
                score -= 5
        return max(0, score)
    
    def _generate_text_report(self) -> str:
        """Generate text report."""
        lines = [
            f"🔍 SkillGuard Scan Results",
            f"Risk Score: {self._calculate_risk_score()}/100",
            f"Findings: {len(self.findings)}",
            "",
        ]
        
        for finding in self.findings:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠", "LOW": "🟢"}.get(finding["level"], "⚪")
            lines.append(f"{emoji} {finding['level']} | {finding['rule_name']}")
            lines.append(f"   {finding['file']}:{finding['line']}")
            lines.append(f"   {finding['description']}")
            lines.append("")
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="SkillGuard - Skill Security Scanner")
    parser.add_argument("path", help="Path to skill directory")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--output", "-o", help="Output file path")
    
    args = parser.parse_args()
    
    skill_path = Path(args.path)
    if not skill_path.exists():
        print(f"❌ Error: Path not found: {skill_path}", file=sys.stderr)
        sys.exit(1)
    
    guard = SkillGuard(skill_path)
    findings = guard.scan()
    report = guard.generate_report(args.format)
    
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"📄 Report saved: {args.output}")
    else:
        print(report)
    
    # Exit with error if critical findings
    critical = sum(1 for f in findings if f["level"] == RiskLevel.CRITICAL)
    sys.exit(1 if critical > 0 else 0)


if __name__ == "__main__":
    main()
