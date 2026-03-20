# Contributing to SafeSkill

Thanks for contributing to SafeSkill.

SafeSkill is focused on one thing: helping people detect risky patterns in AI Skills before they install or run them.

## What kind of contributions are useful?

### 1. New detection rules
Good rule contributions usually include:
- a clear threat pattern
- low false-positive rate
- a short explanation of why it matters
- a remediation suggestion
- test coverage

### 2. False positive reduction
This is especially valuable.
If a rule is technically correct but noisy in real Skill repos, it reduces trust in the scanner.

### 3. Better test fixtures
If you add a rule, please also add:
- a positive sample that should be detected
- a negative sample that should not be detected

### 4. Docs and CI improvements
README clarity, examples, CI stability, release hygiene — all welcome.

## Development setup

```bash
git clone https://github.com/AIPMAndy/safeskill.git
cd safeskill
pip install -e .
pip install pytest
```

## Run tests

```bash
python -m unittest tests.test_safeskill -v
python -m pytest tests/ -q
```

## Run local scan

```bash
python safeskill.py . --format json --quiet
```

## Pull request guidelines

- Keep PRs focused
- Explain the threat model or problem being solved
- Add or update tests when behavior changes
- Prefer fewer, clearer rules over many noisy ones
- If you change README behavior or CLI behavior, update docs too

## Rule design principles

When adding detection rules, optimize for:
1. **High signal** — catch meaningful risk
2. **Low noise** — avoid spamming users with false positives
3. **Actionability** — findings should include useful remediation
4. **Skill relevance** — prioritize patterns common in AI Skill ecosystems

## Security note

If you find a serious security issue in the project itself, please avoid posting exploitable details publicly before maintainers have time to respond.

Thanks for making Skill ecosystems safer.
