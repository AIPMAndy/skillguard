# Release Guide

## Cut a release

1. Update version in:
- `safeskill.py`
- `setup.py`
- `pyproject.toml`
- `README.md` / `README_EN.md` badges if needed
- `CHANGELOG.md`

2. Run checks:

```bash
make test
make demo
```

3. Commit changes:

```bash
git add .
git commit -m "release: v0.x.y"
```

4. Create and push a tag:

```bash
git tag v0.x.y
git push origin main --tags
```

5. GitHub Actions will build distributions and create the release automatically.
