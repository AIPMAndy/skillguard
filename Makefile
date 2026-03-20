PYTHON ?= python3

.PHONY: help install install-dev test unittest pytest scan demo clean

help:
	@echo "Available targets:"
	@echo "  install      Install package"
	@echo "  install-dev  Install package + dev dependencies"
	@echo "  test         Run all tests"
	@echo "  unittest     Run unittest suite"
	@echo "  pytest       Run pytest suite"
	@echo "  scan         Run safeskill against this repo"
	@echo "  demo         Run demo scan against examples/dangerous-skill"
	@echo "  clean        Remove common cache files"

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e .[dev]

test: unittest pytest

unittest:
	$(PYTHON) -m unittest tests.test_safeskill -v

pytest:
	$(PYTHON) -m pytest tests/ -q

scan:
	$(PYTHON) safeskill.py . --format json --quiet

demo:
	$(PYTHON) safeskill.py ./examples/dangerous-skill

clean:
	find . -type d \( -name __pycache__ -o -name .pytest_cache -o -name .tox \) -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
