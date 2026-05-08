.PHONY: build clean install test lint

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

build: clean
	$(PIP) install -q build
	$(PYTHON) -m build
	@echo "Wheel ready in dist/"

clean:
	rm -rf dist/ build/ *.egg-info

install: build
	$(PIP) install dist/*.whl

test:
	$(VENV)/bin/pytest -v

lint:
	$(VENV)/bin/ruff check .

$(VENV):
	python3 -m venv $(VENV)
	$(PIP) install -q -e ".[dev]"

dev: $(VENV)
