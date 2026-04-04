.PHONY: all sync format reformat-ruff check fix-ruff fix pyright vulture bandit complexity xenon test integration validate

all: validate test

sync:
	uv sync --group dev

format:
	uv run ruff format --check --diff .

reformat-ruff:
	uv run ruff format .

check:
	uv run ruff check .

fix-ruff:
	uv run ruff check . --fix

fix: reformat-ruff fix-ruff
	@echo "Updated code."

pyright:
	uv run pyright

vulture:
	uv run vulture src --config pyproject.toml

bandit:
	uv run bandit -r src -c pyproject.toml

complexity:
	uv run radon cc src -a -nc

xenon:
	uv run xenon -b D -m B -a B src

test:
	uv run pytest -m "not integration"

integration:
	uv run pytest -m integration tests/integration

validate: format check pyright vulture complexity
	@echo "Validation passed. Your code is ready to push."
