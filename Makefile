.PHONY: all sync format reformat-ruff check fix-ruff fix pyright vulture bandit complexity xenon test integration validate probe-corpus-build-image probe-corpus-generate probe-corpus-validate refresh-with-probe-corpus

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

probe-corpus-build-image:
	docker build -f docker/probe-corpus.Dockerfile -t resolver-inventory-probe-corpus .

probe-corpus-generate: probe-corpus-build-image
	mkdir -p outputs/probe-corpus
	docker run --rm -v "$$(pwd)/outputs/probe-corpus:/out" resolver-inventory-probe-corpus

probe-corpus-validate: probe-corpus-generate
	uv run resolver-inventory validate-probe-corpus --config configs/probe-corpus.toml --input outputs/probe-corpus/probe-corpus.json --schema-version 2

refresh-with-probe-corpus: probe-corpus-validate
	uv run resolver-inventory refresh --config configs/default.toml --probe-corpus outputs/probe-corpus/probe-corpus.json --output outputs/latest
