.PHONY: install format lint typecheck test build check doctor

install:
	uv sync --locked --extra dev --extra phase1

format:
	uv run ruff format .

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy

test:
	uv run pytest

build:
	uv build

check: lint typecheck test build

doctor:
	uv run reverserx doctor
