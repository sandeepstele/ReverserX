.PHONY: install format lint typecheck test check doctor

install:
	uv sync --extra dev

format:
	uv run ruff format .

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy

test:
	uv run pytest

check: lint typecheck test

doctor:
	uv run reverserx doctor
