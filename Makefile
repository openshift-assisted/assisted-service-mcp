IMAGE_NAME ?= quay.io/carbonin/assisted-service-mcp
TAG ?= latest

.PHONY: build
build:
	podman build -t $(IMAGE_NAME):$(TAG) .

.PHONY: push
push:
	podman push $(IMAGE_NAME):$(TAG)

.PHONY: run
run:
	podman run --rm -p 127.0.0.1:8000:8000 $(IMAGE_NAME):$(TAG)

.PHONY: run-local
run-local:
	uv run python -m assisted_service_mcp.src.main

.PHONY: run-mock-assisted
run-mock-assisted:
	cd integration_test/mock_server && go run mock_server.go

.PHONY: test test-coverage test-verbose install-test-deps
test:
	uv run --group test pytest

.PHONY: deploy-template
deploy-template:
	scripts/deploy_from_template.sh

test-coverage:
	uv run --group test pytest --cov=assisted_service_mcp --cov-report=html --cov-report=term-missing

test-verbose:
	uv run --group test pytest -v

install-test-deps:
	uv sync --group test

.PHONY: black pylint pyright docstyle ruff check-types verify format
black:
	uv run black --check .

pylint:
	uv run pylint .

pyright:
	uv run pyright .

docstyle:
	uv run pydocstyle -v .

ruff:
	uv run ruff check .

check-types:
	uv run mypy --config-file pyproject.toml .

verify: black pylint pyright ruff check-types test

format:
	uv run black .
	uv run ruff check . --fix
