.PHONY: help setup install lint format typecheck test test-cov clean run train simulate api docker-build docker-up docker-down

help:
	@echo "DMARRSS Development Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  setup         - Install all dependencies (including dev)"
	@echo "  install       - Install package in editable mode"
	@echo "  lint          - Run linting checks (ruff)"
	@echo "  format        - Format code with black"
	@echo "  typecheck     - Run mypy type checking"
	@echo "  test          - Run test suite"
	@echo "  test-cov      - Run tests with coverage report"
	@echo "  clean         - Remove build artifacts and cache files"
	@echo "  run           - Run DMARRSS daemon"
	@echo "  train         - Train/update neural model"
	@echo "  simulate      - Run simulation with synthetic data"
	@echo "  api           - Start REST API server"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-up     - Start Docker Compose services"
	@echo "  docker-down   - Stop Docker Compose services"

setup:
	pip install -e ".[dev]"
	pre-commit install

install:
	pip install -e .

lint:
	ruff check src/ tests/
	black --check src/ tests/

format:
	black src/ tests/
	ruff check --fix src/ tests/

typecheck:
	mypy src/dmarrss/

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=src/dmarrss --cov-report=term-missing --cov-report=html

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

run:
	dmarrss run

train:
	dmarrss train

simulate:
	dmarrss simulate

api:
	dmarrss api

docker-build:
	docker build -t dmarrss:latest -f docker/Dockerfile .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down
