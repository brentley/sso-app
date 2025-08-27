.PHONY: help dev test build deploy logs shell stop clean

help:
	@echo "Available commands:"
	@echo "  make dev     - Start development environment"
	@echo "  make test    - Run tests"
	@echo "  make build   - Build Docker image"
	@echo "  make deploy  - Deploy to production"
	@echo "  make logs    - View logs"
	@echo "  make shell   - Access container shell"
	@echo "  make stop    - Stop all containers"
	@echo "  make clean   - Clean up everything"
	@echo "  make init    - Initialize database"

dev:
	@echo "Starting development environment..."
	docker compose -f docker-compose.dev.yml up --build

test:
	@echo "Running tests..."
	docker compose -f docker-compose.dev.yml run --rm sso-app-dev pytest tests/ -v

build:
	@echo "Building production image..."
	docker compose build

deploy:
	@echo "Deployment is automated via GitHub Actions"
	@echo "Push to main branch to trigger deployment"

logs:
	docker compose logs -f

shell:
	docker compose exec sso-app /bin/bash

stop:
	@echo "Stopping all containers..."
	docker compose -f docker-compose.dev.yml down
	docker compose down

clean:
	@echo "Cleaning up everything..."
	docker compose -f docker-compose.dev.yml down -v
	docker compose down -v
	docker system prune -f

init:
	@echo "Initializing database..."
	docker compose -f docker-compose.dev.yml run --rm sso-app-dev python -c "from app import db; db.create_all()"