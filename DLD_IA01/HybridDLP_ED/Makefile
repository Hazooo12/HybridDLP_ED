# Makefile cho HybridDLP Docker Management

.PHONY: help build up down restart logs clean test

help:
	@echo "HybridDLP Docker Management"
	@echo ""
	@echo "Commands:"
	@echo "  make build      - Build all Docker images"
	@echo "  make up         - Start all services"
	@echo "  make down       - Stop and remove containers"
	@echo "  make restart    - Restart all services"
	@echo "  make logs       - Show logs (all services)"
	@echo "  make logs-worker - Show worker logs"
	@echo "  make logs-dashboard - Show dashboard logs"
	@echo "  make clean      - Remove containers, volumes, and images"
	@echo "  make test       - Run health checks"
	@echo "  make dev        - Start in development mode"
	@echo "  make prod       - Start in production mode"

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

restart:
	docker-compose restart

logs:
	docker-compose logs -f

logs-worker:
	docker-compose logs -f worker

logs-dashboard:
	docker-compose logs -f dashboard

clean:
	docker-compose down -v
	docker system prune -f

test:
	@echo "Testing Worker health..."
	@docker ps | grep -q hybrid-dlp-worker && echo "✅ Worker is running" || echo "❌ Worker not running"
	@echo "Testing Dashboard..."
	@curl -f http://localhost:8501/_stcore/health > /dev/null 2>&1 && echo "✅ Dashboard is accessible" || echo "❌ Dashboard not accessible"

dev:
	docker-compose -f docker-compose.dev.yml up -d

prod:
	docker-compose up -d

shell-worker:
	docker exec -it hybrid-dlp-worker bash

shell-dashboard:
	docker exec -it hybrid-dlp-dashboard bash

stats:
	docker stats
