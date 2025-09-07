## Makefile for local dev and deploy (to run directly on VPS)

# -------- Variables --------
NETWORK_NAME ?= grpc_network
# Choose your compose command. Override if you use Docker Compose v2 plugin
# e.g., make deploy DC="docker compose"
DC ?= docker-compose
CORE_SERVICE ?= core

.PHONY: up down logs rebuild network clean \
        restart ps \
        swag \
        deploy pull migrate

# -------- Local / VPS (Docker) --------

deploy: network ## Build and start stack in detached mode
	$(DC) up -d --build

up: deploy ## Alias of deploy

down: ## Stop containers
	$(DC) down

pull: ## Pull images (if any services use image: tag)
	$(DC) pull || true

logs: ## Tail logs
	$(DC) logs -f

rebuild: network ## Rebuild without cache and start
	$(DC) build --no-cache
	$(DC) up -d

restart: ## Restart core service
	$(DC) restart $(CORE_SERVICE)

ps: ## Show container status
	$(DC) ps

network: ## Ensure external grpc network exists
	@if ! docker network inspect $(NETWORK_NAME) >/dev/null 2>&1; then \
		echo "Creating external network $(NETWORK_NAME)..."; \
		docker network create $(NETWORK_NAME); \
	else \
		echo "Network $(NETWORK_NAME) already exists."; \
	fi

clean: down ## Prune unused docker data (careful!)
	docker system prune -f
	- docker volume rm $$(docker volume ls -qf dangling=true)

migrate: ## Run migrator once (if needed)
	$(DC) run --rm migrator || true

swag: ## Regenerate swagger docs (requires swag installed)
	swag init -g cmd/main.go -o docs
