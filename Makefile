# Имя внешней сети
NETWORK_NAME=grpc_network

.PHONY: up down logs rebuild network clean

# Проверка и создание внешней сети, запуск docker-compose
up: network
	docker-compose up --build

# Остановка контейнеров
down:
	docker-compose down

# Вывод логов
logs:
	docker-compose logs -f

# Полная пересборка без использования кэша
rebuild: network
	docker-compose build --no-cache
	docker-compose up

# Создание внешней сети, если её нет
network:
	@if ! docker network inspect $(NETWORK_NAME) >/dev/null 2>&1; then \
		echo "Создание внешней сети $(NETWORK_NAME)..."; \
		docker network create $(NETWORK_NAME); \
	else \
		echo "Сеть $(NETWORK_NAME) уже существует."; \
	fi

# Очистка: остановка, удаление контейнеров, образов и томов
clean: down
	docker system prune -f
	docker volume rm $$(docker volume ls -qf dangling=true) || true
