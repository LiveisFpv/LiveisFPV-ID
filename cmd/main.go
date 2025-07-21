package cmd

import (
	"authorization_service/internal/config"
	"authorization_service/pkg/logger"
	"authorization_service/pkg/storage"
	"context"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// ! Init logger
	logger := logger.LoggerSetup(true)
	// ! Parse config from env
	cfg, err := config.MustLoadConfig()
	if err != nil {
		logger.Fatalf("Failed to load config with error: %v", err)
		return
	}
	// ! Init repoisitory
	// ! Init postgres
	pgPool, err := storage.PostgresConnect(ctx, cfg.PostgresConfig)
	if err != nil {
		logger.Fatalf("Failed to create pool conection to postgres with error: %v", err)
		return
	}
	// ! Init redis
	redisClient, err := storage.RedisConnect(ctx, cfg.RedisConfig)
	if err != nil {
		logger.Fatalf("Failed to create conection to redis with error: %v", err)
		return
	}
	// ! Init REST
	// ! Init gRPC

	// ! Graceful shutdown
}
