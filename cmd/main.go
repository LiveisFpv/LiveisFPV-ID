package main

import (
	"authorization_service/internal/app"
	"authorization_service/internal/config"
	"authorization_service/internal/repository/postgres"
	"authorization_service/internal/repository/redis"
	"authorization_service/internal/transport/http"
	"authorization_service/pkg/logger"
	"authorization_service/pkg/storage"
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// @title SSO API
// @version 0.1
// @description SSO для регистрации и авторизации сервисов
// @host localhost:8080
// @BasePath /
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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

	SessionRepo := redis.NewSessionRepository(redisClient)
	UserRepo := postgres.NewUserRepository(pgPool)
	TokenBlock := redis.NewTokenBlocklist(redisClient)

	usecase := app.NewApp(cfg, SessionRepo, UserRepo, TokenBlock, logger)
	// ! Init REST
	server := http.NewHTTPServer(cfg, usecase)
	logger.Info("Start HTTP server")
	go func() {
		err = server.Listen()
		if err != nil {
			logger.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()
	//Wait for interrupt signal to shutdown server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutdown HTTP Server ...")

	// ! Init gRPC

	// ! Graceful shutdown
	err = server.Stop(ctx)
	if err != nil {
		logger.Fatal("Server Shutdown:", err)
	}
	select {
	case <-ctx.Done():
		logger.Info("Timeout stop server")
	default:
		logger.Info("Server exiting")
	}

}
