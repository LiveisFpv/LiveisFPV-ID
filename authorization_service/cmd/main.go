package main

import (
	"authorization_service/internal/app"
	"authorization_service/internal/config"
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	// TODO: инициализировать объект конфига
	cfg := config.MustLoad()

	// TODO: инициализировать логгер
	log := setupLogger(cfg.Env)

	// TODO: инициализировать приложение (app)
	ctx := context.Background()
	application := app.New(ctx, log, cfg.GRPC.Port, cfg.Dsn, cfg.TokenTTL)

	// TODO: запустить gRPC-сервер приложения
	go func() {
		application.GRPCServer.MustRun()
	}()

	// Graceful shutdown

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	// Waiting for SIGINT (pkill -2) or SIGTERM
	<-stop

	// initiate graceful shutdown
	application.GRPCServer.Stop() // Assuming GRPCServer has Stop() method for graceful shutdown
	log.Info("Gracefully stopped")
	application.Storage.Stop()
	log.Info("AuthService stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	//Chose env for loger
	switch env {
	case envLocal:
		//for local start
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		//On dev server
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		//For production only Info logs
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}
	return log
}
