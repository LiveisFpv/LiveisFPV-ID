package main

import (
	"authorization_service/internal/app"
	"authorization_service/internal/config"
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

func main() {
	// TODO: инициализировать объект конфига
	cfg := config.MustLoad()

	// TODO: инициализировать логгер
	log := setupLogger()

	// TODO: инициализировать приложение (app)
	ctx := context.Background()
	application := app.New(ctx, log, cfg.GRPC.Port, cfg.Dsn, cfg.TokenTTL)

	log.Info("Start service")
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
	log.Info("Postgres connection closed")
}

func setupLogger() *logrus.Logger {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	return log
}
