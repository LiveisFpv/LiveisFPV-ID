package app

import (
	grpcapp "authorization_service/internal/app/grpc"
	"authorization_service/internal/services/auth"
	postgresql "authorization_service/internal/storage/postgreSQL"
	"context"
	"log/slog"
	"time"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(
	ctx context.Context,
	log *slog.Logger,
	grpcPort int,
	dsn string,
	tokenTTL time.Duration,
) *App {
	storage, err := postgresql.NewStorage(ctx, dsn, log)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCServer: grpcApp,
	}
}
