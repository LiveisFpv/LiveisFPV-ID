package auth

import (
	"authorization_service/internal/domain/models"
	"context"
	"log/slog"
	"time"
)

type UserStorage interface {
	SaveUser(ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
	User(ctx context.Context, email string) (models.User, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

type Auth struct {
	log         *slog.Logger
	userStorage UserStorage
	appProvider AppProvider
	tokenTTL    time.Duration
}

func New(
	log *slog.Logger,
	userStorage UserStorage,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		userStorage: userStorage,
		log:         log,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
	}
}
