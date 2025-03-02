package auth

import (
	"authorization_service/internal/domain/models"
	"authorization_service/internal/lib/jwt"
	"authorization_service/internal/storage"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
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
	log         *logrus.Logger
	userStorage UserStorage
	appProvider AppProvider
	tokenTTL    time.Duration
}

func New(
	log *logrus.Logger,
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

func (a *Auth) RegisterNewUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "Auth.RegisterNewUser"

	//logging information without password
	log := a.log.WithFields(
		logrus.Fields{
			"op":    op,
			"email": email,
		},
	)

	log.Info("registering user")

	//Generate salt and hash for password
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", err)
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	//Save user to database
	id, err := a.userStorage.SaveUser(ctx, email, passHash)
	if err != nil {
		log.Error("failed ti save user", err)
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {
	const op = "Auth.Login"

	log := a.log.WithFields(
		logrus.Fields{
			"op":    op,
			"email": email,
		},
	)

	log.Info("attempting ti login user")

	user, err := a.userStorage.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", err)

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", err)

		return "", fmt.Errorf("%s: %w", op, err)
	}
	// Проверяем корректность полученного пароля
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", err)

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	// Получаем информацию о приложении
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	// Создаём токен авторизации
	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", err)

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}
