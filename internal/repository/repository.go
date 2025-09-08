package repository

import (
	"authorization_service/internal/domain"
	"context"
	"errors"
	"time"
)

var (
	ErrorUserNotFound     = errors.New("user not found")
	ErrorUserAlreadyExist = errors.New("user already exist")
	ErrorInvalidToken     = errors.New("invalid token")
	ErrorTokenExpired     = errors.New("token expired")
)

type UserRepository interface {
	GetUserByID(ctx context.Context, id int) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	GetUserByGoogleID(ctx context.Context, id string) (*domain.User, error)
	GetUserByYandexID(ctx context.Context, id string) (*domain.User, error)
	GetUserByVkID(ctx context.Context, id string) (*domain.User, error)
	UpdateUser(ctx context.Context, user *domain.User) error
	SetOauthID(ctx context.Context, userID int, provider string, oauthID string) error
	CreateUser(ctx context.Context, user *domain.User) (userID int, err error)
	ConfirmEmail(ctx context.Context, userID int) error
}

type SessionRepository interface {
	CreateSession(ctx context.Context, session *domain.Session) error
	GetSession(ctx context.Context, sessionID int) (*domain.Session, error)
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*domain.Session, error)
	GetAllUserSessions(ctx context.Context, userID int) ([]*domain.Session, error)
	DeleteSession(ctx context.Context, sessionID int) error
}

type TokenBlocklist interface {
	IsBlocked(ctx context.Context, jti string) (bool, error)
	Block(ctx context.Context, jti string, exp time.Duration) error
}
