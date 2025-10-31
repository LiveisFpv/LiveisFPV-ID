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
    // ListUsers returns a page of users matching provided filter and total count
    ListUsers(ctx context.Context, filter UserListFilter, page, limit int) ([]*domain.User, int, error)
}

// UserListFilter defines filter options for listing users
type UserListFilter struct {
    // Query performs case-insensitive match against first_name, last_name and email
    Query string
    // Role filters by role existing in roles array
    Role *string
    // EmailConfirmed filters by email confirmation status
    EmailConfirmed *bool
    // Locale filters by locale value
    Locale *string
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
