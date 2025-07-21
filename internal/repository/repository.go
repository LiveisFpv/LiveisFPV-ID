package repository

import (
	"authorization_service/internal/domain"
	"context"
)

type UserRepository interface {
	GetUserByID(ctx context.Context, id int) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	GetUserByGoogleID(ctx context.Context, id string) (*domain.User, error)
	GetUserByVkID(ctx context.Context, id string) (*domain.User, error)
	UpdateUser(ctx context.Context, user *domain.User) error
	CreateUser(ctx context.Context, user *domain.User) error
	ConfirmEmail(ctx context.Context, userID int) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
	Get(ctx context.Context, sessionID string) (*domain.Session, error)
	Delete(ctx context.Context, sessionID string) error
}
