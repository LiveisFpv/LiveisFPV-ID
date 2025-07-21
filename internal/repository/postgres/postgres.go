package postgres

import (
	"authorization_service/internal/repository"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrorUserNotFound     = errors.New("user not found")
	ErrorUserAlreadyExist = errors.New("user already exist")
	ErrorInvalidToken     = errors.New("invalid token")
	ErrorTokenExpired     = errors.New("token expired")
)

type userRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) repository.UserRepository {
	return userRepository{db: db}
}

func (ur *userRepository) GetUserByID(ctx context.Context, id int) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ur *userRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ur *userRepository) GetUserByGoogleID(ctx context.Context, id string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ur *userRepository) GetUserByVkID(ctx context.Context, id string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ur *userRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	return fmt.Errorf("not implemented")
}

func (ur *userRepository) CreateUser(ctx context.Context, user *domain.User) error {
	return fmt.Errorf("not implemented")
}

func (ur *userRepository) ConfirmEmail(ctx context.Context, userID int) error {
	return fmt.Errorf("not implemented")
}
