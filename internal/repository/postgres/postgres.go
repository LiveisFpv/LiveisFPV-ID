package postgres

import (
	"authorization_service/internal/repository"
	"errors"

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
	return &userRepository{db: db}
}
