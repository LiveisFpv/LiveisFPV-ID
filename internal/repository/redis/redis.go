package redis

import (
	"authorization_service/internal/repository"
	"authorization_service/pkg/storage"
	"errors"
)

var (
	ErrorSessionNotFound = errors.New("session not found")
)

type sessionRepository struct {
	redis *storage.RedisClient
}

func NewSessionRepository(redis *storage.RedisClient) repository.SessionRepository {
	return &sessionRepository{redis: redis}
}
