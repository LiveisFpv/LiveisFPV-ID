package redis

import (
	"authorization_service/internal/repository"
	"authorization_service/pkg/storage"
)

type sessionRepository struct {
	redis *storage.RedisClient
}

func NewSessionRepository(redis *storage.RedisClient) repository.SessionRepository {
	return &sessionRepository{redis: redis}
}

type TokenBlocklist struct {
	redis *storage.RedisClient
}

func NewTokenBlocklist(redis *storage.RedisClient) repository.TokenBlocklist {
	return &TokenBlocklist{redis: redis}
}
