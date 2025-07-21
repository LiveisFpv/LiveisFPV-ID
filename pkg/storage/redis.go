package storage

import (
	"authorization_service/internal/config"
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

func RedisConnect(ctx context.Context, cfg config.RedisConfig) (client *redis.Client, err error) {
	client = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	return client, nil
}
