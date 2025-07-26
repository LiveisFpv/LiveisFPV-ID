package storage

import (
	"authorization_service/internal/config"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client *redis.Client
}

func RedisConnect(ctx context.Context, cfg config.RedisConfig) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	return &RedisClient{
		client: client,
	}, nil
}

func (r *RedisClient) Close() error {
	return r.client.Close()
}

func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.Set(ctx, key, jsonValue, expiration).Err()
}

func (r *RedisClient) Get(ctx context.Context, key string, dest interface{}) error {
	val, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("key not found: %s", key)
		}
		return fmt.Errorf("failed to get value: %w", err)
	}

	if err := json.Unmarshal(val, dest); err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	return nil
}

func (r *RedisClient) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *RedisClient) SAdd(ctx context.Context, key string, members ...interface{}) error {
	if len(members) == 0 {
		return nil // No members to add
	}
	return r.client.SAdd(ctx, key, members...).Err()
}

func (r *RedisClient) SRem(ctx context.Context, key string, members ...interface{}) error {
	if len(members) == 0 {
		return nil // No members to remove
	}
	return r.client.SRem(ctx, key, members...).Err()
}

func (r *RedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	val, err := r.client.SMembers(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("key not found: %s", key)
		}
		return nil, fmt.Errorf("failed to get members: %w", err)
	}
	// if len(val) == 0 {
	// 	return nil, fmt.Errorf("no members found for key: %s", key)
	// }
	return val, nil
}

func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	val, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}
	return val > 0, nil
}

func (r *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get TTL: %w", err)
	}
	return ttl, nil
}
