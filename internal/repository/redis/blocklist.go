package redis

import (
	"context"
	"time"
)

// Block implements repository.TokenBlocklist.
func (t *TokenBlocklist) Block(ctx context.Context, jti string, exp time.Duration) error {
	// Set the token in Redis with an expiration time
	err := t.redis.Set(ctx, jti, "true", exp)
	if err != nil {
		return err
	}
	return nil
}

// IsBlocked implements repository.TokenBlocklist.
func (t *TokenBlocklist) IsBlocked(ctx context.Context, jti string) (bool, error) {
	// Check if the token is blocked in Redis
	var blocked string
	err := t.redis.Get(ctx, jti, &blocked)
	if err != nil {
		if err.Error() == "redis: nil" {
			return false, nil
		}
		return false, err
	}

	return blocked == "true", nil
}
