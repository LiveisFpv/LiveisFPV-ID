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
    // Check existence instead of GET to avoid treating missing keys as errors
    exists, err := t.redis.Exists(ctx, jti)
    if err != nil {
        return false, err
    }
    return exists, nil
}
