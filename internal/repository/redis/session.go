package redis

import (
	"context"
	"fmt"
)

// ! Create session on redis
func (sr *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	return fmt.Errorf("not implemented")
}
func (sr *sessionRepository) Get(ctx context.Context, sessionID string) (*domain.Session, error) {
	return nil, fmt.Errorf("not implemented")
}
func (sr *sessionRepository) Delete(ctx context.Context, sessionID string) error {
	return fmt.Errorf("not implemented")
}
