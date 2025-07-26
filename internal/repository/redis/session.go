package redis

import (
	"authorization_service/internal/domain"
	"context"
)

// ! Create session on redis
// CreateSession implements repository.SessionRepository.
func (s *sessionRepository) CreateSession(ctx context.Context, session *domain.Session) error {
	panic("unimplemented")
}

// DeleteSession implements repository.SessionRepository.
func (s *sessionRepository) DeleteSession(ctx context.Context, sessionID int) error {
	panic("unimplemented")
}

// GetAllUserSessions implements repository.SessionRepository.
func (s *sessionRepository) GetAllUserSessions(ctx context.Context, userID int) ([]*domain.Session, error) {
	panic("unimplemented")
}

// GetSession implements repository.SessionRepository.
func (s *sessionRepository) GetSession(ctx context.Context, sessionID int) (*domain.Session, error) {
	panic("unimplemented")
}

// GetSessionByRefreshToken implements repository.SessionRepository.
func (s *sessionRepository) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*domain.Session, error) {
	panic("unimplemented")
}
