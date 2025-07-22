package service

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
)

type SessionService interface {
	CreateSession(ctx context.Context, userID int, refreshToken string) (*domain.Session, error)
	GetSessionByRefreshToken(ctx context.Context, token string) (*domain.Session, error)
	DeleteSession(ctx context.Context, sessionID int) error
	DeleteAllUserSessions(ctx context.Context, userID int) error
}

type sessionService struct {
	sessionRepository repository.SessionRepository
}

func NewSessionService(sessionRepository repository.SessionRepository) SessionService {
	return &sessionService{
		sessionRepository: sessionRepository,
	}
}

// CreateSession implements SessionService.
func (s *sessionService) CreateSession(ctx context.Context, userID int, refreshToken string) (*domain.Session, error) {
	panic("unimplemented")
}

// DeleteAllUserSessions implements SessionService.
func (s *sessionService) DeleteAllUserSessions(ctx context.Context, userID int) error {
	panic("unimplemented")
}

// DeleteSession implements SessionService.
func (s *sessionService) DeleteSession(ctx context.Context, sessionID int) error {
	panic("unimplemented")
}

// GetSessionByRefreshToken implements SessionService.
func (s *sessionService) GetSessionByRefreshToken(ctx context.Context, token string) (*domain.Session, error) {
	panic("unimplemented")
}
