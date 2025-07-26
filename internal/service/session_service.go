package service

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

type SessionService interface {
	CreateSession(ctx context.Context, refreshToken string) (*domain.Session, error)
	GetSessionByRefreshToken(ctx context.Context, token string) (*domain.Session, error)
	GetAllUserSessions(ctx context.Context, userID int) ([]*domain.Session, error)
	DeleteSession(ctx context.Context, sessionID int) error
	DeleteAllUserSessions(ctx context.Context, userID int) error
	ValidateSession(ctx context.Context, refreshToken string) (*domain.Session, error)
}

type sessionService struct {
	sessionRepository repository.SessionRepository
	jwtService        JWTService
	logger            *logrus.Logger
}

func NewSessionService(sessionRepository repository.SessionRepository, jwtService JWTService, logger *logrus.Logger) SessionService {
	return &sessionService{
		sessionRepository: sessionRepository,
		jwtService:        jwtService,
		logger:            logger,
	}
}

// CreateSession implements SessionService.
// !TODO add user agent and ip address
func (s *sessionService) CreateSession(ctx context.Context, refreshToken string) (*domain.Session, error) {
	claims, err := s.jwtService.ParseToken(refreshToken)
	if err != nil {
		return nil, err
	}

	existingSession, err := s.sessionRepository.GetSessionByRefreshToken(ctx, refreshToken)
	if err == nil && existingSession != nil {
		return nil, fmt.Errorf("session already exists with this token: %s", refreshToken)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session by refresh token: %w", err)
	}

	session := &domain.Session{
		UserID:       claims.UserID,
		RefreshToken: refreshToken,
		UserAgent:    "",
		IPAddress:    "",
		ExpiresAt:    claims.ExpiresAt.Time,
		CreatedAt:    claims.IssuedAt.Time,
	}
	err = s.sessionRepository.CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}
	return session, nil
}

// DeleteAllUserSessions implements SessionService.
func (s *sessionService) DeleteAllUserSessions(ctx context.Context, userID int) error {
	sessions, err := s.GetAllUserSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	for _, session := range sessions {
		if err := s.DeleteSession(ctx, session.SessionID); err != nil {
		}
	}

	return nil
}

// DeleteSession implements SessionService.
func (s *sessionService) DeleteSession(ctx context.Context, sessionID int) error {
	session, err := s.sessionRepository.GetSession(ctx, sessionID)
	if err != nil || session == nil {
		return fmt.Errorf("session not found: %w", err)
	}

	err = s.sessionRepository.DeleteSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// GetAllUserSessions implements SessionService.
func (s *sessionService) GetAllUserSessions(ctx context.Context, userID int) ([]*domain.Session, error) {
	sessions, err := s.sessionRepository.GetAllUserSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	var activeSessions []*domain.Session
	for _, session := range sessions {
		if session.ExpiresAt.After(time.Now()) {
			activeSessions = append(activeSessions, session)
		}
	}

	return activeSessions, nil
}

// GetSessionByRefreshToken implements SessionService.
func (s *sessionService) GetSessionByRefreshToken(ctx context.Context, token string) (*domain.Session, error) {
	session, err := s.sessionRepository.GetSessionByRefreshToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get session by refresh token: %w", err)
	}
	if session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session has expired")
	}
	return session, nil
}

// ValidateSession implements SessionService.
func (s *sessionService) ValidateSession(ctx context.Context, refreshToken string) (*domain.Session, error) {
	claims, err := s.jwtService.ParseToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	session, err := s.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	if session.UserID != claims.UserID {
		return nil, fmt.Errorf("session validation failed")
	}

	if session.ExpiresAt.Before(time.Now()) {
		err = s.sessionRepository.DeleteSession(ctx, session.SessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to delete expired session: %w", err)
		}
		return nil, fmt.Errorf("session has expired")
	}

	return session, nil
}
