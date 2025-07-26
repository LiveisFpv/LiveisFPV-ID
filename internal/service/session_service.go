package service

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	ErrSessionAlreadyExists    = errors.New("session already exists with this token")
	ErrSessionNotFound         = errors.New("session not found")
	ErrSessionExpired          = errors.New("session has expired")
	ErrSessionValidationFailed = errors.New("session validation failed")
	ErrInvalidToken            = errors.New("invalid token")

	ErrGetSessionByRefreshToken = errors.New("failed to get session by refresh token")
	ErrSaveSession              = errors.New("failed to save session")
	ErrDeleteSession            = errors.New("failed to delete session")
	ErrGetUserSessions          = errors.New("failed to get user sessions")
)

type SessionService interface {
	CreateSession(ctx context.Context, refreshToken string, access_jti string) (*domain.Session, error)
	GetSessionByRefreshToken(ctx context.Context, token string) (*domain.Session, error)
	GetAllUserSessions(ctx context.Context, userID int) ([]*domain.Session, error)
	DeleteSession(ctx context.Context, sessionID int) error
	DeleteAllUserSessions(ctx context.Context, userID int) error
	ValidateSession(ctx context.Context, refreshToken string) (*domain.Session, error)
}

type sessionService struct {
	sessionRepository repository.SessionRepository
	blockList         repository.TokenBlocklist
	jwtService        JWTService
	logger            *logrus.Logger
}

func NewSessionService(sessionRepository repository.SessionRepository, blockListRepository repository.TokenBlocklist, jwtService JWTService, logger *logrus.Logger) SessionService {
	return &sessionService{
		sessionRepository: sessionRepository,
		blockList:         blockListRepository,
		jwtService:        jwtService,
		logger:            logger,
	}
}

// CreateSession implements SessionService.
// !TODO add user agent and ip address
func (s *sessionService) CreateSession(ctx context.Context, refreshToken string, access_jti string) (*domain.Session, error) {
	claims, err := s.jwtService.ParseToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	existingSession, err := s.sessionRepository.GetSessionByRefreshToken(ctx, refreshToken)
	if err == nil && existingSession != nil {
		return nil, ErrSessionAlreadyExists
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGetSessionByRefreshToken, err)
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
		return nil, fmt.Errorf("%w: %v", ErrSaveSession, err)
	}
	return session, nil
}

// DeleteAllUserSessions implements SessionService.
func (s *sessionService) DeleteAllUserSessions(ctx context.Context, userID int) error {
	sessions, err := s.GetAllUserSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGetUserSessions, err)
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
		return ErrSessionNotFound
	}

	s.blockList.Block(ctx, session.JTI, time.Until(session.ExpiresAt))

	err = s.sessionRepository.DeleteSession(ctx, sessionID)
	if err != nil {
		return ErrDeleteSession
	}

	return nil
}

// GetAllUserSessions implements SessionService.
func (s *sessionService) GetAllUserSessions(ctx context.Context, userID int) ([]*domain.Session, error) {
	sessions, err := s.sessionRepository.GetAllUserSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGetUserSessions, err)
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
		return nil, ErrGetSessionByRefreshToken
	}
	if session.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionExpired
	}
	return session, nil
}

// ValidateSession implements SessionService.
func (s *sessionService) ValidateSession(ctx context.Context, refreshToken string) (*domain.Session, error) {
	claims, err := s.jwtService.ParseToken(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	session, err := s.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	if session.UserID != claims.UserID {
		return nil, ErrSessionValidationFailed
	}

	if session.ExpiresAt.Before(time.Now()) {
		err = s.sessionRepository.DeleteSession(ctx, session.SessionID)
		if err != nil {
			return nil, ErrDeleteSession
		}
		return nil, ErrSessionExpired
	}

	return session, nil
}
