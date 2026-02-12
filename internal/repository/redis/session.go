package redis

import (
	"authorization_service/internal/domain"
	"context"
	"fmt"
	"time"
)

// CreateSession implements repository.SessionRepository.
func (s *sessionRepository) CreateSession(ctx context.Context, session *domain.Session) error {
	key := fmt.Sprintf("session:%s", session.SessionID)
	err := s.redis.Set(ctx, key, session, time.Until(session.ExpiresAt))
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrorSetSession, err)
	}

	userSessionsKey := fmt.Sprintf("user_sessions:%d", session.UserID)

	err = s.redis.SAdd(ctx, userSessionsKey, session.SessionID)
	if err != nil {
		s.redis.Delete(ctx, key)
		return fmt.Errorf("%w: %v", domain.ErrorFailedToAddUserSession, err)
	}

	tokenkey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)
	err = s.redis.Set(ctx, tokenkey, session, time.Until(session.ExpiresAt))
	if err != nil {
		s.redis.Delete(ctx, key)
		s.redis.SRem(ctx, userSessionsKey, session.SessionID)
		return fmt.Errorf("%w: %v", domain.ErrorFailedToSetRefreshToken, err)
	}

	return nil
}

// DeleteSession implements repository.SessionRepository.
func (s *sessionRepository) DeleteSession(ctx context.Context, sessionID string) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("session:%s", sessionID)
	err = s.redis.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrorFailedToDeleteSession, err)
	}

	userSessionsKey := fmt.Sprintf("user_sessions:%d", session.UserID)
	err = s.redis.SRem(ctx, userSessionsKey, sessionID)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrorFailedToDeleteUserSession, err)
	}

	tokenkey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)
	err = s.redis.Delete(ctx, tokenkey)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrorFailedToDeleteRefreshToken, err)
	}
	return nil
}

// GetAllUserSessions implements repository.SessionRepository.
func (s *sessionRepository) GetAllUserSessions(ctx context.Context, userID int) ([]*domain.Session, error) {
	userSessionsKey := fmt.Sprintf("user_sessions:%d", userID)
	sessionIDs, err := s.redis.SMembers(ctx, userSessionsKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrorFailedToGetUserSessions, err)
	}
	sessions := make([]*domain.Session, 0, len(sessionIDs))
	for _, idStr := range sessionIDs {
		id := idStr
		session, err := s.GetSession(ctx, id)
		if err == nil {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// GetSession implements repository.SessionRepository.
func (s *sessionRepository) GetSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	key := fmt.Sprintf("session:%s", sessionID)
	session := &domain.Session{}
	err := s.redis.Get(ctx, key, session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// GetSessionByRefreshToken implements repository.SessionRepository.
func (s *sessionRepository) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*domain.Session, error) {
	tokenKey := fmt.Sprintf("refresh_token:%s", refreshToken)
	session := &domain.Session{}
	err := s.redis.Get(ctx, tokenKey, session)

	if err != nil {
		return nil, domain.ErrorSessionNotFound
	}

	return session, nil
}
