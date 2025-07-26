package redis

import (
	"authorization_service/internal/domain"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

var (
	ErrorMarshalSession             = fmt.Errorf("failed to marshal session")
	ErrorSessionNotFound            = fmt.Errorf("session not found")
	ErrorUnmarshalSession           = fmt.Errorf("failed to unmarshal session")
	ErrorSetSession                 = fmt.Errorf("failed to set session in redis")
	ErrorFailedToAddUserSession     = fmt.Errorf("failed to add user session to set")
	ErrorFailedToSetRefreshToken    = fmt.Errorf("failed to set refresh token in redis")
	ErrorFailedToGetUserSessions    = fmt.Errorf("failed to get user sessions from set")
	ErrorFailedToDeleteSession      = fmt.Errorf("failed to delete session")
	ErrorFailedToDeleteRefreshToken = fmt.Errorf("failed to delete refresh token")
	ErrorFailedToDeleteUserSession  = fmt.Errorf("failed to delete user session from set")
)

// CreateSession implements repository.SessionRepository.
func (s *sessionRepository) CreateSession(ctx context.Context, session *domain.Session) error {
	key := fmt.Sprintf("session:%d", session.SessionID)
	data, err := json.Marshal(session)
	if err != nil {
		return ErrorMarshalSession
	}

	err = s.redis.Set(ctx, key, data, time.Until(session.ExpiresAt))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrorSetSession, err)
	}

	userSessionsKey := fmt.Sprintf("user_sessions:%d", session.UserID)

	err = s.redis.SAdd(ctx, userSessionsKey, session.SessionID)
	if err != nil {
		s.redis.Delete(ctx, key)
		return fmt.Errorf("%w: %v", ErrorFailedToAddUserSession, err)
	}

	tokenkey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)
	err = s.redis.Set(ctx, tokenkey, data, time.Until(session.ExpiresAt))
	if err != nil {
		s.redis.Delete(ctx, key)
		s.redis.SRem(ctx, userSessionsKey, session.SessionID)
		return fmt.Errorf("%w: %v", ErrorFailedToSetRefreshToken, err)
	}

	return nil
}

// DeleteSession implements repository.SessionRepository.
func (s *sessionRepository) DeleteSession(ctx context.Context, sessionID int) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("session:%d", sessionID)
	err = s.redis.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrorFailedToDeleteSession, err)
	}

	userSessionsKey := fmt.Sprintf("user_sessions:%d", session.UserID)
	err = s.redis.SRem(ctx, userSessionsKey, sessionID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrorFailedToDeleteUserSession, err)
	}

	tokenkey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)
	err = s.redis.Delete(ctx, tokenkey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrorFailedToDeleteRefreshToken, err)
	}
	return nil
}

// GetAllUserSessions implements repository.SessionRepository.
func (s *sessionRepository) GetAllUserSessions(ctx context.Context, userID int) ([]*domain.Session, error) {
	userSessionsKey := fmt.Sprintf("user_sessions:%d", userID)
	sessionIDs, err := s.redis.SMembers(ctx, userSessionsKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrorFailedToGetUserSessions, err)
	}
	sessions := make([]*domain.Session, 0, len(sessionIDs))
	for _, idStr := range sessionIDs {
		id, _ := strconv.Atoi(idStr)
		session, err := s.GetSession(ctx, id)
		if err == nil {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// GetSession implements repository.SessionRepository.
func (s *sessionRepository) GetSession(ctx context.Context, sessionID int) (*domain.Session, error) {
	key := fmt.Sprintf("session:%d", sessionID)
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
		return nil, fmt.Errorf("%w: %v", ErrorSessionNotFound, err)
	}

	return session, nil
}
