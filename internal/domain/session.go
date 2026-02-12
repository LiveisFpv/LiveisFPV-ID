package domain

import (
	"errors"
	"time"
)

type Session struct {
	SessionID    string
	UserID       int
	RefreshToken string
	JTI          string
	UserAgent    string
	IPAddress    string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

var (
	ErrorMarshalSession             = errors.New("failed to marshal session")
	ErrorSessionNotFound            = errors.New("session not found")
	ErrorUnmarshalSession           = errors.New("failed to unmarshal session")
	ErrorSetSession                 = errors.New("failed to set session in redis")
	ErrorFailedToAddUserSession     = errors.New("failed to add user session to set")
	ErrorFailedToSetRefreshToken    = errors.New("failed to set refresh token in redis")
	ErrorFailedToGetUserSessions    = errors.New("failed to get user sessions from set")
	ErrorFailedToDeleteSession      = errors.New("failed to delete session")
	ErrorFailedToDeleteRefreshToken = errors.New("failed to delete refresh token")
	ErrorFailedToDeleteUserSession  = errors.New("failed to delete user session from set")

	ErrorSessionAlreadyExists    = errors.New("session already exists with this token")
	ErrorSessionExpired          = errors.New("session has expired")
	ErrorSessionValidationFailed = errors.New("session validation failed")
	ErrorInvalidToken            = errors.New("invalid token")

	ErrorGetSessionByRefreshToken = errors.New("failed to get session by refresh token")
	ErrorSaveSession              = errors.New("failed to save session")
	ErrorDeleteSession            = errors.New("failed to delete session")
	ErrorGetUserSessions          = errors.New("failed to get user sessions")
)
