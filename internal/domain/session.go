package domain

import "time"

type Session struct {
	SessionID    int
	UserID       int
	RefreshToken string
	JTI          string
	UserAgent    string
	IPAddress    string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}
