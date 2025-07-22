package domain

import "time"

type Session struct {
	ID           int
	UserID       int
	RefreshToken string
	UserAgent    string
	IPAddress    string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}
