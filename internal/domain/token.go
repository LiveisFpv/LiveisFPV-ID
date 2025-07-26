package domain

import "github.com/golang-jwt/jwt/v5"

type TokenType string

const (
	AccessTokenType  TokenType = "access_token"
	RefreshTokenType TokenType = "refresh_token"
	TokenTypeKey               = "token_type"
)

type UserTokens struct {
	AccessToken  string
	RefreshToken string
}

type TokenClaims struct {
	jwt.RegisteredClaims
	UserID    int       `json:"user_id"`
	TokenType TokenType `json:"token_type"`
}

type EmailConfirmationClaims struct {
	jwt.RegisteredClaims
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
}
