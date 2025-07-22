package domain

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
