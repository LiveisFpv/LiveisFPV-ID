package service

import (
	"authorization_service/internal/config"
	"authorization_service/internal/domain"
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt"
)

var (
	ErrorInvalidToken = errors.New("invalid_token")
)

type JWTService interface {
	CreateJwtTokens(ctx context.Context, userID int) (*domain.UserTokens, error)
	VerifyToken(ctx context.Context, token string, tokenType domain.TokenType) (int, error)
}

type jwtService struct {
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	secretKey       string
}

func NewJWTService(config *config.JWTConfig) JWTService {
	return &jwtService{
		accessTokenTTL:  config.AccessTokenTTL,
		refreshTokenTTL: config.RefreshTokenTTL,
		secretKey:       config.SecretKey,
	}
}

// CreateJwtTokens implements JWTService.
func (j *jwtService) CreateJwtTokens(ctx context.Context, userID int) (*domain.UserTokens, error) {
	accessToken, err := j.createAccessToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := j.createRefreshToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &domain.UserTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// VerifyToken implements JWTService.
func (j *jwtService) VerifyToken(ctx context.Context, token string, tokenType domain.TokenType) (int, error) {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Проверка метода подписи
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.secretKey), nil
	})

	if err != nil || !parsedToken.Valid {
		slog.DebugContext(ctx, "Token is invalid", slog.String("token", token))
		return 0, ErrorInvalidToken
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		slog.DebugContext(ctx, "Invalid token", slog.String("token", token))
		return 0, ErrorInvalidToken
	}

	if val, ok := claims[domain.TokenTypeKey]; !ok || val != string(tokenType) {
		slog.DebugContext(ctx, "Token type mismatch", slog.String("token", token))
		return 0, ErrorInvalidToken
	}

	userID, ok := claims["id"].(float64)
	if !ok {
		return 0, errors.New("invalid user ID in token")
	}

	return int(userID), nil
}

func (j *jwtService) createAccessToken(ctx context.Context, userID int) (string, error) {
	return j.createToken(ctx, userID, j.accessTokenTTL, domain.AccessTokenType)
}

func (j *jwtService) createRefreshToken(ctx context.Context, userID int) (string, error) {
	return j.createToken(ctx, userID, j.refreshTokenTTL, domain.RefreshTokenType)
}

func (j *jwtService) createToken(ctx context.Context, userID int, tokenTTL time.Duration, tokenType domain.TokenType) (string, error) {
	claims := jwt.MapClaims{
		"id":                userID,
		"exp":               time.Now().Add(tokenTTL).Unix(),
		domain.TokenTypeKey: tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		slog.ErrorContext(ctx, "Failed signed token", slog.String("error", err.Error()))
		return "", err
	}
	return signedToken, nil
}
