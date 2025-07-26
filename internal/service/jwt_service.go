package service

import (
	"authorization_service/internal/config"
	"authorization_service/internal/domain"
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var (
	ErrorInvalidToken = errors.New("invalid_token")
)

type JWTService interface {
	CreateJwtTokens(ctx context.Context, userID int) (*domain.UserTokens, error)
	VerifyToken(ctx context.Context, token string, tokenType domain.TokenType) (int, error)
	ParseToken(refresh_token string) (*domain.TokenClaims, error)
	RefreshToken(ctx context.Context, refreshToken string) (*domain.UserTokens, error)
}

type jwtService struct {
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	secretKey       string
	logger          *logrus.Logger
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

func (j *jwtService) ParseToken(refresh_token string) (*domain.TokenClaims, error) {
	claims := domain.TokenClaims{}
	parsedToken, err := jwt.ParseWithClaims(refresh_token, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.secretKey), nil
	})
	if err != nil || !parsedToken.Valid {
		return nil, ErrorInvalidToken
	}
	if claims.TokenType != domain.RefreshTokenType {
		return nil, ErrorInvalidToken
	}
	return &claims, nil
}

// VerifyToken implements JWTService.
func (j *jwtService) VerifyToken(ctx context.Context, token string, tokenType domain.TokenType) (int, error) {
	claims := &domain.TokenClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.secretKey), nil
	})

	if err != nil || !parsedToken.Valid {
		return 0, ErrorInvalidToken
	}

	if claims.TokenType != tokenType {
		return 0, ErrorInvalidToken
	}

	return claims.UserID, nil
}

// RefreshToken implements JWTService.
func (j *jwtService) RefreshToken(ctx context.Context, refreshToken string) (*domain.UserTokens, error) {
	claims, err := j.ParseToken(refreshToken)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != domain.RefreshTokenType {
		return nil, ErrorInvalidToken
	}
	userID := claims.UserID
	// Create new access token
	accessToken, err := j.createAccessToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Create new refresh token
	refreshToken, err = j.createRefreshToken(ctx, userID)
	if err != nil {
		return nil, err
	}
	userTokens := &domain.UserTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return userTokens, nil
}

func (j *jwtService) createAccessToken(ctx context.Context, userID int) (string, error) {
	return j.createToken(ctx, userID, j.accessTokenTTL, domain.AccessTokenType)
}

func (j *jwtService) createRefreshToken(ctx context.Context, userID int) (string, error) {
	return j.createToken(ctx, userID, j.refreshTokenTTL, domain.RefreshTokenType)
}

func (j *jwtService) createToken(ctx context.Context, userID int, tokenTTL time.Duration, tokenType domain.TokenType) (string, error) {
	claims := domain.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
		UserID:    userID,
		TokenType: tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		j.logger.Error(ctx, "Failed signed token", "error", err.Error())
		return "", err
	}
	return signedToken, nil
}
