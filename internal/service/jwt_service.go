package service

import (
	"authorization_service/internal/config"
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var (
	ErrorMethod       = errors.New("unexpected signing method")
	ErrorInvalidToken = errors.New("invalid token")
	ErrorTokenExpired = errors.New("token expired")
	ErrorTokenBlocked = errors.New("token blocked")
)

type JWTService interface {
	CreateJwtTokens(ctx context.Context, userID int) (*domain.UserTokens, error)
	VerifyToken(ctx context.Context, token string, tokenType domain.TokenType) (int, error)
	ParseToken(ctx context.Context, refresh_token string) (*domain.TokenClaims, error)
	RefreshToken(ctx context.Context, refreshToken string) (*domain.UserTokens, error)
	ParseJTI(ctx context.Context, token string) (string, error)
}

type jwtService struct {
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	blockList       repository.TokenBlocklist
	secretKey       string
	logger          *logrus.Logger
}

func NewJWTService(config *config.JWTConfig, blocklist repository.TokenBlocklist, logger *logrus.Logger) JWTService {
	return &jwtService{
		accessTokenTTL:  config.AccessTokenTTL,
		refreshTokenTTL: config.RefreshTokenTTL,
		blockList:       blocklist,
		secretKey:       config.SecretKey,
		logger:          logger,
	}
}

// ParseJTI implements JWTService.
func (j *jwtService) ParseJTI(ctx context.Context, token string) (string, error) {
	claims := &domain.TokenClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrorMethod
		}
		return []byte(j.secretKey), nil
	})

	if err != nil || !parsedToken.Valid {
		return "", ErrorInvalidToken
	}

	if claims.RegisteredClaims.ExpiresAt == nil || claims.RegisteredClaims.ExpiresAt.Time.Before(time.Now()) {
		return "", ErrorTokenExpired
	}

	return claims.ID, nil
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

func (j *jwtService) ParseToken(ctx context.Context, refresh_token string) (*domain.TokenClaims, error) {
	claims := domain.TokenClaims{}
	parsedToken, err := jwt.ParseWithClaims(refresh_token, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrorMethod
		}
		return []byte(j.secretKey), nil
	})
	if err != nil || !parsedToken.Valid {
		return nil, ErrorInvalidToken
	}
	if claims.TokenType != domain.RefreshTokenType {
		return nil, ErrorInvalidToken
	}

	if claims.RegisteredClaims.ExpiresAt == nil || claims.RegisteredClaims.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrorTokenExpired
	}

	return &claims, nil
}

// VerifyToken implements JWTService.
func (j *jwtService) VerifyToken(ctx context.Context, token string, tokenType domain.TokenType) (int, error) {
	claims := &domain.TokenClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrorMethod
		}
		return []byte(j.secretKey), nil
	})

	if err != nil || !parsedToken.Valid {
		return 0, ErrorInvalidToken
	}

	if claims.TokenType != tokenType {
		return 0, ErrorInvalidToken
	}

	if claims.RegisteredClaims.ExpiresAt == nil || claims.RegisteredClaims.ExpiresAt.Time.Before(time.Now()) {
		return 0, ErrorTokenExpired
	}

	if claims.TokenType == domain.AccessTokenType {
		// Check if the access token is blocked
		blocked, err := j.blockList.IsBlocked(ctx, claims.ID)
		if blocked {
			return 0, ErrorTokenBlocked
		}
		if err != nil {
			j.logger.Error(ctx, "Failed to check if token is blocked", "error", err.Error())
			return 0, err
		}
	}

	return claims.UserID, nil
}

// RefreshToken implements JWTService.
func (j *jwtService) RefreshToken(ctx context.Context, refreshToken string) (*domain.UserTokens, error) {
	claims, err := j.ParseToken(ctx, refreshToken)
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
