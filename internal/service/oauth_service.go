package service

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	oauth "authorization_service/internal/service/oauth"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

type OAuthService interface {
	// Google
	StartGoogleLogin(ctx context.Context, redirectURL string) (string, string, error)
	HandleGoogleCallback(ctx context.Context, code string, state string, cookieNonce string) (*domain.UserTokens, string, *domain.User, error)
	// Yandex
	StartYandexLogin(ctx context.Context, redirectURL string) (string, string, error)
	HandleYandexCallback(ctx context.Context, code string, state string, cookieNonce string) (*domain.UserTokens, string, *domain.User, error)
}

type oAuthService struct {
	google           oauth.OauthGoogleService
	yandex           oauth.OauthYandexService
	jwt              JWTService
	session          SessionService
	userRepository   repository.UserRepository
	logger           *logrus.Logger
	stateSecret      string
	allowedRedirects []string
}

func NewOAuthService(google oauth.OauthGoogleService, yandex oauth.OauthYandexService, jwt JWTService, session SessionService, userRepository repository.UserRepository, logger *logrus.Logger, stateSecret string, allowedRedirects []string) OAuthService {
	return &oAuthService{
		google:           google,
		yandex:           yandex,
		jwt:              jwt,
		session:          session,
		userRepository:   userRepository,
		logger:           logger,
		stateSecret:      stateSecret,
		allowedRedirects: allowedRedirects,
	}
}

type oauthStateClaims struct {
	jwt.RegisteredClaims
	Nonce       string `json:"nonce"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

func (s *oAuthService) StartGoogleLogin(ctx context.Context, redirectURL string) (string, string, error) {
	ru := ""
	if s.isAllowedRedirect(redirectURL) {
		ru = redirectURL
	}
	nonce := randomBase64(16)
	claims := oauthStateClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "oauth_state",
		},
		Nonce:       nonce,
		RedirectURL: ru,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	state, err := token.SignedString([]byte(s.stateSecret))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign oauth state: %w", err)
	}
	authURL := s.google.AuthURLWithState(state)
	return nonce, authURL, nil
}

func (s *oAuthService) HandleGoogleCallback(ctx context.Context, code string, state string, cookieNonce string) (*domain.UserTokens, string, *domain.User, error) {
	redirectURL, err := s.verifyState(state, cookieNonce)
	if err != nil {
		return nil, "", nil, err
	}

	user, err := s.google.GetUserDataFromGoogle(ctx, code)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get user from Google: %w", err)
	}
	if user == nil {
		return nil, "", nil, fmt.Errorf("invalid user data from oauth provider")
	}
	if user.ID == 0 {
		if user.Email != "" {
			resolved, getErr := s.userRepository.GetUserByEmail(ctx, user.Email)
			if getErr != nil {
				return nil, "", nil, fmt.Errorf("failed to resolve user ID: %w", getErr)
			}
			user = resolved
		} else {
			return nil, "", nil, fmt.Errorf("invalid user data from oauth provider: missing id and email")
		}
	}

	tokens, err := s.jwt.CreateJwtTokens(ctx, user.ID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to create tokens: %w", err)
	}
	jti, err := s.jwt.ParseJTI(ctx, tokens.AccessToken)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse token id: %w", err)
	}
	if _, err := s.session.CreateSession(ctx, tokens.RefreshToken, jti); err != nil {
		return nil, "", nil, fmt.Errorf("failed to create session: %w", err)
	}
	return tokens, redirectURL, user, nil
}

func (s *oAuthService) verifyState(state string, cookieNonce string) (string, error) {
	if state == "" {
		return "", fmt.Errorf("missing state")
	}
	claims := &oauthStateClaims{}
	parsed, err := jwt.ParseWithClaims(state, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(s.stateSecret), nil
	})
	if err != nil || !parsed.Valid {
		return "", fmt.Errorf("invalid state")
	}
	if claims.Subject != "oauth_state" {
		return "", fmt.Errorf("invalid state subject")
	}
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return "", fmt.Errorf("state expired")
	}
	if claims.Nonce == "" || claims.Nonce != cookieNonce {
		return "", fmt.Errorf("invalid oauth state")
	}
	if claims.RedirectURL != "" && !s.isAllowedRedirect(claims.RedirectURL) {
		return "", fmt.Errorf("redirect not allowed")
	}
	return claims.RedirectURL, nil
}

func (s *oAuthService) isAllowedRedirect(redirect string) bool {
	if redirect == "" {
		return false
	}
	u, err := url.Parse(redirect)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	for _, a := range s.allowedRedirects {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if redirect == a {
			return true
		}
		au, err := url.Parse(a)
		if err != nil {
			continue
		}
		sameOrigin := au.Scheme == u.Scheme && au.Host == u.Host
		if sameOrigin {
			if au.Path == "" || au.Path == "/" ||
				u.EscapedPath() == au.EscapedPath() ||
				strings.HasPrefix(u.EscapedPath(), au.EscapedPath()+"/") {
				return true
			}
		}
	}
	return false
}

func randomBase64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *oAuthService) StartYandexLogin(ctx context.Context, redirectURL string) (string, string, error) {
	ru := ""
	if s.isAllowedRedirect(redirectURL) {
		ru = redirectURL
	}
	nonce := randomBase64(16)
	claims := oauthStateClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "oauth_state",
		},
		Nonce:       nonce,
		RedirectURL: ru,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	state, err := token.SignedString([]byte(s.stateSecret))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign oauth state: %w", err)
	}
	if s.yandex == nil {
		return "", "", fmt.Errorf("yandex oauth service is not configured")
	}
	authURL := s.yandex.AuthURLWithState(state)
	return nonce, authURL, nil
}

func (s *oAuthService) HandleYandexCallback(ctx context.Context, code string, state string, cookieNonce string) (*domain.UserTokens, string, *domain.User, error) {
	redirectURL, err := s.verifyState(state, cookieNonce)
	if err != nil {
		return nil, "", nil, err
	}
	if s.yandex == nil {
		return nil, "", nil, fmt.Errorf("yandex oauth service is not configured")
	}
	user, err := s.yandex.GetUserDataFromYandex(ctx, code)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get user from Yandex: %w", err)
	}
	if user == nil {
		return nil, "", nil, fmt.Errorf("invalid user data from oauth provider")
	}
	if user.ID == 0 {
		if user.Email != "" {
			resolved, getErr := s.userRepository.GetUserByEmail(ctx, user.Email)
			if getErr != nil {
				return nil, "", nil, fmt.Errorf("failed to resolve user ID: %w", getErr)
			}
			user = resolved
		} else {
			return nil, "", nil, fmt.Errorf("invalid user data from oauth provider: missing id and email")
		}
	}
	tokens, err := s.jwt.CreateJwtTokens(ctx, user.ID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to create tokens: %w", err)
	}
	jti, err := s.jwt.ParseJTI(ctx, tokens.AccessToken)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse token id: %w", err)
	}
	if _, err := s.session.CreateSession(ctx, tokens.RefreshToken, jti); err != nil {
		return nil, "", nil, fmt.Errorf("failed to create session: %w", err)
	}
	return tokens, redirectURL, user, nil
}
