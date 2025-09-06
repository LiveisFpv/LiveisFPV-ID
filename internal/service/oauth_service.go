package service

import (
    "authorization_service/internal/domain"
    "authorization_service/internal/repository"
    oauth "authorization_service/internal/service/oauth"
    "context"
    "fmt"

    "github.com/sirupsen/logrus"
)

type OAuthService interface {
    StartGoogleLogin(ctx context.Context) (state string, url string)
    HandleGoogleCallback(ctx context.Context, code string) (*domain.UserTokens, *domain.User, error)
}

type oAuthService struct {
    google          oauth.OauthGoogleService
    jwt             JWTService
    session         SessionService
    userRepository  repository.UserRepository
    logger          *logrus.Logger
}

func NewOAuthService(google oauth.OauthGoogleService, jwt JWTService, session SessionService, userRepository repository.UserRepository, logger *logrus.Logger) OAuthService {
    return &oAuthService{
        google:         google,
        jwt:            jwt,
        session:        session,
        userRepository: userRepository,
        logger:         logger,
    }
}

func (s *oAuthService) StartGoogleLogin(ctx context.Context) (state string, url string) {
    return s.google.OauthGoogleLogin(ctx)
}

func (s *oAuthService) HandleGoogleCallback(ctx context.Context, code string) (*domain.UserTokens, *domain.User, error) {
    user, err := s.google.GetUserDataFromGoogle(ctx, code)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to get user from Google: %w", err)
    }
    if user == nil {
        return nil, nil, fmt.Errorf("invalid user data from oauth provider")
    }
    if user.ID == 0 {
        // Try to resolve by email when ID is missing in provider return path
        if user.Email != "" {
            resolved, getErr := s.userRepository.GetUserByEmail(ctx, user.Email)
            if getErr != nil {
                return nil, nil, fmt.Errorf("failed to resolve user ID: %w", getErr)
            }
            user = resolved
        } else {
            return nil, nil, fmt.Errorf("invalid user data from oauth provider: missing id and email")
        }
    }

    tokens, err := s.jwt.CreateJwtTokens(ctx, user.ID)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to create tokens: %w", err)
    }

    jti, err := s.jwt.ParseJTI(ctx, tokens.AccessToken)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to parse token id: %w", err)
    }

    if _, err := s.session.CreateSession(ctx, tokens.RefreshToken, jti); err != nil {
        return nil, nil, fmt.Errorf("failed to create session: %w", err)
    }

    return tokens, user, nil
}

