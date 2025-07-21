package oauth

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"

	"golang.org/x/oauth2"
)

type UserInfoGoogle struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

type OauthGoogleService interface {
	OauthGoogleLogin(ctx context.Context) (state, url string)
	GetUserDataFromGoogle(ctx context.Context, code string) (*domain.User, error)
}

type OAuthGoogleServiceImpl struct {
	userRepository    repository.UserRepository
	conf              *oauth2.Config
	oauthGoogleUrlAPI string
}
