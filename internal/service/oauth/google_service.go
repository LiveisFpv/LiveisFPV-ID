package oauth

import (
	"authorization_service/internal/config"
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	logger            *logrus.Logger
}

func NewOAuthGoogleService(userRepository repository.UserRepository, conf *config.Config, logger *logrus.Logger) OauthGoogleService {
	return &OAuthGoogleServiceImpl{
		userRepository: userRepository,
		conf: &oauth2.Config{
			ClientID:     conf.OauthGoogleConfig.ClientID,
			ClientSecret: conf.OauthGoogleConfig.ClientSecret,
			RedirectURL:  conf.Domain + "/oauth/google/callback",
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/userinfo.email",
			},
			Endpoint: google.Endpoint,
		},
		oauthGoogleUrlAPI: "https://www.googleapis.com/oauth2/v3/userinfo",
		logger:            logger,
	}
}

// GetUserDataFromGoogle implements OauthGoogleService.
func (gs *OAuthGoogleServiceImpl) GetUserDataFromGoogle(ctx context.Context, code string) (*domain.User, error) {
	token, err := gs.conf.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	httpClient := &http.Client{Timeout: 2 * time.Second}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	client := gs.conf.Client(ctx, token)
	response, err := client.Get(gs.oauthGoogleUrlAPI)
	if err != nil {
		return nil, fmt.Errorf("failed getting userInfo info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}

	var userInfo UserInfoGoogle
	err = json.Unmarshal(contents, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshal userInfo info: %s", err.Error())
	}
	gs.logger.Infof("UserInfo from Google: %+v", userInfo)
	user, err := gs.userRepository.GetUserByGoogleID(ctx, userInfo.ID)
	if err != nil {
		gs.logger.Errorf("get user for google: %v", err)
		if errors.Is(err, repository.ErrorUserNotFound) {
			newUser := &domain.User{
				GoogleID:       &userInfo.ID,
				LastName:       userInfo.FamilyName,
				FirstName:      userInfo.GivenName,
				Email:          userInfo.Email,
				Roles:          []string{"user"},
				EmailConfirmed: true,
			}
			if userInfo.Picture != "" {
				newUser.Photo = &userInfo.Picture
			}
			_, err := gs.userRepository.CreateUser(ctx, newUser)
			gs.logger.Infof("create user for google: %+v", newUser)
			if err != nil {
				gs.logger.Errorf("error create user: %v", err)
				return nil, err
			}

			return newUser, nil
		}
		return nil, err
	}

	gs.logger.Infof("User from repository: %+v", user)
	return user, nil
}

// OauthGoogleLogin implements OauthGoogleService.
func (gs *OAuthGoogleServiceImpl) OauthGoogleLogin(ctx context.Context) (state string, url string) {
	oauthState := generateStateOauthCookie()

	u := gs.conf.AuthCodeURL(oauthState)
	return oauthState, u
}

func generateStateOauthCookie() string {

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}
