package oauth

import (
    "authorization_service/internal/config"
    "authorization_service/internal/domain"
    "authorization_service/internal/repository"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/sirupsen/logrus"
    "golang.org/x/oauth2"
)

// Yandex user info response (subset)
type yandexUserInfo struct {
    ID           string   `json:"id"`
    Login        string   `json:"login"`
    DefaultEmail string   `json:"default_email"`
    Emails       []string `json:"emails"`
    FirstName    string   `json:"first_name"`
    LastName     string   `json:"last_name"`
    DisplayName  string   `json:"display_name"`
}

type OauthYandexService interface {
    OauthYandexLogin(ctx context.Context) (state, url string)
    AuthURLWithState(state string) string
    GetUserDataFromYandex(ctx context.Context, code string) (*domain.User, error)
}

type OAuthYandexServiceImpl struct {
    userRepository    repository.UserRepository
    conf              *oauth2.Config
    userInfoURL       string
    logger            *logrus.Logger
}

func NewOAuthYandexService(userRepository repository.UserRepository, conf *config.Config, logger *logrus.Logger) OauthYandexService {
    endpoint := oauth2.Endpoint{
        AuthURL:  "https://oauth.yandex.ru/authorize",
        TokenURL: "https://oauth.yandex.ru/token",
    }
    return &OAuthYandexServiceImpl{
        userRepository: userRepository,
        conf: &oauth2.Config{
            ClientID:     conf.OauthYandexConfig.ClientID,
            ClientSecret: conf.OauthYandexConfig.ClientSecret,
            RedirectURL:  "http://" + conf.Domain + ":" + conf.HttpServerConfig.Port + "/api/oauth/yandex/callback",
            Scopes:       []string{"login:email", "login:info"},
            Endpoint:     endpoint,
        },
        userInfoURL: "https://login.yandex.ru/info?format=json",
        logger:      logger,
    }
}

func (ys *OAuthYandexServiceImpl) OauthYandexLogin(ctx context.Context) (state, url string) {
    return "", ys.conf.AuthCodeURL("")
}

func (ys *OAuthYandexServiceImpl) AuthURLWithState(state string) string {
    return ys.conf.AuthCodeURL(state)
}

func (ys *OAuthYandexServiceImpl) GetUserDataFromYandex(ctx context.Context, code string) (*domain.User, error) {
    token, err := ys.conf.Exchange(context.Background(), code)
    if err != nil {
        return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
    }
    httpClient := &http.Client{Timeout: 2 * time.Second}
    ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

    client := ys.conf.Client(ctx, token)
    resp, err := client.Get(ys.userInfoURL)
    if err != nil {
        return nil, fmt.Errorf("failed getting userInfo info: %s", err.Error())
    }
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed read response: %s", err.Error())
    }
    var info yandexUserInfo
    if err := json.Unmarshal(body, &info); err != nil {
        return nil, fmt.Errorf("failed unmarshal userInfo info: %s", err.Error())
    }
    ys.logger.Infof("UserInfo from Yandex: %+v", info)

    email := info.DefaultEmail
    if email == "" && len(info.Emails) > 0 {
        email = info.Emails[0]
    }
    user, err := ys.userRepository.GetUserByYandexID(ctx, info.ID)
    if err != nil {
        ys.logger.Errorf("get user for yandex: %v", err)
        if err == repository.ErrorUserNotFound {
            newUser := &domain.User{
                YandexID:       &info.ID,
                LastName:       info.LastName,
                FirstName:      info.FirstName,
                Email:          email,
                EmailConfirmed: true,
            }
            if _, err := ys.userRepository.CreateUser(ctx, newUser); err != nil {
                ys.logger.Errorf("error create user: %v", err)
                return nil, err
            }
            return newUser, nil
        }
        return nil, err
    }
    ys.logger.Infof("User from repository: %+v", user)
    return user, nil
}