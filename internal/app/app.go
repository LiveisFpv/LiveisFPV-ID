package app

import (
	"authorization_service/internal/config"
	"authorization_service/internal/repository"
	"authorization_service/internal/service"
	"authorization_service/internal/service/oauth"

	"github.com/sirupsen/logrus"
)

type App struct {
	Config             *config.Config
	AuthService        service.AuthService
	OauthGoogleService oauth.OauthGoogleService
	EmailService       service.EmailService
	JWTService         service.JWTService
	SessionService     service.SessionService
}

func NewApp(
	cfg *config.Config,
	SessionRepository repository.SessionRepository,
	UserRepository repository.UserRepository,
	TokenBlocklist repository.TokenBlocklist,
	Logger *logrus.Logger,
) *App {
	JWTService := service.NewJWTService(&cfg.JWTConfig, TokenBlocklist, Logger)
	EmailService := service.NewEmailService(&cfg.EmailConfig, cfg.Domain, Logger)
	SessionService := service.NewSessionService(SessionRepository, TokenBlocklist, JWTService, Logger)
	AuthService := service.NewAuthService(JWTService, EmailService, SessionService, UserRepository, Logger)
	OauthGoogleService := oauth.NewOAuthGoogleService(UserRepository, cfg, Logger)
	return &App{
		Config:             cfg,
		AuthService:        AuthService,
		OauthGoogleService: OauthGoogleService,
		EmailService:       EmailService,
		JWTService:         JWTService,
		SessionService:     SessionService,
	}
}
