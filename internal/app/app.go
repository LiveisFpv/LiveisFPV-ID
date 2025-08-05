package app

import (
	"authorization_service/internal/service"
	"authorization_service/internal/service/oauth"
)

type App struct {
	AuthService        service.AuthService
	OauthGoogleService oauth.OauthGoogleService
	EmailService       service.EmailService
	JWTService         service.JWTService
	SessionService     service.SessionService
}
