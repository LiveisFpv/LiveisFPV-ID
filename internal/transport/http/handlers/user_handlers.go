package handlers

import (
	"authorization_service/internal/app"
	"authorization_service/internal/transport/http/presenters"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Logout(ctx *gin.Context, a *app.App) {
	cookieCfg := a.Config.CookieConfig

	refreshToken, err := ctx.Cookie("refresh_token")
	if err != nil {
		if err == http.ErrNoCookie {
			resp := presenters.Error(fmt.Errorf("no refresh token found: %w", err))
			ctx.JSON(http.StatusUnauthorized, resp)
			return
		}
		resp := presenters.Error(fmt.Errorf("failed to retrieve refresh token: %w", err))
		ctx.JSON(http.StatusInternalServerError, resp)
		return
	}

	// Clear REDIS session
	if err := a.AuthService.Logout(ctx, refreshToken); err != nil {
		resp := presenters.Error(fmt.Errorf("logout failed: %w", err))
		ctx.JSON(http.StatusInternalServerError, resp)
		return
	}

	ctx.SetCookie(
		"refresh_token",
		"",
		-1,
		cookieCfg.Path,
		cookieCfg.Domain,
		cookieCfg.Secure,
		cookieCfg.HttpOnly,
	)

	resp := presenters.TokenResReq{
		AccessToken: "",
	}
	ctx.JSON(http.StatusOK, resp)
}

func Refresh(ctx *gin.Context, a *app.App) {
	refreshToken, err := ctx.Cookie("refresh_token")
	if err != nil {
		if err == http.ErrNoCookie {
			resp := presenters.Error(fmt.Errorf("no refresh token found: %w", err))
			ctx.JSON(http.StatusUnauthorized, resp)
			return
		}
		resp := presenters.Error(fmt.Errorf("failed to retrieve refresh token: %w", err))
		ctx.JSON(http.StatusInternalServerError, resp)
		return
	}
	tokens, err := a.AuthService.Refresh(ctx, refreshToken)
	if err != nil {
		resp := presenters.Error(fmt.Errorf("refresh token failed: %w", err))
		ctx.JSON(http.StatusUnauthorized, resp)
		return
	}
	cookieCfg := a.Config.CookieConfig

	ctx.SetCookie(
		"refresh_token",
		tokens.RefreshToken,
		int(cookieCfg.MaxAge.Seconds()),
		cookieCfg.Path,
		cookieCfg.Domain,
		cookieCfg.Secure,
		cookieCfg.HttpOnly,
	)
	resp := presenters.TokenResReq{
		AccessToken: tokens.AccessToken,
	}
	ctx.JSON(http.StatusOK, resp)

}

func Authenticate(ctx *gin.Context, a *app.App) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, presenters.Error(fmt.Errorf("missing Authorization header")))
		return
	}

	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) || authHeader[:len(prefix)] != prefix {
		ctx.JSON(http.StatusUnauthorized, presenters.Error(fmt.Errorf("invalid Authorization header format")))
		return
	}
	accessToken := authHeader[len(prefix):]
	user, err := a.AuthService.Authenticate(ctx, accessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, presenters.Error(fmt.Errorf("authentication failed: %w", err)))
		return
	}
	ctx.JSON(http.StatusOK, presenters.UserResponse{
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Email:          user.Email,
		EmailConfirmed: user.EmailConfirmed,
		LocaleType:     user.LocaleType,
		Roles:          user.Roles,
		Photo:          user.Photo,
	})
}
func Validate(ctx *gin.Context, a *app.App) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, presenters.Error(fmt.Errorf("missing Authorization header")))
		return
	}

	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) || authHeader[:len(prefix)] != prefix {
		ctx.JSON(http.StatusUnauthorized, presenters.Error(fmt.Errorf("invalid Authorization header format")))
		return
	}
	accessToken := authHeader[len(prefix):]
	_, err := a.AuthService.Validate(ctx, accessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, presenters.Error(fmt.Errorf("validate failed: %w", err)))
		return
	}
	ctx.Status(http.StatusOK)
}

func UpdateUser(ctx *gin.Context, a *app.App) {
	panic("UpdateUser handler not implemented")
}

func ConfirmEmail(ctx *gin.Context, a *app.App) {
	panic("ConfirmEmail handler not implemented")
}

func Login(ctx *gin.Context, a *app.App) {
	var req presenters.UserLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		resp := presenters.Error(fmt.Errorf("invalid request: %w", err))
		ctx.JSON(http.StatusBadRequest, resp)
	}
	tokens, err := a.AuthService.Login(ctx, req.Login, req.Password)
	if err != nil {
		resp := presenters.Error(fmt.Errorf("login failed: %w", err))
		ctx.JSON(http.StatusUnauthorized, resp)
		return
	}
	cookieCfg := a.Config.CookieConfig

	ctx.SetCookie(
		"refresh_token",
		tokens.RefreshToken,
		int(cookieCfg.MaxAge.Seconds()),
		cookieCfg.Path,
		cookieCfg.Domain,
		cookieCfg.Secure,
		cookieCfg.HttpOnly,
	)
	resp := presenters.TokenResReq{
		AccessToken: tokens.AccessToken,
	}
	ctx.JSON(http.StatusOK, resp)
}

func CreateUser(ctx *gin.Context, a *app.App) {
	panic("CreateUser handler not implemented")
}

func OauthGoogleLogin(ctx *gin.Context, a *app.App) {
	panic("OauthGoogleLogin handler not implemented")
}

func OauthGoogleCallback(ctx *gin.Context, a *app.App) {
	panic("OauthGoogleCallback handler not implemented")
}

func OauthYandexLogin(ctx *gin.Context, a *app.App) {
	panic("OauthYandexLogin handler not implemented")
}

func OauthYandexCallback(ctx *gin.Context, a *app.App) {
	panic("OauthYandexCallback handler not implemented")
}

func OauthVkLogin(ctx *gin.Context, a *app.App) {
	panic("OauthVkLogin handler not implemented")
}

func OauthVkCallback(ctx *gin.Context, a *app.App) {
	panic("OauthVkCallback handler not implemented")
}
