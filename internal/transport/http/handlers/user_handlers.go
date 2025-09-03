package handlers

import (
	"authorization_service/internal/app"
	"authorization_service/internal/transport/http/presenters"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Logout
// @Summary Logout user
// @Description Logs out the user by invalidating the refresh token and clearing the cookie
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} presenters.TokenResReq
// @Failure 401 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/logout [post]
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

// Refresh
// @Summary Refresh tokens
// @Description Refreshes the access and refresh tokens using the refresh token from the cookie
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} presenters.TokenResReq
// @Failure 401 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/refresh [post]
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
		int(cookieCfg.MaxAge.Duration().Seconds()),
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

// Authenticate
// @Summary Authenticate user
// @Description Authenticates the user using the provided access token
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} presenters.UserResponse
// @Failure 401 {object} presenters.ErrorResponse
// @Router /auth/authenticate [get]
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

// Validate
// @Summary Validate access token
// @Description Validates the provided access token
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200
// @Failure 401 {object} presenters.ErrorResponse
// @Router /auth/validate [get]
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

// UpdateUser
// @Summary Update user
// @Description Updates user information (not implemented)
// @Tags User
// @Accept json
// @Produce json
// @Router /user/update [put]
func UpdateUser(ctx *gin.Context, a *app.App) {
	panic("UpdateUser handler not implemented")
}

// ConfirmEmail
// @Summary Confirm email
// @Description Confirms the user's email address (not implemented)
// @Tags User
// @Accept json
// @Produce json
// @Router /user/confirm-email [post]
func ConfirmEmail(ctx *gin.Context, a *app.App) {
	panic("ConfirmEmail handler not implemented")
}

// Login
// @Summary Login user
// @Description Logs in the user and returns access and refresh tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body presenters.UserLoginRequest true "Login request"
// @Success 200 {object} presenters.TokenResReq
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 401 {object} presenters.ErrorResponse
// @Router /auth/login [post]
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
		int(cookieCfg.MaxAge.Duration().Seconds()),
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

// CreateUser
// @Summary Create user
// @Description Creates a new user (not implemented)
// @Tags User
// @Accept json
// @Produce json
// @Router /user/create [post]
func CreateUser(ctx *gin.Context, a *app.App) {
	panic("CreateUser handler not implemented")
}

// OauthGoogleLogin
// @Summary Google OAuth login
// @Description Initiates Google OAuth login (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/google/login [get]
func OauthGoogleLogin(ctx *gin.Context, a *app.App) {
	panic("OauthGoogleLogin handler not implemented")
}

// OauthGoogleCallback
// @Summary Google OAuth callback
// @Description Handles Google OAuth callback (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/google/callback [get]
func OauthGoogleCallback(ctx *gin.Context, a *app.App) {
	panic("OauthGoogleCallback handler not implemented")
}

// OauthYandexLogin
// @Summary Yandex OAuth login
// @Description Initiates Yandex OAuth login (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/yandex/login [get]
func OauthYandexLogin(ctx *gin.Context, a *app.App) {
	panic("OauthYandexLogin handler not implemented")
}

// OauthYandexCallback
// @Summary Yandex OAuth callback
// @Description Handles Yandex OAuth callback (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/yandex/callback [get]
func OauthYandexCallback(ctx *gin.Context, a *app.App) {
	panic("OauthYandexCallback handler not implemented")
}

// OauthVkLogin
// @Summary VK OAuth login
// @Description Initiates VK OAuth login (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/vk/login [get]
func OauthVkLogin(ctx *gin.Context, a *app.App) {
	panic("OauthVkLogin handler not implemented")
}

// OauthVkCallback
// @Summary VK OAuth callback
// @Description Handles VK OAuth callback (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/vk/callback [get]
func OauthVkCallback(ctx *gin.Context, a *app.App) {
	panic("OauthVkCallback handler not implemented")
}
