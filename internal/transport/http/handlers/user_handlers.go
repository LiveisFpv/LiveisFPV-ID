package handlers

import (
	"authorization_service/internal/app"
	"authorization_service/internal/domain"
	"authorization_service/internal/service"
	"authorization_service/internal/transport/http/presenters"
	"fmt"
	"net/http"
	"time"

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
// @Param Authorization header string true "Bearer access token"
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
// @Param Authorization header string true "Bearer access token"
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
// @Description Updates user profile fields. Requires Bearer access token in Authorization header.
// @Tags User
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param request body presenters.UserUpdateRequest true "Update request"
// @Success 200 {object} presenters.UserResponse
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 401 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/update [put]
func UpdateUser(ctx *gin.Context, a *app.App) {
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

	var req presenters.UserUpdateRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid request: %w", err)))
		return
	}

	current, err := a.AuthService.Authenticate(ctx, accessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, presenters.Error(fmt.Errorf("authentication failed: %w", err)))
		return
	}

	updated := &domain.User{
		FirstName:  current.FirstName,
		LastName:   current.LastName,
		Email:      current.Email,
		Password:   nil,
		Roles:      current.Roles,
		Photo:      current.Photo,
		LocaleType: current.LocaleType,
	}
	if req.FirstName != nil {
		updated.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		updated.LastName = *req.LastName
	}
	if req.Email != nil {
		updated.Email = *req.Email
	}
	if req.Password != nil {
		updated.Password = req.Password
	}
	if req.LocaleType != nil {
		updated.LocaleType = req.LocaleType
	}

	user, err := a.AuthService.UpdateUser(ctx, accessToken, updated)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("update user failed: %w", err)))
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

// ConfirmEmail
// @Summary Confirm email
// @Description Confirms the user's email address by email-confirmation token.
// @Tags User
// @Accept json
// @Produce json
// @Param token query string true "Email confirmation token"
// @Success 200
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/confirm-email [get]
func ConfirmEmail(ctx *gin.Context, a *app.App) {
	token := ctx.Query("token")
	if token == "" {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("missing token")))
		return
	}
	_, err := a.AuthService.ConfirmEmail(ctx, token)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("confirm email failed: %w", err)))
		return
	}
	ctx.Status(http.StatusOK)
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
		return
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
// @Description Creates a new user and sends an email confirmation link.
// @Tags User
// @Accept json
// @Produce json
// @Param request body presenters.UserRegisterRequest true "Register request"
// @Success 201 {object} presenters.UserResponse
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/create [post]
func CreateUser(ctx *gin.Context, a *app.App) {
	var req presenters.UserRegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		resp := presenters.Error(fmt.Errorf("invalid request: %w", err))
		ctx.JSON(http.StatusBadRequest, resp)
		return
	}
	user := &domain.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  &req.Password,
	}
	created, err := a.AuthService.CreateUser(ctx, user)
	if err == service.ErrUserExists {
		resp := presenters.Error(err)
		ctx.JSON(http.StatusBadRequest, resp)
		return
	}
	if err != nil {
		resp := presenters.Error(fmt.Errorf("create user failed: %w", err))
		ctx.JSON(http.StatusInternalServerError, resp)
		return
	}
	ctx.JSON(http.StatusCreated, presenters.UserResponse{
		FirstName:      created.FirstName,
		LastName:       created.LastName,
		Email:          created.Email,
		EmailConfirmed: created.EmailConfirmed,
		LocaleType:     created.LocaleType,
		Roles:          created.Roles,
		Photo:          created.Photo,
	})
}

// OauthGoogleLogin
// @Summary Google OAuth login
// @Description Initiates Google OAuth login. Redirects to Google authorization page.
// @Tags OAuth
// @Accept json
// @Produce json
// @Success 307
// @Router /oauth/google [get]
func OauthGoogleLogin(ctx *gin.Context, a *app.App) {
	state, url := a.OauthGoogleService.OauthGoogleLogin(ctx)

	// Save state cookie for 5 minutes
	cookieCfg := a.Config.CookieConfig
	ctx.SetCookie("oauth_state", state, int((5 * time.Minute).Seconds()), cookieCfg.Path, cookieCfg.Domain, cookieCfg.Secure, cookieCfg.HttpOnly)

	ctx.Redirect(http.StatusTemporaryRedirect, url)
}

// OauthGoogleCallback
// @Summary Google OAuth callback
// @Description Handles Google OAuth callback, issues auth tokens and sets refresh token cookie.
// @Tags OAuth
// @Accept json
// @Produce json
// @Param state query string false "OAuth state"
// @Param code query string true "OAuth authorization code"
// @Success 200 {object} presenters.TokenResReq
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /oauth/google/callback [get]
func OauthGoogleCallback(ctx *gin.Context, a *app.App) {
	state := ctx.Query("state")
	if cookieState, err := ctx.Cookie("oauth_state"); err == nil && cookieState != "" {
		if state == "" || state != cookieState {
			ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid oauth state")))
			return
		}
		// clear state cookie
		cookieCfg := a.Config.CookieConfig
		ctx.SetCookie("oauth_state", "", -1, cookieCfg.Path, cookieCfg.Domain, cookieCfg.Secure, cookieCfg.HttpOnly)
	}

	code := ctx.Query("code")
	if code == "" {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("missing code")))
		return
	}

	user, err := a.OauthGoogleService.GetUserDataFromGoogle(ctx, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("failed to get user from Google: %w", err)))
		return
	}
	if user == nil || user.ID == 0 {
		if user != nil && user.Email != "" {
			found, getErr := a.AuthService.GetUserByEmail(ctx, user.Email)
			if getErr != nil {
				ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("failed to resolve user ID: %w", getErr)))
				return
			}
			user = found
		} else {
			ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("invalid user data from oauth provider")))
			return
		}
	}

	tokens, err := a.JWTService.CreateJwtTokens(ctx, user.ID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("failed to create tokens: %w", err)))
		return
	}
	jti, err := a.JWTService.ParseJTI(ctx, tokens.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("failed to parse token id: %w", err)))
		return
	}
	if _, err := a.SessionService.CreateSession(ctx, tokens.RefreshToken, jti); err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("failed to create session: %w", err)))
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

	ctx.JSON(http.StatusOK, presenters.TokenResReq{AccessToken: tokens.AccessToken})
}

// OauthYandexLogin
// @Summary Yandex OAuth login
// @Description Initiates Yandex OAuth login (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/yandex [get]
func OauthYandexLogin(ctx *gin.Context, a *app.App) {
	ctx.JSON(http.StatusNotImplemented, presenters.Error(fmt.Errorf("yandex oauth not implemented")))
}

// OauthYandexCallback
// @Summary Yandex OAuth callback
// @Description Handles Yandex OAuth callback (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/yandex/callback [get]
func OauthYandexCallback(ctx *gin.Context, a *app.App) {
	ctx.JSON(http.StatusNotImplemented, presenters.Error(fmt.Errorf("yandex oauth not implemented")))
}

// OauthVkLogin
// @Summary VK OAuth login
// @Description Initiates VK OAuth login (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/vk [get]
func OauthVkLogin(ctx *gin.Context, a *app.App) {
	ctx.JSON(http.StatusNotImplemented, presenters.Error(fmt.Errorf("vk oauth not implemented")))
}

// OauthVkCallback
// @Summary VK OAuth callback
// @Description Handles VK OAuth callback (not implemented)
// @Tags OAuth
// @Accept json
// @Produce json
// @Router /oauth/vk/callback [get]
func OauthVkCallback(ctx *gin.Context, a *app.App) {
	ctx.JSON(http.StatusNotImplemented, presenters.Error(fmt.Errorf("vk oauth not implemented")))
}
