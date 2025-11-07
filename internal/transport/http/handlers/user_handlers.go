package handlers

import (
	"authorization_service/internal/app"
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"authorization_service/internal/service"
	"authorization_service/internal/transport/http/presenters"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// setCookieWithConfig sets cookie with SameSite from config.
func setCookieWithConfig(ctx *gin.Context, a *app.App, name, value string, maxAge int) {
	cfg := a.Config.CookieConfig
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   maxAge,
		HttpOnly: cfg.HttpOnly,
		Secure:   cfg.Secure,
		SameSite: func() http.SameSite {
			switch cfgSame := cfg.SameSite; cfgSame {
			case "None", "none":
				return http.SameSiteNoneMode
			case "Strict", "strict":
				return http.SameSiteStrictMode
			case "Lax", "lax":
				fallthrough
			default:
				return http.SameSiteLaxMode
			}
		}(),
	})
}

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

	setCookieWithConfig(ctx, a, "refresh_token", "", -1)

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
	setCookieWithConfig(ctx, a, "refresh_token", tokens.RefreshToken, int(a.Config.CookieConfig.MaxAge.Duration().Seconds()))
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

// RequestPasswordReset
// @Summary Request password reset
// @Description Sends a password reset confirmation link to the email if it exists.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body presenters.PasswordResetRequest true "Password reset request"
// @Success 200 {object} presenters.PasswordResetResponse
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/password-reset [post]
func RequestPasswordReset(ctx *gin.Context, a *app.App) {
	var req presenters.PasswordResetRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid request: %w", err)))
		return
	}

	if err := a.AuthService.RequestPasswordReset(ctx, req.Email); err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("password reset request failed: %w", err)))
		return
	}

	ctx.JSON(http.StatusOK, presenters.PasswordResetResponse{
		Message: "If the email exists, a confirmation link has been sent.",
	})
}

// ConfirmPasswordReset
// @Summary Confirm password reset
// @Description Validates the reset token and emails a new password to the user.
// @Tags Auth
// @Accept json
// @Produce json
// @Param token query string true "Password reset token"
// @Success 200 {object} presenters.PasswordResetResponse
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/password-reset/confirm [get]
func ConfirmPasswordReset(ctx *gin.Context, a *app.App) {
	token := ctx.Query("token")
	if token == "" {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("missing token")))
		return
	}

	if err := a.AuthService.ConfirmPasswordReset(ctx, token); err != nil {
		if errors.Is(err, service.ErrInvalidPasswordResetToken) || errors.Is(err, service.ErrPasswordResetTokenExpired) || errors.Is(err, service.ErrPasswordResetTokenUsed) {
			ctx.JSON(http.StatusBadRequest, &presenters.ErrorResponse{Error: "invalid or expired token"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("password reset confirmation failed: %w", err)))
		return
	}

	ctx.JSON(http.StatusOK, presenters.PasswordResetResponse{
		Message: "A new password has been sent to your email.",
	})
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
	setCookieWithConfig(ctx, a, "refresh_token", tokens.RefreshToken, int(a.Config.CookieConfig.MaxAge.Duration().Seconds()))
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
	password := req.Password
	user := &domain.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  &password,
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

// CreateUserWithRoles
// @Summary Create user with roles
// @Description Creates a new user with custom roles.
// @Tags User
// @Accept json
// @Produce json
// @Param request body presenters.UserCreateWithRolesRequest true "Create request with roles"
// @Success 201 {object} presenters.UserResponse
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 403 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/admin/users [post]
func CreateUserWithRoles(ctx *gin.Context, a *app.App) {
	var req presenters.UserCreateWithRolesRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid request: %w", err)))
		return
	}

	password := req.Password
	user := &domain.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  &password,
		Roles:     req.Roles,
	}

	created, err := a.AuthService.CreateUser(ctx, user)
	if err == service.ErrUserExists {
		ctx.JSON(http.StatusBadRequest, presenters.Error(err))
		return
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("create user failed: %w", err)))
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

// UpdateUserAdmin
// @Summary Update user (admin)
// @Description Updates user profile fields including roles by user ID.
// @Tags User
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param request body presenters.UserUpdateAdminRequest true "Admin update request"
// @Success 200 {object} presenters.UserResponse
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 404 {object} presenters.ErrorResponse
// @Failure 403 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/admin/users/{id} [put]
func UpdateUserAdmin(ctx *gin.Context, a *app.App) {
	idParam := ctx.Param("id")
	userID, err := strconv.Atoi(idParam)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid user id: %w", err)))
		return
	}

	var req presenters.UserUpdateAdminRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid request: %w", err)))
		return
	}

	updated := &domain.User{
		ID:        userID,
		FirstName: "",
		LastName:  "",
		Email:     "",
		Password:  nil,
		Roles:     nil,
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
	if req.Roles != nil {
		updated.Roles = *req.Roles
	}

	user, err := a.AuthService.UpdateUserAdmin(ctx, updated)
	if err != nil {
		if errors.Is(err, repository.ErrorUserNotFound) {
			ctx.JSON(http.StatusNotFound, presenters.Error(repository.ErrorUserNotFound))
			return
		}
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("admin update user failed: %w", err)))
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

// ListUsers
// @Summary List users
// @Description Returns a paginated list of users with optional filtering
// @Tags User
// @Accept json
// @Produce json
// @Param q query string false "Search by first_name, last_name, email"
// @Param role query string false "Filter by role"
// @Param email_confirmed query bool false "Filter by email confirmation status"
// @Param locale query string false "Filter by locale (e.g., ru)"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Page size" default(20)
// @Success 200 {object} presenters.UserListResponse
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 403 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /auth/admin/users [get]
func ListUsers(ctx *gin.Context, a *app.App) {
	// Parse pagination
	page := 1
	limit := 20
	if v := ctx.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		} else if err != nil {
			ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid page: %w", err)))
			return
		}
	}
	if v := ctx.Query("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 {
			limit = l
		} else if err != nil {
			ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid limit: %w", err)))
			return
		}
	}

	// Filters
	filter := repository.UserListFilter{}
	if q := ctx.Query("q"); q != "" {
		filter.Query = q
	}
	if r := ctx.Query("role"); r != "" {
		filter.Role = &r
	}
	if ec := ctx.Query("email_confirmed"); ec != "" {
		switch ec {
		case "true", "1", "yes", "on":
			b := true
			filter.EmailConfirmed = &b
		case "false", "0", "no", "off":
			b := false
			filter.EmailConfirmed = &b
		default:
			ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("invalid email_confirmed value")))
			return
		}
	}
	if l := ctx.Query("locale"); l != "" {
		filter.Locale = &l
	}

	users, total, err := a.AuthService.ListUsers(ctx, filter, page, limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("list users failed: %w", err)))
		return
	}

	// Map to presenter
	items := make([]presenters.UserResponse, 0, len(users))
	for _, u := range users {
		items = append(items, presenters.UserResponse{
			FirstName:      u.FirstName,
			LastName:       u.LastName,
			Email:          u.Email,
			EmailConfirmed: u.EmailConfirmed,
			LocaleType:     u.LocaleType,
			Roles:          u.Roles,
			Photo:          u.Photo,
		})
	}

	ctx.JSON(http.StatusOK, presenters.UserListResponse{
		Items: items,
		Total: total,
		Page:  page,
		Limit: limit,
	})
}

// OauthGoogleLogin
// @Summary Google OAuth login
// @Description Initiates Google OAuth login. Builds a signed state token and redirects to Google.
// @Tags OAuth
// @Accept json
// @Produce json
// @Param redirect_url query string true "Frontend URL to redirect after callback (must be allowlisted)"
// @Success 307
// @Router /oauth/google [get]
func OauthGoogleLogin(ctx *gin.Context, a *app.App) {
	requested := ctx.Query("redirect_url")
	nonce, url, err := a.OAuthService.StartGoogleLogin(ctx, requested)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("failed to start oauth: %w", err)))
		return
	}
	a.Logger.Infoln("Redirecting to Google OAuth URL:", url)
	cookieCfg := a.Config.CookieConfig
	ctx.SetCookie("oauth_state", nonce, int((5 * time.Minute).Seconds()), cookieCfg.Path, cookieCfg.Domain, cookieCfg.Secure, cookieCfg.HttpOnly)
	ctx.Redirect(http.StatusTemporaryRedirect, url)
}

// OauthGoogleCallback
// @Summary Google OAuth callback
// @Description Handles Google OAuth callback, validates signed state, issues tokens and sets refresh token cookie.
// @Tags OAuth
// @Accept json
// @Produce json
// @Param state query string true "Signed OAuth state"
// @Param code query string true "OAuth authorization code"
// @Success 307 "Redirects to frontend if redirect_url is provided and allowed"
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /oauth/google/callback [get]
func OauthGoogleCallback(ctx *gin.Context, a *app.App) {
	state := ctx.Query("state")
	cookieState, _ := ctx.Cookie("oauth_state")
	code := ctx.Query("code")
	if code == "" {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("missing code")))
		return
	}
	tokens, redirectURL, _, err := a.OAuthService.HandleGoogleCallback(ctx, code, state, cookieState)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenters.Error(err))
		return
	}

	setCookieWithConfig(ctx, a, "refresh_token", tokens.RefreshToken, int(a.Config.CookieConfig.MaxAge.Duration().Seconds()))
	// clear state cookie then redirect if present, else return tokens JSON
	cookieCfg := a.Config.CookieConfig
	ctx.SetCookie("oauth_state", "", -1, cookieCfg.Path, cookieCfg.Domain, cookieCfg.Secure, cookieCfg.HttpOnly)
	if redirectURL != "" {
		ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}
	Logout(ctx, a) // clear any existing session
	ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("no redirect URL configured")))
}

// OauthYandexLogin
// @Summary Yandex OAuth login
// @Description Initiates Yandex OAuth login. Builds a signed state token and redirects to Yandex.
// @Tags OAuth
// @Accept json
// @Produce json
// @Param redirect_url query string true "Frontend URL to redirect after callback (must be allowlisted)"
// @Success 307
// @Router /oauth/yandex [get]
func OauthYandexLogin(ctx *gin.Context, a *app.App) {
	requested := ctx.Query("redirect_url")
	nonce, url, err := a.OAuthService.StartYandexLogin(ctx, requested)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, presenters.Error(fmt.Errorf("failed to start oauth: %w", err)))
		return
	}
	a.Logger.Infoln("Redirecting to Yandex OAuth URL:", url)
	cookieCfg := a.Config.CookieConfig
	ctx.SetCookie("oauth_state", nonce, int((5 * time.Minute).Seconds()), cookieCfg.Path, cookieCfg.Domain, cookieCfg.Secure, cookieCfg.HttpOnly)
	ctx.Redirect(http.StatusTemporaryRedirect, url)
}

// OauthYandexCallback
// OauthYandexCallback
// @Summary Yandex OAuth callback
// @Description Handles Yandex OAuth callback, validates signed state, issues tokens and sets refresh token cookie.
// @Tags OAuth
// @Accept json
// @Produce json
// @Param state query string true "Signed OAuth state"
// @Param code query string true "OAuth authorization code"
// @Success 307 "Redirects to frontend if redirect_url is provided and allowed"
// @Failure 400 {object} presenters.ErrorResponse
// @Failure 500 {object} presenters.ErrorResponse
// @Router /oauth/yandex/callback [get]
func OauthYandexCallback(ctx *gin.Context, a *app.App) {
	state := ctx.Query("state")
	cookieState, _ := ctx.Cookie("oauth_state")
	code := ctx.Query("code")
	if code == "" {
		ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("missing code")))
		return
	}
	tokens, redirectURL, _, err := a.OAuthService.HandleYandexCallback(ctx, code, state, cookieState)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, presenters.Error(err))
		return
	}
	setCookieWithConfig(ctx, a, "refresh_token", tokens.RefreshToken, int(a.Config.CookieConfig.MaxAge.Duration().Seconds()))
	cookieCfg := a.Config.CookieConfig
	ctx.SetCookie("oauth_state", "", -1, cookieCfg.Path, cookieCfg.Domain, cookieCfg.Secure, cookieCfg.HttpOnly)
	if redirectURL != "" {
		ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}
	ctx.JSON(http.StatusBadRequest, presenters.Error(fmt.Errorf("no redirect URL configured")))
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
