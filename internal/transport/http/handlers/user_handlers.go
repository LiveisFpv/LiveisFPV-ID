package handlers

import (
	"authorization_service/internal/app"
	"authorization_service/internal/transport/http/presenters"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Logout(ctx *gin.Context, a *app.App) {
	panic("Logout handler not implemented")
}

func Refresh(ctx *gin.Context, a *app.App) {
	panic("Refresh handler not implemented")
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
	resp := presenters.TokenResReq{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
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
