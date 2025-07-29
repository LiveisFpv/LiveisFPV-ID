package http

import (
	"authorization_service/internal/app"
	"authorization_service/internal/transport/http/handlers"

	"github.com/gin-gonic/gin"
)

func MainRouter(r *gin.RouterGroup, a *app.App) {
	r.POST("/login", func(ctx *gin.Context) { handlers.Login(ctx, a) })
	r.POST("/logout", func(ctx *gin.Context) { handlers.Logout(ctx, a) })
	r.POST("/refresh", func(ctx *gin.Context) { handlers.Refresh(ctx, a) })
}
func OauthRouter(r *gin.RouterGroup, a *app.App) {
	r.GET("/google", func(ctx *gin.Context) { handlers.OauthGoogleLogin(ctx, a) })
	r.GET("/google/callback", func(ctx *gin.Context) { handlers.OauthGoogleCallback(ctx, a) })
	// r.GET("/yandex", func(ctx *gin.Context) { handlers.OauthYandexLogin(ctx, a) })
	// r.GET("/yandex/callback", func(ctx *gin.Context) { handlers.OauthYandexCallback(ctx, a) })
	// r.GET("/vk", func(ctx *gin.Context) { handlers.OauthVkLogin(ctx, a) })
	// r.GET("/vk/callback", func(ctx *gin.Context) { handlers.OauthVkCallback(ctx, a) })
}
