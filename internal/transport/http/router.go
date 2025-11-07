package http

import (
	"authorization_service/internal/app"
	"authorization_service/internal/transport/http/handlers"
	"authorization_service/internal/transport/http/middlewares"

	"github.com/gin-gonic/gin"
)

func MainRouter(r *gin.RouterGroup, a *app.App) {
	r.POST("/logout", func(ctx *gin.Context) { handlers.Logout(ctx, a) })
	r.POST("/refresh", func(ctx *gin.Context) { handlers.Refresh(ctx, a) })
	r.PUT("/update", func(ctx *gin.Context) { handlers.UpdateUser(ctx, a) })
	r.GET("/confirm-email", func(ctx *gin.Context) { handlers.ConfirmEmail(ctx, a) })
	r.POST("/password-reset", func(ctx *gin.Context) { handlers.RequestPasswordReset(ctx, a) })
	r.GET("/password-reset/confirm", func(ctx *gin.Context) { handlers.ConfirmPasswordReset(ctx, a) })
	r.POST("/login", func(ctx *gin.Context) { handlers.Login(ctx, a) })
	r.POST("/create", func(ctx *gin.Context) { handlers.CreateUser(ctx, a) })
	r.GET("/authenticate", func(ctx *gin.Context) { handlers.Authenticate(ctx, a) })
	r.GET("/validate", func(ctx *gin.Context) { handlers.Validate(ctx, a) })
}
func AdminRouter(r *gin.RouterGroup, a *app.App) {
	admin := r.Group("", middlewares.AdminOnly(a))
	admin.GET("/admin/users", func(ctx *gin.Context) { handlers.ListUsers(ctx, a) })
	admin.POST("/admin/users", func(ctx *gin.Context) { handlers.CreateUserWithRoles(ctx, a) })
	admin.PUT("/admin/users/:id", func(ctx *gin.Context) { handlers.UpdateUserAdmin(ctx, a) })
}
func OauthRouter(r *gin.RouterGroup, a *app.App) {
	r.GET("/google", func(ctx *gin.Context) { handlers.OauthGoogleLogin(ctx, a) })
	r.GET("/google/callback", func(ctx *gin.Context) { handlers.OauthGoogleCallback(ctx, a) })
	r.GET("/yandex", func(ctx *gin.Context) { handlers.OauthYandexLogin(ctx, a) })
	r.GET("/yandex/callback", func(ctx *gin.Context) { handlers.OauthYandexCallback(ctx, a) })
	r.GET("/vk", func(ctx *gin.Context) { handlers.OauthVkLogin(ctx, a) })
	r.GET("/vk/callback", func(ctx *gin.Context) { handlers.OauthVkCallback(ctx, a) })
}
