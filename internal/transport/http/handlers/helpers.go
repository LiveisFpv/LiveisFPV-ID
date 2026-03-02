package handlers

import (
	"authorization_service/internal/app"
	"net/http"

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
