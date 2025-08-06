package http

import (
	"authorization_service/internal/app"
	"authorization_service/internal/config"
	"context"
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Server struct {
	port       string
	app        *gin.Engine
	httpServer *http.Server
}

func NewHTTPServer(conf *config.Config, a *app.App) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(
		//middlewares logger need
		gin.Logger(),
		gin.Recovery(),
	)
	httpServer := &http.Server{
		Addr:    conf.HttpServerConfig.Port,
		Handler: r,
	}
	s := Server{
		port:       conf.HttpServerConfig.Port,
		app:        r,
		httpServer: httpServer,
	}
	s.app.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},                                       // Need added to config legal adresses                                      // Разрешаем запросы с любых доменов
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, // Разрешаем все нужные методы
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))
	// Register routes
	MainRouter(s.app.Group("/api/auth"), a)
	OauthRouter(s.app.Group("/api/oauth"), a)
	return &s
}

func (s *Server) Listen() error {
	fmt.Printf("Server is running on %s\n", s.port)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
