package http

import (
	"authorization_service/internal/app"
	"authorization_service/internal/config"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Server struct {
	port string
	app  *gin.Engine
}

func NewHTTPServer(conf config.Config, a *app.App) Server {
	gin.SetMode(gin.ReleaseMode)
	s := Server{
		port: string(conf.HttpServerConfig.Port),
		app:  gin.Default(),
	}
	s.app.Use()
	return s
}

func (s *Server) Listen() error {
	return s.app.Run(s.port)
}

func (s *Server) Handler() http.Handler {
	return s.app
}
