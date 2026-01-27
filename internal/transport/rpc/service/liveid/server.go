package liveid

import (
	"authorization_service/internal/app"
	"authorization_service/internal/transport/rpc/handlers"
)

type Server struct {
	Auth *handlers.AuthHandler
	User *handlers.UserHandler
}

func New(a *app.App) *Server {
	return &Server{
		Auth: handlers.NewAuthHandler(a),
		User: handlers.NewUserHandler(a),
	}
}
