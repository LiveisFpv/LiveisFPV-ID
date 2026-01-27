package liveid

import (
	liveidv1 "authorization_service/api/live_id/v1"

	"google.golang.org/grpc"
)

func Register(gRPCServer *grpc.Server, server *Server) {
	liveidv1.RegisterAuthServiceServer(gRPCServer, server.Auth)
	liveidv1.RegisterUserServiceServer(gRPCServer, server.User)
}
