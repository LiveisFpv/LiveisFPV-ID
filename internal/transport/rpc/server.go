package rpc

import "google.golang.org/grpc"

type serverAPI struct {
	sso_service_v1.UnimplementedTestRPCServer
	sso_service Sso_service
}

type Sso_service interface {
}

func Register(gRPCServer *grpc.Server, sso_service Sso_service) {
	sso_service_v1.RegisterTestRPCServer(gRPCServer, &serverAPI{sso_service: sso_service})
}
