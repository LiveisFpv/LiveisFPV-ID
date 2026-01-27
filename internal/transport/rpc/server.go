package rpc

import (
	"authorization_service/internal/app"
	"authorization_service/internal/transport/rpc/service/liveid"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type Server struct {
	log        *logrus.Logger
	gRPCServer *grpc.Server
	port       string
}

func New(
	log *logrus.Logger,
	a *app.App,
	port string,
) *Server {
	// Build interceptor chain.
	interceptors := NewMiddlewareChain(log)

	// Initialize gRPC server.
	gRPCServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(interceptors...),
	)

	// Register services.
	liveidServer := liveid.New(a)
	liveid.Register(gRPCServer, liveidServer)

	return &Server{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (s *Server) MustRun() {
	if err := s.Run(); err != nil {
		s.log.Fatalf("gRPC server failed: %v", err)
	}
}

func (s *Server) Run() error {
	l, err := net.Listen("tcp", fmt.Sprintf(":%s", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.log.Infof("gRPC server started on port %s", s.port)

	if err := s.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

func (s *Server) Stop() {
	s.log.Info("stopping gRPC server")
	s.gRPCServer.GracefulStop()
}
