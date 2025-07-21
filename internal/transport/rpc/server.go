package rpc

import (
	"authorization_service/internal/transport/rpc/service/sso"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type Server struct {
	log        *logrus.Logger
	gRPCServer *grpc.Server
	port       int
}

func New(
	log *logrus.Logger,
	ssoService sso.Sso_service, // ? Мб переименовать и разделить
	port int,
) *Server {
	// Создаем цепочку интерцепторов
	interceptors := NewMiddlewareChain(log)

	// Инициализируем gRPC сервер
	gRPCServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(interceptors...),
	)

	// Регистрируем сервисы
	sso.Register(gRPCServer, ssoService)

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
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.log.Infof("gRPC server started on port %d", s.port)

	if err := s.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

func (s *Server) Stop() {
	s.log.Info("stopping gRPC server")
	s.gRPCServer.GracefulStop()
}
