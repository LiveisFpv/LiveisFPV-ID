package middlewares

import (
	"authorization_service/internal/transport/rpc"
	"authorization_service/pkg/logger"
	"fmt"
	"log/slog"
	"net"

	grpclog "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type App struct {
	log        *logrus.Logger
	gRPCServer *grpc.Server
	port       int
}

func New(log *logrus.Logger, sso_Service rpc.Sso_service, port int) *App {

	recoverOpts := []recovery.Option{
		recovery.WithRecoveryHandler(
			func(p interface{}) (err error) {
				//Logging panic with leve error
				log.Errorf("Recovered from panic %s", p)
				//Return to client internal error
				return status.Errorf(codes.Internal, "internal error")
			}),
	}

	//logging all, logging data, loggind payload, user didnt know that we know
	loggingOpts := []grpclog.Option{
		grpclog.WithLogOnEvents(
			grpclog.PayloadReceived, grpclog.PayloadSent,
		),
	}
	//Create grpcServer with interseptors(logger, recover)
	gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		recovery.UnaryServerInterceptor(recoverOpts...),
		grpclog.UnaryServerInterceptor(logger.InterceptorLogger(log), loggingOpts...),
	))

	//Тута и мне осознать надо
	rpc.Register(gRPCServer, sso_Service)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

// Start gRPC server
func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

// Run runs gRPC server.
func (a *App) Run() error {
	const op = "grpcapp.Run"

	// Создаём listener, который будет слушить TCP-сообщения, адресованные
	// Нашему gRPC-серверу
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	a.log.Info("grpc server started", slog.String("addr", l.Addr().String()))

	// Запускаем обработчик gRPC-сообщений
	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// Stop gRPC server
func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.Infof("op %s", op)
	a.log.Info("stopping gRPC server", slog.Int("port", a.port))

	a.gRPCServer.GracefulStop()
}
