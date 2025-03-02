package grpcapp

import (
	authgrpc "authorization_service/internal/grpc/auth"
	"context"
	"fmt"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
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
	port       int //There is port with grpc works
}

func InterceptorLogger(l *logrus.Logger) grpclog.Logger {
	return grpclog.LoggerFunc(func(ctx context.Context, lvl grpclog.Level, msg string, fields ...any) {
		var logrusLevel logrus.Level
		switch lvl {
		case grpclog.LevelDebug:
			logrusLevel = logrus.DebugLevel
		case grpclog.LevelInfo:
			logrusLevel = logrus.InfoLevel
		case grpclog.LevelWarn:
			logrusLevel = logrus.WarnLevel
		case grpclog.LevelError:
			logrusLevel = logrus.ErrorLevel
		default:
			logrusLevel = logrus.InfoLevel
		}

		l.WithFields(logrus.Fields{"details": fields}).Log(logrusLevel, msg)
	})
}

func New(log *logrus.Logger, authService authgrpc.Auth, port int) *App {

	recoverOpts := []recovery.Option{
		recovery.WithRecoveryHandler(func(p interface{}) (err error) {
			//Logging panic with leve error
			log.Error("Recovered from panic", p)

			//Return to client internal error
			return status.Errorf(codes.Internal, "internal error")
		}),
	}
	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(
			logging.PayloadReceived, logging.PayloadSent,
		),
	}

	//TODO: create gRPCServer and connect it insterseptors
	gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		recovery.UnaryServerInterceptor(recoverOpts...),
		logging.UnaryServerInterceptor(InterceptorLogger(log), loggingOpts...),
	))

	//TODO: sign up our gRPC-service Auth
	authgrpc.Register(gRPCServer, authService)

	//TODO: Return App object with all params
	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

// MustRun runs gRPC server and panics if any error occurs.
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

	a.log.Info("grpc server started", "addr", l.Addr().String())

	// Запускаем обработчик gRPC-сообщений
	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// Stop gRPC server
func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.WithFields(
		logrus.Fields{
			"op": op,
		})
	a.log.Info("stopping gRPC server", "port", a.port)

	a.gRPCServer.GracefulStop()
}
