package rpc

import (
	"authorization_service/internal/transport/rpc/interceptors"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func NewMiddlewareChain(log *logrus.Logger) []grpc.UnaryServerInterceptor {
	return []grpc.UnaryServerInterceptor{
		interceptors.NewRecoveryInterceptor(log),
		interceptors.NewLoggingInterceptor(log),
		// Здесь можно добавить другие интерцепторы
	}
}
