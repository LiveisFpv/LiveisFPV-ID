package interceptors

import (
	"authorization_service/pkg/logger"
	"time"

	grpclog "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func NewLoggingInterceptor(log *logrus.Logger) grpc.UnaryServerInterceptor {
	opts := []grpclog.Option{
		grpclog.WithLogOnEvents(
			grpclog.PayloadReceived,
			grpclog.PayloadSent,
		),
		grpclog.WithDurationField(func(duration time.Duration) grpclog.Fields {
			return grpclog.Fields{"latency", duration.String()}
		}),
	}

	return grpclog.UnaryServerInterceptor(logger.InterceptorLogger(log), opts...)
}
