package logger

import (
	"context"

	grpclog "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"

	"github.com/sirupsen/logrus"
)

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

		// Преобразование поля `fields` в структуру с ключами
		logFields := make(map[string]any)
		for i := 0; i < len(fields); i += 2 {
			if i+1 < len(fields) {
				key, ok := fields[i].(string)
				if !ok {
					key = "unknown"
				}
				logFields[key] = fields[i+1]
			}
		}

		// Логирование с полями
		l.WithFields(logrus.Fields{
			"details": logFields,
		}).Log(logrusLevel, msg)
	})
}
