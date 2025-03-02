package logger

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

type AsyncLogstashHook struct {
	address string
	logChan chan string
}

func NewAsyncLogstashHook(address string) *AsyncLogstashHook {
	hook := &AsyncLogstashHook{
		address: address,
		logChan: make(chan string, 100), // Буфер для логов
	}
	go hook.processLogs()
	return hook
}

func (h *AsyncLogstashHook) processLogs() {
	var conn net.Conn
	var err error

	for logMsg := range h.logChan {
		// Если соединение отсутствует, пытаемся восстановить
		if conn == nil {
			conn, err = net.DialTimeout("tcp", h.address, 2*time.Second)
			if err != nil {
				time.Sleep(2 * time.Second) // Ожидание перед повторной попыткой
				continue
			}
		}

		// Пишем лог в соединение
		_, err = conn.Write([]byte(logMsg + "\n"))
		if err != nil {
			conn.Close()
			conn = nil
		}
	}
}

func (h *AsyncLogstashHook) Fire(entry *logrus.Entry) error {
	logMsg, err := entry.String()
	if err != nil {
		return err
	}
	select {
	case h.logChan <- logMsg: // Лог отправляется в очередь
	default:
		// Если очередь заполнена, отбрасываем логи (чтобы не тормозить приложение)
	}
	return nil
}

func (h *AsyncLogstashHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func LoggerSetup(debug bool) *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339})

	if debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	hook := NewAsyncLogstashHook("logstash:5050")
	logger.AddHook(hook)

	return logger
}
