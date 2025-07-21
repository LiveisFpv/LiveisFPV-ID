package middlewares

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const (
	maxBodySizeToLog = 1024
)

type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w responseBodyWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// RequestLogger логирует входящие запросы
func RequestLogger(log *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Пропускаем health-check запросы
		if c.Request.URL.Path == "/healthz" {
			c.Next()
			return
		}

		// Читаем тело запроса (с ограничением размера)
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(c.Request.Body, maxBodySizeToLog))
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Восстанавливаем тело
		}

		entry := log.WithFields(logrus.Fields{
			"type":       "request",
			"client_ip":  c.ClientIP(),
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"user_agent": c.Request.UserAgent(),
			"body_size":  len(bodyBytes),
			"body":       string(bodyBytes), // Логируем только первые maxBodySizeToLog байт
		})

		if len(c.Request.URL.RawQuery) > 0 {
			entry = entry.WithField("query", c.Request.URL.RawQuery)
		}

		entry.Info("incoming request")

		// Сохраняем время начала обработки для ResponseLogger
		c.Set("start_time", time.Now())
		c.Next()
	}
}

// ResponseLogger логирует исходящие ответы
func ResponseLogger(log *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Создаем кастомный Writer для перехвата тела ответа
		w := &responseBodyWriter{
			ResponseWriter: c.Writer,
			body:           bytes.NewBufferString(""),
		}
		c.Writer = w
		c.Next()

		// Пропускаем health-check запросы
		if c.Request.URL.Path == "/healthz" {
			return
		}

		// Получаем время начала из контекста
		startTime, exists := c.Get("start_time")
		if !exists {
			startTime = time.Now()
		}

		latency := time.Since(startTime.(time.Time))

		// Читаем тело ответа (если нужно)
		responseBody := w.body.String()

		entry := log.WithFields(logrus.Fields{
			"type":      "response",
			"status":    c.Writer.Status(),
			"method":    c.Request.Method,
			"path":      c.Request.URL.Path,
			"latency":   latency.String(),
			"client_ip": c.ClientIP(),
		})

		if len(responseBody) > 0 {
			entry = entry.WithField("response_size", len(responseBody))
			if len(responseBody) <= maxBodySizeToLog {
				entry = entry.WithField("response_body", responseBody)
			}
		}

		// Логируем ошибки, если они есть
		if len(c.Errors) > 0 {
			entry = entry.WithField("errors", c.Errors.JSON())
		}

		switch {
		case c.Writer.Status() >= 500:
			entry.Error("server error")
		case c.Writer.Status() >= 400:
			entry.Warn("client error")
		default:
			entry.Info("request completed")
		}
	}
}
