package service

import (
	"authorization_service/internal/config"
	"authorization_service/internal/domain"
	"context"
	"fmt"
	"net/smtp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

type EmailService interface {
	SendEmailConfirmation(ctx context.Context, userID int, email string) error
	GenerateEmailConfirmationToken(ctx context.Context, userID int, email string) (string, error)
	VerifyEmailConfirmationToken(ctx context.Context, token string) (int, error)
}

type emailService struct {
	smtpHost     string
	smtpPort     string
	smtpUsername string
	smtpPassword string
	fromEmail    string
	jwtSecret    string
	domainURL    string
	logger       *logrus.Logger
}

func NewEmailService(config *config.EmailConfig, domainURL string, logger *logrus.Logger) EmailService {
	return &emailService{
		smtpHost:     config.SMTPHost,
		smtpPort:     config.SMTPPort,
		smtpUsername: config.SMTPUsername,
		smtpPassword: config.SMTPPassword,
		fromEmail:    config.FromEmail,
		jwtSecret:    config.JwtSecret,
		domainURL:    domainURL,
		logger:       logger,
	}
}

// GenerateEmailConfirmationToken implements EmailService.
func (e *emailService) GenerateEmailConfirmationToken(ctx context.Context, userID int, email string) (string, error) {
	claims := domain.EmailConfirmationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    e.domainURL,
			Subject:   "email_confirmation",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Token valid for 24 hours
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID: userID,
		Email:  email,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(e.jwtSecret))
}

// SendEmailConfirmation implements EmailService.
func (e *emailService) SendEmailConfirmation(ctx context.Context, userID int, email string) error {
	token, err := e.GenerateEmailConfirmationToken(ctx, userID, email)
	if err != nil {
		return fmt.Errorf("failed to generate email confirmation token: %w", err)
	}

	confirmURL := fmt.Sprintf("%s/confirm-email?token=%s", e.domainURL, token)

	subject := "Подтверждение Email"
	body := fmt.Sprintf("Здравствуйте!\n\nПерейдите по ссылке для подтверждения почты:\n\n%s\n\nЕсли это не вы — проигнорируйте письмо.", confirmURL)
	msg := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)

	auth := smtp.PlainAuth("", e.smtpUsername, e.smtpPassword, e.smtpHost)
	addr := fmt.Sprintf("%s:%s", e.smtpHost, e.smtpPort)

	return smtp.SendMail(addr, auth, e.fromEmail, []string{email}, []byte(msg))
}

// VerifyEmailConfirmationToken implements EmailService.
func (e *emailService) VerifyEmailConfirmationToken(ctx context.Context, token string) (int, error) {
	TokenClaims := &domain.EmailConfirmationClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, TokenClaims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(e.jwtSecret), nil
	})
	if err != nil || !parsedToken.Valid {
		return 0, fmt.Errorf("invalid token")
	}
	if TokenClaims.Subject != "email_confirmation" {
		return 0, fmt.Errorf("invalid token subject")
	}
	if TokenClaims.Issuer != e.domainURL {
		return 0, fmt.Errorf("invalid user domain")
	}
	if time.Now().After(TokenClaims.ExpiresAt.Time) {
		return 0, fmt.Errorf("token has expired")
	}
	return TokenClaims.UserID, nil
}
