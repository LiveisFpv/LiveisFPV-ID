package service

import (
	"authorization_service/internal/config"
	"context"
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
	frontendURL  string
	jwtSecret    string
	domainURL    string
}

func NewEmailService(config *config.EmailConfig, frontendURL, jwtSecret, domainURL string) EmailService {
	return &emailService{
		smtpHost:     config.SMTPHost,
		smtpPort:     config.SMTPPort,
		smtpUsername: config.SMTPUsername,
		smtpPassword: config.SMTPPassword,
		fromEmail:    config.FromEmail,
		frontendURL:  frontendURL,
		jwtSecret:    jwtSecret,
		domainURL:    domainURL,
	}
}

// GenerateEmailConfirmationToken implements EmailService.
func (e *emailService) GenerateEmailConfirmationToken(ctx context.Context, userID int, email string) (string, error) {
	panic("unimplemented")
}

// SendEmailConfirmation implements EmailService.
func (e *emailService) SendEmailConfirmation(ctx context.Context, userID int, email string) error {
	panic("unimplemented")
}

// VerifyEmailConfirmationToken implements EmailService.
func (e *emailService) VerifyEmailConfirmationToken(ctx context.Context, token string) (int, error) {
	panic("unimplemented")
}
