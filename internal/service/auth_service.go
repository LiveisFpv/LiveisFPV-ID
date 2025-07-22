package service

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
)

type AuthService interface {
	Login(ctx context.Context, email, password string) (*domain.UserTokens, error)
	Logout(ctx context.Context, refreshToken string) error
	Refresh(ctx context.Context, refreshToken string) (*domain.UserTokens, error)
	Authenticate(ctx context.Context, accessToken string) (*domain.User, error)
	CreateTokens(ctx context.Context, userID int) (*domain.UserTokens, error)
	CreateUser(ctx context.Context, user *domain.User) (*domain.User, error)
	UpdateUser(ctx context.Context, accessToken string, user *domain.User) (*domain.User, error)
	ConfirmEmail(ctx context.Context, token string) (int, error)
	SendEmailConfirmation(ctx context.Context, userID int, email string) error
	GetUserByID(ctx context.Context, userID int) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	DeleteSession(ctx context.Context, sessionID int) error
}

type authService struct {
	jwtService     JWTService
	emailService   EmailService
	sessionService SessionService
	userRepository repository.UserRepository
}

func NewAuthService(jwtService JWTService, emailService EmailService, sessionService SessionService, userRepository repository.UserRepository) AuthService {
	return &authService{
		jwtService:     jwtService,
		emailService:   emailService,
		sessionService: sessionService,
		userRepository: userRepository,
	}
}

// Authenticate implements AuthService.
func (a *authService) Authenticate(ctx context.Context, accessToken string) (*domain.User, error) {
	panic("unimplemented")
}

// ConfirmEmail implements AuthService.
func (a *authService) ConfirmEmail(ctx context.Context, token string) (int, error) {
	panic("unimplemented")
}

// CreateTokens implements AuthService.
func (a *authService) CreateTokens(ctx context.Context, userID int) (*domain.UserTokens, error) {
	panic("unimplemented")
}

// CreateUser implements AuthService.
func (a *authService) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	panic("unimplemented")
}

// DeleteSession implements AuthService.
func (a *authService) DeleteSession(ctx context.Context, sessionID int) error {
	panic("unimplemented")
}

// GetUserByEmail implements AuthService.
func (a *authService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	panic("unimplemented")
}

// GetUserByID implements AuthService.
func (a *authService) GetUserByID(ctx context.Context, userID int) (*domain.User, error) {
	panic("unimplemented")
}

// Login implements AuthService.
func (a *authService) Login(ctx context.Context, email string, password string) (*domain.UserTokens, error) {
	panic("unimplemented")
}

// Logout implements AuthService.
func (a *authService) Logout(ctx context.Context, refreshToken string) error {
	panic("unimplemented")
}

// Refresh implements AuthService.
func (a *authService) Refresh(ctx context.Context, refreshToken string) (*domain.UserTokens, error) {
	panic("unimplemented")
}

// SendEmailConfirmation implements AuthService.
func (a *authService) SendEmailConfirmation(ctx context.Context, userID int, email string) error {
	panic("unimplemented")
}

// UpdateUser implements AuthService.
func (a *authService) UpdateUser(ctx context.Context, accessToken string, user *domain.User) (*domain.User, error) {
	panic("unimplemented")
}
