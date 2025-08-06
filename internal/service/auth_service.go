package service

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Login(ctx context.Context, email, password string) (*domain.UserTokens, error)
	Logout(ctx context.Context, refreshToken string) error
	Refresh(ctx context.Context, refreshToken string) (*domain.UserTokens, error)
	Authenticate(ctx context.Context, accessToken string) (*domain.User, error)
	Validate(ctx context.Context, accessToken string) (int, error)
	CreateUser(ctx context.Context, user *domain.User) (*domain.User, error)
	UpdateUser(ctx context.Context, accessToken string, user *domain.User) (*domain.User, error)
	ConfirmEmail(ctx context.Context, token string) (int, error)
	SendEmailConfirmation(ctx context.Context, userID int, email string) error
	GetUserByID(ctx context.Context, userID int) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	DeleteSession(ctx context.Context, refresh_token string) error
}

type authService struct {
	jwtService     JWTService
	emailService   EmailService
	sessionService SessionService
	userRepository repository.UserRepository
	logger         *logrus.Logger
}

func NewAuthService(jwtService JWTService, emailService EmailService,
	sessionService SessionService, userRepository repository.UserRepository, logger *logrus.Logger) AuthService {
	return &authService{
		jwtService:     jwtService,
		emailService:   emailService,
		sessionService: sessionService,
		userRepository: userRepository,
		logger:         logger,
	}
}

// Authenticate implements AuthService.
func (a *authService) Authenticate(ctx context.Context, accessToken string) (*domain.User, error) {
	userID, err := a.jwtService.VerifyToken(ctx, accessToken, domain.AccessTokenType)
	if err != nil {
		return nil, err
	}
	user, err := a.userRepository.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user with ID %d not found", userID)
	}
	return user, nil
}

func (a *authService) Validate(ctx context.Context, accessToken string) (int, error) {
	userID, err := a.jwtService.VerifyToken(ctx, accessToken, domain.AccessTokenType)
	if err != nil {
		return 0, fmt.Errorf("failed to verify access token: %w", err)
	}
	return userID, nil
}

// ConfirmEmail implements AuthService.
func (a *authService) ConfirmEmail(ctx context.Context, token string) (int, error) {
	userID, err := a.emailService.VerifyEmailConfirmationToken(ctx, token)
	if err != nil {
		return 0, fmt.Errorf("failed to verify email confirmation token: %w", err)
	}

	err = a.userRepository.ConfirmEmail(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to confirm email for user ID %d: %w", userID, err)
	}

	return userID, nil
}

// CreateUser implements AuthService.
func (a *authService) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}
	existingUser, err := a.userRepository.GetUserByEmail(ctx, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing user by email %s: %w", user.Email, err)
	}

	if existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", user.Email)
	}

	if user.Password == nil {
		return nil, fmt.Errorf("password cannot be nil")
	}
	pass, _ := bcrypt.GenerateFromPassword([]byte(*user.Password), bcrypt.DefaultCost)
	p := string(pass)

	user.Password = &p
	user.EmailConfirmed = false

	if user.Roles == nil {
		user.Roles = []string{"USER"}
	}

	userID, err := a.userRepository.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	user, err = a.userRepository.GetUserByID(ctx, userID)

	if err != nil {
		return nil, fmt.Errorf("failed to get created user by ID %d: %w", userID, err)
	}

	err = a.emailService.SendEmailConfirmation(ctx, userID, user.Email)

	if err != nil {
		a.logger.Error(ctx)
	}
	return user, nil
}

// DeleteSession implements AuthService.
func (a *authService) DeleteSession(ctx context.Context, refreshtoken string) error {
	session, err := a.sessionService.GetSessionByRefreshToken(ctx, refreshtoken)
	if err != nil {
		return fmt.Errorf("failed to get session by refresh token: %w", err)
	}
	if session == nil {
		return fmt.Errorf("session not found for refresh token: %s", refreshtoken)
	}

	err = a.sessionService.DeleteSession(ctx, session.SessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// GetUserByEmail implements AuthService.
func (a *authService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	user, err := a.userRepository.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email %s: %w", email, err)
	}
	return user, nil
}

// GetUserByID implements AuthService.
func (a *authService) GetUserByID(ctx context.Context, userID int) (*domain.User, error) {
	user, err := a.userRepository.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID %d: %w", userID, err)
	}
	return user, nil
}

// Login implements AuthService.
func (a *authService) Login(ctx context.Context, email string, password string) (*domain.UserTokens, error) {
	user, err := a.userRepository.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email %s: %w", email, err)
	}
	if user == nil {
		return nil, fmt.Errorf("user with email %s not found", email)
	}

	err = bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(password))

	if err != nil {
		return nil, fmt.Errorf("invalid password for user with email %s: %w", email, err)
	}

	if !user.EmailConfirmed {
		return nil, fmt.Errorf("email for user with email %s is not confirmed", email)
	}

	userTokens, err := a.jwtService.CreateJwtTokens(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT tokens for user with email %s: %w", email, err)
	}

	jti, err := a.jwtService.ParseJTI(ctx, userTokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JTI from access token: %w", err)
	}
	// Create a session for the user
	_, err = a.sessionService.CreateSession(ctx, userTokens.RefreshToken, jti)
	if err != nil {
		return nil, fmt.Errorf("failed to create session for user with email %s: %w", email, err)
	}

	return userTokens, nil
}

// Logout implements AuthService.
func (a *authService) Logout(ctx context.Context, refreshToken string) error {
	session, err := a.sessionService.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		return fmt.Errorf("failed to get session by refresh token: %w", err)
	}
	if session == nil {
		return fmt.Errorf("session not found for refresh token: %s", refreshToken)
	}

	err = a.sessionService.DeleteSession(ctx, session.SessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// Refresh implements AuthService.
func (a *authService) Refresh(ctx context.Context, refreshToken string) (*domain.UserTokens, error) {
	session, err := a.sessionService.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get session by refresh token: %w", err)
	}
	if session == nil {
		return nil, fmt.Errorf("session not found for refresh token: %s", refreshToken)
	}

	userTokens, err := a.jwtService.RefreshTokens(ctx, refreshToken)

	if err != nil {
		return nil, fmt.Errorf("failed to refresh JWT tokens: %w", err)
	}

	// Update the session with the new refresh token
	err = a.DeleteSession(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to delete old session: %w", err)
	}
	jti, err := a.jwtService.ParseJTI(ctx, userTokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JTI from access token: %w", err)
	}

	_, err = a.sessionService.CreateSession(ctx, userTokens.RefreshToken, jti)

	if err != nil {
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	return userTokens, nil
}

// SendEmailConfirmation implements AuthService.
func (a *authService) SendEmailConfirmation(ctx context.Context, userID int, email string) error {
	_, err := a.userRepository.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user by ID %d: %w", userID, err)
	}
	err = a.emailService.SendEmailConfirmation(ctx, userID, email)
	if err != nil {
		return fmt.Errorf("failed to send email confirmation: %w", err)
	}
	return nil
}

// UpdateUser implements AuthService.
func (a *authService) UpdateUser(ctx context.Context, accessToken string, userData *domain.User) (*domain.User, error) {
	userID, err := a.jwtService.VerifyToken(ctx, accessToken, domain.AccessTokenType)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token: %w", err)
	}

	user, err := a.userRepository.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID %d: %w", userID, err)
	}

	user.FirstName = userData.FirstName
	user.LastName = userData.LastName
	user.Email = userData.Email

	if userData.Password != nil {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*userData.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		hashedPass := string(hashedPassword)
		user.Password = &hashedPass
	}

	if userData.Roles != nil {
		user.Roles = userData.Roles
	}

	if userData.Photo != nil {
		user.Photo = userData.Photo
	}
	err = a.userRepository.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	return user, nil
}
