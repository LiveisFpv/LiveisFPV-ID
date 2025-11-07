package service

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserExists             = fmt.Errorf("user already exists")
	ErrPasswordResetTokenUsed = errors.New("password reset token already used")
)

type AuthService interface {
	Login(ctx context.Context, email, password string) (*domain.UserTokens, error)
	Logout(ctx context.Context, refreshToken string) error
	Refresh(ctx context.Context, refreshToken string) (*domain.UserTokens, error)
	Authenticate(ctx context.Context, accessToken string) (*domain.User, error)
	Validate(ctx context.Context, accessToken string) (int, error)
	CreateUser(ctx context.Context, user *domain.User) (*domain.User, error)
	UpdateUser(ctx context.Context, accessToken string, user *domain.User) (*domain.User, error)
	UpdateUserAdmin(ctx context.Context, input *domain.User) (*domain.User, error)
	ConfirmEmail(ctx context.Context, token string) (int, error)
	SendEmailConfirmation(ctx context.Context, userID int, email string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ConfirmPasswordReset(ctx context.Context, token string) error
	GetUserByID(ctx context.Context, userID int) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	DeleteSession(ctx context.Context, refresh_token string) error
	// ListUsers returns a page of users matching filter and total count
	ListUsers(ctx context.Context, filter repository.UserListFilter, page, limit int) ([]*domain.User, int, error)
}

type authService struct {
	jwtService     JWTService
	emailService   EmailService
	sessionService SessionService
	userRepository repository.UserRepository
	tokenBlocklist repository.TokenBlocklist
	logger         *logrus.Logger
}

func NewAuthService(jwtService JWTService, emailService EmailService,
	sessionService SessionService, userRepository repository.UserRepository, tokenBlocklist repository.TokenBlocklist, logger *logrus.Logger) AuthService {
	return &authService{
		jwtService:     jwtService,
		emailService:   emailService,
		sessionService: sessionService,
		userRepository: userRepository,
		tokenBlocklist: tokenBlocklist,
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
	if err != nil && !errors.Is(err, repository.ErrorUserNotFound) {
		return nil, fmt.Errorf("failed to check existing user by email %s: %w", user.Email, err)
	}

	if existingUser != nil {
		return nil, ErrUserExists
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

	// Ensure locale is set to a sane default to satisfy NOT NULL
	if user.LocaleType == nil {
		def := "ru"
		user.LocaleType = &def
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
		a.logger.WithError(err).Errorf("failed to send email confirmation: user_id=%d email=%s", userID, user.Email)
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

// RequestPasswordReset sends a confirmation link to the provided email if the user exists.
func (a *authService) RequestPasswordReset(ctx context.Context, email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	user, err := a.userRepository.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrorUserNotFound) {
			a.logger.WithField("email", email).Debug("password reset requested for non-existent email")
			return nil
		}
		return fmt.Errorf("failed to get user by email %s: %w", email, err)
	}

	if err := a.emailService.SendPasswordResetConfirmation(ctx, user.ID, user.Email); err != nil {
		return fmt.Errorf("failed to send password reset confirmation: %w", err)
	}
	return nil
}

// ConfirmPasswordReset validates confirmation token, rotates the password, revokes sessions and emails the new password.
func (a *authService) ConfirmPasswordReset(ctx context.Context, token string) error {
	userID, tokenEmail, tokenID, expiresAt, err := a.emailService.VerifyPasswordResetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to verify password reset token: %w", err)
	}

	user, err := a.userRepository.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user by ID %d: %w", userID, err)
	}
	if user == nil {
		return fmt.Errorf("user with ID %d not found", userID)
	}

	targetEmail := user.Email
	if !strings.EqualFold(user.Email, tokenEmail) {
		a.logger.WithFields(logrus.Fields{
			"user_id":     userID,
			"storedEmail": user.Email,
			"tokenEmail":  tokenEmail,
		}).Warn("password reset token email differs from stored email")
	}

	if a.tokenBlocklist != nil {
		used, blockErr := a.tokenBlocklist.IsBlocked(ctx, tokenID)
		if blockErr != nil {
			return fmt.Errorf("failed to verify password reset token status: %w", blockErr)
		}
		if used {
			return fmt.Errorf("password reset token already used: %w", ErrPasswordResetTokenUsed)
		}
	}

	newPassword, err := generateRandomPassword(12, 16)
	if err != nil {
		return fmt.Errorf("failed to generate new password: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	if err := a.userRepository.UpdatePassword(ctx, userID, string(hashedPassword)); err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}

	if err := a.sessionService.DeleteAllUserSessions(ctx, userID); err != nil {
		a.logger.WithError(err).Warnf("failed to revoke sessions for user %d after password reset", userID)
	}

	if a.tokenBlocklist != nil {
		ttl := time.Until(expiresAt)
		if ttl <= 0 {
			ttl = time.Hour
		}
		if err := a.tokenBlocklist.Block(ctx, tokenID, ttl); err != nil {
			a.logger.WithError(err).Warn("failed to mark password reset token as used")
		}
	}

	if err := a.emailService.SendNewPassword(ctx, targetEmail, newPassword); err != nil {
		return fmt.Errorf("failed to send new password email: %w", err)
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

// UpdateUserAdmin updates arbitrary user data without relying on access token verification.
func (a *authService) UpdateUserAdmin(ctx context.Context, input *domain.User) (*domain.User, error) {
	userID := input.ID
	user, err := a.userRepository.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID %d: %w", userID, err)
	}
	if user.FirstName == "" {
		user.FirstName = input.FirstName
	}

	if user.LastName == "" {
		user.LastName = input.LastName
	}

	if user.Email == "" {
		user.Email = input.Email
	}

	if input.Password != nil {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*input.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		hashedPass := string(hashedPassword)
		user.Password = &hashedPass
	}

	if input.Roles != nil {
		user.Roles = input.Roles
	}

	if input.LocaleType != nil {
		user.LocaleType = input.LocaleType
	}

	if err := a.userRepository.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user via admin: %w", err)
	}

	return user, nil
}

// ListUsers implements AuthService.
func (a *authService) ListUsers(ctx context.Context, filter repository.UserListFilter, page, limit int) ([]*domain.User, int, error) {
	users, total, err := a.userRepository.ListUsers(ctx, filter, page, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	return users, total, nil
}

func generateRandomPassword(minLength, maxLength int) (string, error) {
	if minLength <= 0 || maxLength < minLength {
		return "", fmt.Errorf("invalid password length bounds")
	}

	length := minLength
	if maxLength > minLength {
		diff := maxLength - minLength + 1
		n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
		if err != nil {
			return "", fmt.Errorf("failed to choose password length: %w", err)
		}
		length = minLength + int(n.Int64())
	}

	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*"
	password := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("failed to generate password character: %w", err)
		}
		password[i] = alphabet[idx.Int64()]
	}

	return string(password), nil
}
