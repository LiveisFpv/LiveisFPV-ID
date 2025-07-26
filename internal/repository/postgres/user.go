package postgres

import (
	"authorization_service/internal/domain"
	"context"
	"fmt"
)

func (ur *userRepository) GetUserByID(ctx context.Context, id int) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ur *userRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ur *userRepository) GetUserByGoogleID(ctx context.Context, id string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ur *userRepository) GetUserByVkID(ctx context.Context, id string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ur *userRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	return fmt.Errorf("not implemented")
}

func (ur *userRepository) CreateUser(ctx context.Context, user *domain.User) (userID int, err error) {
	return 0, fmt.Errorf("not implemented")
}

func (ur *userRepository) ConfirmEmail(ctx context.Context, userID int) error {
	return fmt.Errorf("not implemented")
}
