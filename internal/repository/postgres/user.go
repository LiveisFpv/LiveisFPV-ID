package postgres

import (
	"authorization_service/internal/domain"
	"context"
	"fmt"

	"github.com/jackc/pgx"
)

func (ur *userRepository) GetUserByID(ctx context.Context, id int) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed, 
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE id = $1 AND is_active = true
    `

	var user domain.User
	err := ur.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

func (ur *userRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE email = $1 AND is_active = true
    `

	var user domain.User
	err := ur.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

func (ur *userRepository) GetUserByGoogleID(ctx context.Context, id string) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE google_id = $1 AND is_active = true
    `

	var user domain.User
	err := ur.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by Google ID: %w", err)
	}

	return &user, nil
}

func (ur *userRepository) GetUserByYandexID(ctx context.Context, id string) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE yandex_id = $1 AND is_active = true
    `

	var user domain.User
	err := ur.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by Yandex ID: %w", err)
	}

	return &user, nil
}

func (ur *userRepository) GetUserByVkID(ctx context.Context, id string) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE vk_id = $1 AND is_active = true
    `

	var user domain.User
	err := ur.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by VK ID: %w", err)
	}

	return &user, nil
}

func (ur *userRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	query := `
        UPDATE users
        SET first_name = $1, last_name = $2, email = $3, photo = $4, roles = $5, locale = $6
        WHERE id = $7 AND is_active = true
    `

	_, err := ur.db.Exec(ctx, query,
		user.FirstName,
		user.LastName,
		user.Email,
		user.Photo,
		user.Roles,
		user.LocaleType,
		user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (ur *userRepository) CreateUser(ctx context.Context, user *domain.User) (int, error) {
	query := `
        INSERT INTO users (first_name, last_name, email, pass_hash, google_id, yandex_id, vk_id, photo, roles, locale)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id
    `

	var userID int
	err := ur.db.QueryRow(ctx, query,
		user.FirstName,
		user.LastName,
		user.Email,
		user.Password,
		user.GoogleID,
		user.YandexID,
		user.VkID,
		user.Photo,
		user.Roles,
		user.LocaleType,
	).Scan(&userID)

	if err != nil {
		return 0, fmt.Errorf("failed to create user: %w", err)
	}

	return userID, nil
}

func (ur *userRepository) ConfirmEmail(ctx context.Context, userID int) error {
	query := `
        UPDATE users
        SET email_confirmed = true
        WHERE id = $1
    `

	_, err := ur.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to confirm email: %w", err)
	}

	return nil
}
