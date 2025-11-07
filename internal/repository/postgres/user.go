package postgres

import (
	"authorization_service/internal/domain"
	"authorization_service/internal/repository"
	"context"
	"errors"
	"fmt"

	"strings"

	"github.com/jackc/pgx/v5"
)

func (ur *userRepository) GetUserByID(ctx context.Context, id int) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed, pass_hash,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE id = $1 AND is_active = true
    `

	var user domain.User
	var passHash []byte
	err := ur.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&passHash,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrorUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	if len(passHash) > 0 {
		s := string(passHash)
		user.Password = &s
	}

	return &user, nil
}

func (ur *userRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed, pass_hash,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE email = $1 AND is_active = true
    `

	var user domain.User
	var passHash []byte
	err := ur.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&passHash,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrorUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	if len(passHash) > 0 {
		s := string(passHash)
		user.Password = &s
	}

	return &user, nil
}

func (ur *userRepository) GetUserByGoogleID(ctx context.Context, id string) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed, pass_hash,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE google_id = $1 AND is_active = true
    `

	var user domain.User
	var passHash []byte
	err := ur.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&passHash,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrorUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by Google ID: %w", err)
	}

	if len(passHash) > 0 {
		s := string(passHash)
		user.Password = &s
	}

	return &user, nil
}

func (ur *userRepository) GetUserByYandexID(ctx context.Context, id string) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed, pass_hash,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE yandex_id = $1 AND is_active = true
    `

	var user domain.User
	var passHash []byte
	err := ur.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&passHash,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrorUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by Yandex ID: %w", err)
	}

	if len(passHash) > 0 {
		s := string(passHash)
		user.Password = &s
	}

	return &user, nil
}

func (ur *userRepository) GetUserByVkID(ctx context.Context, id string) (*domain.User, error) {
	query := `
        SELECT id, first_name, last_name, email, email_confirmed, pass_hash,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
        WHERE vk_id = $1 AND is_active = true
    `

	var user domain.User
	var passHash []byte
	err := ur.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.EmailConfirmed,
		&passHash,
		&user.GoogleID,
		&user.YandexID,
		&user.VkID,
		&user.Photo,
		&user.Roles,
		&user.LocaleType,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrorUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by VK ID: %w", err)
	}

	if len(passHash) > 0 {
		s := string(passHash)
		user.Password = &s
	}

	return &user, nil
}

func (ur *userRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	query := `
        UPDATE users
        SET first_name = $1, last_name = $2, email = $3, photo = $4, roles = $5, locale = $6, pass_hash = $7
        WHERE id = $8 AND is_active = true
    `

	var passHash []byte
	if user.Password != nil {
		passHash = []byte(*user.Password)
	}

	_, err := ur.db.Exec(ctx, query,
		user.FirstName,
		user.LastName,
		user.Email,
		user.Photo,
		user.Roles,
		user.LocaleType,
		passHash,
		user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// SetOauthID sets the OAuth ID for a user based on the provider.
// Supported providers are "google", "yandex", and "vk".
func (ur *userRepository) SetOauthID(ctx context.Context, userID int, provider string, oauthID string) error {
	var query string
	switch provider {
	case "google":
		query = "UPDATE users SET google_id = $1 WHERE id = $2 AND is_active = true"
	case "yandex":
		query = "UPDATE users SET yandex_id = $1 WHERE id = $2 AND is_active = true"
	case "vk":
		query = "UPDATE users SET vk_id = $1 WHERE id = $2 AND is_active = true"
	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}

	_, err := ur.db.Exec(ctx, query, oauthID, userID)
	if err != nil {
		return fmt.Errorf("failed to set %s ID: %w", provider, err)
	}

	return nil
}

func (ur *userRepository) CreateUser(ctx context.Context, user *domain.User) (int, error) {
	query := `
        INSERT INTO users (first_name, last_name, email, pass_hash, google_id, yandex_id, vk_id, photo, email_confirmed)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
		user.EmailConfirmed,
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

func (ur *userRepository) UpdatePassword(ctx context.Context, userID int, passwordHash string) error {
	query := `
        UPDATE users
        SET pass_hash = $2
        WHERE id = $1 AND is_active = true
    `

	if _, err := ur.db.Exec(ctx, query, userID, []byte(passwordHash)); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

// ListUsers returns users matching filter with pagination and total count
func (ur *userRepository) ListUsers(ctx context.Context, filter repository.UserListFilter, page, limit int) ([]*domain.User, int, error) {
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	where := []string{"is_active = true"}
	args := []any{}

	// q filter across first_name, last_name, email
	if filter.Query != "" {
		args = append(args, "%"+filter.Query+"%")
		where = append(where, "(first_name ILIKE $"+fmt.Sprint(len(args))+" OR last_name ILIKE $"+fmt.Sprint(len(args))+" OR email ILIKE $"+fmt.Sprint(len(args))+")")
	}
	// role filter: value must be present in roles array
	if filter.Role != nil {
		args = append(args, *filter.Role)
		where = append(where, "$"+fmt.Sprint(len(args))+" = ANY(roles)")
	}
	if filter.EmailConfirmed != nil {
		args = append(args, *filter.EmailConfirmed)
		where = append(where, "email_confirmed = $"+fmt.Sprint(len(args)))
	}
	if filter.Locale != nil {
		args = append(args, *filter.Locale)
		where = append(where, "locale = $"+fmt.Sprint(len(args)))
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	// total count
	countQuery := `
        SELECT COUNT(*)
        FROM users
    ` + whereSQL

	var total int
	if err := ur.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// pagination
	offset := (page - 1) * limit
	argsWithPage := append([]any{}, args...)
	argsWithPage = append(argsWithPage, limit, offset)

	listQuery := `
        SELECT id, first_name, last_name, email, email_confirmed, pass_hash,
               google_id, yandex_id, vk_id, photo, roles, locale
        FROM users
    ` + whereSQL + `
        ORDER BY created_at DESC
        LIMIT $` + fmt.Sprint(len(args)+1) + ` OFFSET $` + fmt.Sprint(len(args)+2)

	rows, err := ur.db.Query(ctx, listQuery, argsWithPage...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	users := make([]*domain.User, 0)
	for rows.Next() {
		var u domain.User
		var passHash []byte
		if err := rows.Scan(
			&u.ID,
			&u.FirstName,
			&u.LastName,
			&u.Email,
			&u.EmailConfirmed,
			&passHash,
			&u.GoogleID,
			&u.YandexID,
			&u.VkID,
			&u.Photo,
			&u.Roles,
			&u.LocaleType,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan user row: %w", err)
		}
		if len(passHash) > 0 {
			s := string(passHash)
			u.Password = &s
		}
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows error: %w", err)
	}

	return users, total, nil
}
