package postgresql

import (
	"authorization_service/internal/domain/models"
	"authorization_service/internal/storage"
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (q *Queries) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.postgreSQL.SaveUser"
	sql_context := "INSERT INTO users(email, pass_hash) VALUES($1, $2) Returning id"
	row := q.pool.QueryRow(ctx, sql_context, email, passHash)
	var id int64
	err := row.Scan(id)

	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (q *Queries) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgreSQL.User"
	sql_context := "SELECT id, email, pass_hash FROM users WHERE email = $1"

	row := q.pool.QueryRow(ctx, sql_context, email)

	var user models.User
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.PassHash,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return user, nil
}
