package postgresql

import (
	"authorization_service/internal/domain/models"
	"authorization_service/internal/storage"
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (q *Queries) App(ctx context.Context, id int) (models.App, error) {
	const op = "storage.postgresql.App"

	sql_statement := "SELECT id, name, secret FROM apps WHERE id = $1"
	row := q.pool.QueryRow(ctx, sql_statement, id)

	var app models.App
	err := row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}
