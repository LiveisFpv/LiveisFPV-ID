package postgresql

import (
	"context"
	"fmt"
)

func (q *Queries) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.postgreSQL.SaveUser"
	sql := "INSERT INTO users(email, pass_hash) VALUES($1, $2)"
	err := q.pool.QueryRow(ctx, sql, email, passHash)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

}
