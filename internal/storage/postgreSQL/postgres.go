package postgresql

import "github.com/jackc/pgx/v5/pgxpool"

type Queries struct {
	pool *pgxpool.Pool
}

func New(pgxpool *pgxpool.Pool) *Queries {
	return &Queries{pool: pgxpool}
}
