package storage

import (
	postgresql "authorization_service/internal/storage/postgreSQL"
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

type repo struct {
	*postgresql.Queries
	pool *pgxpool.Pool
	log  *slog.Logger
}

func NewRepository(
	pgxpool *pgxpool.Pool,
	log *slog.Logger,
) Repository {
	return &repo{
		Queries: postgresql.New(pgxpool),
		pool:    pgxpool,
		log:     log,
	}
}

type Repository interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (int64, error)
}
