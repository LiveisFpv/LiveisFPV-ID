package postgresql

import (
	"authorization_service/internal/domain/models"
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

type repo struct {
	*Queries
	pool *pgxpool.Pool
	log  *slog.Logger
}

func NewRepository(
	pgxpool *pgxpool.Pool,
	log *slog.Logger,
) Repository {
	return &repo{
		Queries: New(pgxpool),
		pool:    pgxpool,
		log:     log,
	}
}

type Repository interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (int64, error)
	User(ctx context.Context, email string) (models.User, error)
	App(ctx context.Context, id int) (models.App, error)
	Stop()
}

func NewStorage(ctx context.Context, dsn string, log *slog.Logger) (Repository, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Проверяем подключение
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	return NewRepository(pool, log), nil
}

func (r *repo) Stop() {
	r.Queries.Stop()
}
