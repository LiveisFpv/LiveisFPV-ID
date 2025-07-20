package storage

import (
	"authorization_service/internal/config"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func PostgresConnect(ctx context.Context, cfg config.PostgresConfig) (pool *pgxpool.Pool, err error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	parseConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		err = fmt.Errorf("failed to parse PostgreSQL connection string: %v", err)
		return nil, err
	}

	parseConfig.MaxConns = 10
	parseConfig.MaxConnIdleTime = 30 * time.Minute

	pool, err = pgxpool.NewWithConfig(ctx, parseConfig)

	if err != nil {
		err = fmt.Errorf("failed to connect to PostgreSQL: %v", err)
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		err = fmt.Errorf("failed to ping PostgreSQL: %v", err)
		pool.Close()
		return nil, err
	}

	return pool, nil
}
