package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	//go run main.go --user=postgres --password=secret --host=localhost --port=5432 --dbname=mydb --migrations-path=./migrations
	var (
		user, password, host, port, dbname, migrationsPath string
	)

	// Параметры подключения к БД
	flag.StringVar(&user, "user", "", "PostgreSQL username")
	flag.StringVar(&password, "password", "", "PostgreSQL password")
	flag.StringVar(&host, "host", "localhost", "PostgreSQL host")
	flag.StringVar(&port, "port", "5432", "PostgreSQL port")
	flag.StringVar(&dbname, "dbname", "", "PostgreSQL database name")
	flag.StringVar(&migrationsPath, "migrations-path", "", "Path to migration files")
	flag.Parse()

	// Валидация параметров
	if user == "" || password == "" || host == "" || port == "" || dbname == "" {
		panic("Missing required database connection parameters")
	}
	if migrationsPath == "" {
		panic("Missing required --migrations-path argument")
	}
	// Формируем строку подключения
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		user, password, host, port, dbname,
	)

	//Создаем объект мигратора
	m, err := migrate.New("file:"+migrationsPath, dsn)
	if err != nil {
		panic(fmt.Sprintf("Migration init failed: %v", err))
	}
	defer m.Close() //Закрываем соединения с БД после миграции

	err = m.Up()

	if err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("No migrations to apply")
			return
		}
		panic(fmt.Sprintf("Migration failed: %v", err))
	}
	slog.Info("Migrations applied successfully")
}
