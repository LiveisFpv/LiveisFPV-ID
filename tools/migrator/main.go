package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	// Параметры подключения к БД
	var (
		user, password, host, port, dbname, migrationsPath string
	)

	flag.StringVar(&user, "user", "", "PostgreSQL username")
	flag.StringVar(&password, "password", "", "PostgreSQL password")
	flag.StringVar(&host, "host", "localhost", "PostgreSQL host")
	flag.StringVar(&port, "port", "5432", "PostgreSQL port")
	flag.StringVar(&dbname, "dbname", "", "PostgreSQL database name")
	flag.StringVar(&migrationsPath, "migrations-path", "", "Path to migration files")
	flag.Parse()

	// Проверка обязательных параметров
	if user == "" || password == "" || host == "" || port == "" || dbname == "" {
		log.Fatalf("Missing required database connection parameters")
	}
	if migrationsPath == "" {
		log.Fatalf("Missing required --migrations-path argument")
	}

	// Формируем строку подключения
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		user, password, host, port, dbname,
	)

	// Создаем объект мигратора
	m, err := migrate.New("file:"+migrationsPath, dsn)
	if err != nil {
		log.Fatalf("Failed to initialize migrator: %v", err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			log.Printf("Source close error: %v", srcErr)
		}
		if dbErr != nil {
			log.Printf("Database close error: %v", dbErr)
		}
	}()

	// Проверяем состояние базы данных
	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		log.Fatalf("Failed to get migration version: %v", err)
	}
	if dirty {
		log.Printf("Database is in a dirty state at version %d. Forcing clean state...", version)
		if forceErr := m.Force(int(version)); forceErr != nil {
			log.Fatalf("Failed to force clean migration state: %v", forceErr)
		}
		log.Println("Dirty state resolved. Proceeding with migrations...")
	}

	// Применяем миграции
	if err := m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			log.Println("No new migrations to apply")
		} else {
			log.Printf("Migration failed: %v", err)

			// Откат миграции для предотвращения dirty database
			if rollbackErr := m.Down(); rollbackErr != nil {
				log.Printf("Rollback failed: %v", rollbackErr)
			} else {
				log.Println("Rollback completed successfully")
			}

			// Принудительный сброс состояния миграции
			if forceErr := m.Force(-1); forceErr != nil {
				log.Fatalf("Failed to reset migration state: %v", forceErr)
			}
			log.Fatalf("Migration process terminated")
		}
	} else {
		log.Println("Migrations applied successfully")
	}
}
