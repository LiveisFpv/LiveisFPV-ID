package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Dsn      string `env-required:"true"`
	GRPC     GRPCConfig
	TokenTTL time.Duration `env-default:"1h"`
}
type GRPCConfig struct {
	Port    int
	Timeout time.Duration
}

func MustLoad() *Config {
	cfg, err := fetchFromenv()
	if err != nil {
		panic(fmt.Sprintf("config env bad %s", err))
	}
	return cfg
}
func fetchFromenv() (*Config, error) {
	envVars := map[string]string{
		"DB_HOST":      os.Getenv("DB_HOST"),
		"DB_PORT":      os.Getenv("DB_PORT"),
		"DB_USER":      os.Getenv("DB_USER"),
		"DB_PASSWORD":  os.Getenv("DB_PASSWORD"),
		"DB_NAME":      os.Getenv("DB_NAME"),
		"GRPC_PORT":    os.Getenv("GRPC_PORT"),
		"GRPC_TIMEOUT": os.Getenv("GRPC_TIMEOUT"),
	}

	// Проверяем, что все переменные заданы
	for key, value := range envVars {
		if value == "" {
			return nil, fmt.Errorf("Error: %s not set", key)
		}
	}

	// Convert environment
	grpcPort, err := strconv.Atoi(envVars["GRPC_PORT"])
	if err != nil {
		return nil, fmt.Errorf("Bad GRPC_PORT: %v", err)
	}

	grpcTimeout, err := time.ParseDuration(envVars["GRPC_TIMEOUT"])
	if err != nil {
		return nil, fmt.Errorf("Bad GRPC_TIMEOUT: %v", err)
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		envVars["DB_USER"],
		envVars["DB_PASSWORD"],
		envVars["DB_HOST"],
		envVars["DB_PORT"],
		envVars["DB_NAME"],
	)
	// Заполняем конфиг
	cfg := &Config{
		Dsn: dsn,
		GRPC: GRPCConfig{
			Port:    grpcPort,
			Timeout: grpcTimeout,
		},
	}
	return cfg, nil
}
