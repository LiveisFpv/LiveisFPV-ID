package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env      string        `yaml:"env" env-default:"local"`
	Dsn      string        `yaml:"dsn" env-required:"true"`
	GRPC     GRPCConfig    `yaml:"grpc"`
	TokenTTL time.Duration `yaml:"token_ttl" env-default:"1h"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}

func MustLoad() *Config {
	configPath := fetchConfigPath()
	cfg, err := fetchFromenv()
	if err == nil {
		return cfg
	}
	if configPath == "" {
		panic("config and env is empty")
	}

	// check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	if err := cleanenv.ReadConfig(configPath, cfg); err != nil {
		panic("config path is empty: " + err.Error())
	}

	return cfg
}

// fetchConfigPath fetches config path from command line flag or environment variable.
// Priority: flag > env > default.
// Default value is empty string.
func fetchConfigPath() string {
	var res string

	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}

	return res
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
		Env: "dev",
		Dsn: dsn,
		GRPC: GRPCConfig{
			Port:    grpcPort,
			Timeout: grpcTimeout,
		},
	}
	return cfg, nil
}
