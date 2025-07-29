package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	PostgresConfig    PostgresConfig
	RedisConfig       RedisConfig
	HttpServerConfig  HTTPServerConfig
	JWTConfig         JWTConfig
	OauthGoogleConfig OauthGoogleConfig
}

type PostgresConfig struct {
	Host     string `env:"DB_HOST" env-required:"true"`
	Port     int    `env:"DB_PORT" env-required:"true"`
	User     string `env:"DB_USER" env-required:"true"`
	Password string `env:"DB_PASSWORD" env-required:"true"`
	DBName   string `env:"DB_NAME" env-required:"true"`
	SSLMode  string `env:"DB_SSL" env-default:"disable"`
}

type RedisConfig struct {
	Host     string `env:"REDIS_HOST" env-required:"true"`
	Port     string `env:"REDIS_PORT" env-required:"true"`
	Password string `env:"REDIS_PASSWORD" env-required:"true"`
	DB       int    `env:"REDIS_DB" env-default:"0"`
}

type MinioConfig struct {
	RootUser     string `env:"MINIO_ROOT_USER" env-required:"true"`
	RootPassword string `env:"MINIO_ROOT_PASSWORD" env-required:"true"`
	Endpoint     string `env:"MINIO_ENDPOINT" env-required:"true"`
	AccessKey    string `env:"MINIO_ACCESS_KEY" env-required:"true"`
	SecretKey    string `env:"MINIO_SECRET_KEY" env-required:"true"`
	UseSSL       bool   `env:"MINIO_USE_SSL" env-default:"false"`
	BucketName   string `env:"MINIO_BUCKET_NAME" env-required:"true"`
}

type JWTConfig struct {
	AccessTokenTTL  time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL" env-default:"7d"`
	SecretKey       string        `env:"SECRET_KEY" env-required:"true"`
}

type EmailConfig struct {
	SMTPHost     string `env:"SMTP_HOST" env-required:"true"`
	SMTPPort     string `env:"SMTP_PORT" env-required:"true"`
	SMTPUsername string `env:"SMTP_USERNAME" env-required:"true"`
	SMTPPassword string `env:"SMTP_PASSWORD" env-required:"true"`
	FromEmail    string `env:"FROM_EMAIL" env-required:"true"`
}

type HTTPServerConfig struct {
	Port int `env:"HTTP_PORT" env-default:"8080"`
}

type OauthGoogleConfig struct {
	ClientID     string `env:"GOOGLE_CLIENT_ID" env-required:"true"`
	ClientSecret string `env:"GOOGLE_CLIENT_SECRET" env-required:"true"`
}

func MustLoadConfig() (*Config, error) {
	var config Config
	if err := cleanenv.ReadEnv(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
