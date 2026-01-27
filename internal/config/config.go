package config

import (
	"authorization_service/internal/types"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	PostgresConfig      PostgresConfig
	RedisConfig         RedisConfig
	HttpServerConfig    HTTPServerConfig
	GRPCConfig          gRPCConfig
	JWTConfig           JWTConfig
	CookieConfig        CookieConfig
	OauthGoogleConfig   OauthGoogleConfig
	OauthYandexConfig   OauthYandexConfig
	EmailConfig         EmailConfig
	Domain              string   `env:"DOMAIN" env-default:"localhost"`
	PublicURL           string   `env:"PUBLIC_URL"`
	AllowedCORSOrigins  []string `env:"ALLOWED_CORS_ORIGINS" env-separator:","`
	AllowedRedirectURLs []string `env:"ALLOWED_REDIRECT_URLS" env-separator:","`
	DefaultAdminEmails  []string `env:"DEFAULT_ADMIN_EMAILS" env-separator:","`
	SwaggerEnabled      bool     `env:"SWAGGER_ENABLED" env-default:"true"`
	SwaggerUser         string   `env:"SWAGGER_USER"`
	SwaggerPassword     string   `env:"SWAGGER_PASSWORD"`
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

type EmailConfig struct {
	SMTPHost     string `env:"SMTP_HOST" env-required:"true"`
	SMTPPort     string `env:"SMTP_PORT" env-required:"true"`
	SMTPUsername string `env:"SMTP_USERNAME" env-required:"true"`
	SMTPPassword string `env:"SMTP_PASSWORD" env-required:"true"`
	FromEmail    string `env:"FROM_EMAIL" env-required:"true"`
	JwtSecret    string `env:"SMTP_JWT_SECRET" env-required:"true"`
}

type JWTConfig struct {
	AccessTokenTTL  types.CustomDuration `env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL types.CustomDuration `env:"REFRESH_TOKEN_TTL" env-default:"7d"`
	SecretKey       string               `env:"JWT_SECRET_KEY" env-required:"true"`
}

type CookieConfig struct {
	Domain   string               `env:"DOMAIN" env-default:"localhost"`
	Path     string               `env:"COOKIE_PATH" env-default:"/"`
	Secure   bool                 `env:"COOKIE_SECURE" env-default:"false"`
	HttpOnly bool                 `env:"COOKIE_HTTP_ONLY" env-default:"true"`
	MaxAge   types.CustomDuration `env:"COOKIE_MAX_AGE" env-default:"7d"`
	SameSite string               `env:"COOKIE_SAME_SITE" env-default:"Lax"`
}

type gRPCConfig struct {
	Port    string               `env:"GRPC_PORT" env-default:"50051"`
	Timeout types.CustomDuration `env:"GRPC_TIMEOUT" env-default:"24h"`
}

type HTTPServerConfig struct {
	Port string `env:"HTTP_PORT" env-default:"8080"`
}

type OauthGoogleConfig struct {
	ClientID     string `env:"GOOGLE_CLIENT_ID" env-required:"true"`
	ClientSecret string `env:"GOOGLE_CLIENT_SECRET" env-required:"true"`
}

type OauthYandexConfig struct {
	ClientID     string `env:"YANDEX_CLIENT_ID" env-required:"true"`
	ClientSecret string `env:"YANDEX_CLIENT_SECRET" env-required:"true"`
}

func MustLoadConfig() (*Config, error) {
	var config Config
	if err := cleanenv.ReadEnv(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
