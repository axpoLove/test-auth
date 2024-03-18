package config

import (
	"fmt"
	"time"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Server Server
	Auth   Auth
	Mongo  Mongo
}

func NewConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load .env file: %w", err)
	}
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to load env variables: %w", err)
	}
	return &cfg, nil
}

type Server struct {
	Port              int           `envconfig:"SERVER_PORT" default:"8080"`
	ReadHeaderTimeout time.Duration `envconfig:"SERVER_READ_HEADER_TIMEOUT" default:"15s"`
}

type Auth struct {
	AccessTokenTTL     time.Duration `envconfig:"ACCESS_TOKEN_TTL" default:"15m"`
	RefreshTokenTTL    time.Duration `envconfig:"REFRESH_TOKEN_TTL" default:"720h"`
	SecretKey          string        `envconfig:"SECRET_KEY" required:"true"`
	RefreshTokenLength int           `envconfig:"REFRESH_TOKEN_LENGTH" default:"32"`
}

type Mongo struct {
	Host                   string `envconfig:"MONGO_HOST" required:"true"`
	Port                   int    `envconfig:"MONGO_PORT" required:"true"`
	Database               string `envconfig:"MONGO_DATABASE" default:"auth"`
	RefreshTokenCollection string `envconfig:"MONGO_REFRESH_TOKEN_COLLECTION" default:"refreshTokens"`
}

func (m Mongo) URI() string {
	return fmt.Sprintf("mongodb://%s:%d", m.Host, m.Port)
}
