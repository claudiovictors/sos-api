package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

const minSecretLength = 32

type Config struct {
	DatabaseURL     string
	JWTSecret       string
	Addr            string
	QueryTimeout    time.Duration
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	RateLimitMax    int
	RateLimitWindow time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		JWTSecret:       os.Getenv("AUTH_SECRET"),
		Addr:            envString("ADDR", ":8080"),
		QueryTimeout:    envDuration("DB_QUERY_TIMEOUT", 5*time.Second),
		MaxOpenConns:    envInt("DB_MAX_OPEN_CONNS", 10),
		MaxIdleConns:    envInt("DB_MAX_IDLE_CONNS", 5),
		ConnMaxLifetime: envDuration("DB_CONN_MAX_LIFETIME", 30*time.Minute),
		RateLimitMax:    envInt("RATE_LIMIT_MAX", 10),
		RateLimitWindow: envDuration("RATE_LIMIT_WINDOW", time.Minute),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if len(cfg.JWTSecret) < minSecretLength {
		return Config{}, errors.New("AUTH_SECRET must contain at least 32 characters")
	}
	if cfg.QueryTimeout <= 0 || cfg.RateLimitWindow <= 0 || cfg.RateLimitMax <= 0 {
		return Config{}, errors.New("timeouts and rate limits must be positive")
	}
	if cfg.MaxOpenConns < 1 || cfg.MaxIdleConns < 0 || cfg.MaxIdleConns > cfg.MaxOpenConns {
		return Config{}, errors.New("invalid database pool configuration")
	}
	return cfg, nil
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
