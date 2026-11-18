package config

import (
	"strings"
	"testing"
	"time"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/schools?sslmode=disable")
	t.Setenv("AUTH_SECRET", strings.Repeat("s", 32))
}

func TestLoadRequiresDatabaseAndSecret(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("AUTH_SECRET", "")
	if _, err := Load(); err == nil {
		t.Fatal("missing DATABASE_URL/AUTH_SECRET must fail")
	}

	setRequiredEnv(t)
	t.Setenv("AUTH_SECRET", "too-short")
	if _, err := Load(); err == nil {
		t.Fatal("short AUTH_SECRET must fail")
	}
}

func TestLoadDefaults(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Addr != ":8080" || cfg.QueryTimeout != 5*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.MaxOpenConns != 10 || cfg.MaxIdleConns != 5 || cfg.ConnMaxLifetime != 30*time.Minute {
		t.Fatalf("unexpected pool defaults: %+v", cfg)
	}
	if cfg.RateLimitMax != 10 || cfg.RateLimitWindow != time.Minute {
		t.Fatalf("unexpected rate limit defaults: %+v", cfg)
	}
}

func TestLoadRejectsInvalidPool(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DB_MAX_OPEN_CONNS", "0")
	if _, err := Load(); err == nil {
		t.Fatal("invalid pool configuration must fail")
	}
}
