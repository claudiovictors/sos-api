package config

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func Connect() (*sql.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errors.New("DATABASE_URL is required")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
