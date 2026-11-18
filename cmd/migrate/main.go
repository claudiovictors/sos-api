package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/claudiovictors/api-rest/config"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("load .env: %v", err)
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}
	db, err := config.Connect(cfg)
	if err != nil {
		log.Fatalf("connect to PostgreSQL: %v", err)
	}
	defer func() { _ = db.Close() }()

	dir := os.Getenv("MIGRATIONS_DIR")
	if dir == "" {
		dir = "migrations"
	}
	if err := migrate(context.Background(), db, dir); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Println("migrations are up to date")
}

func migrate(ctx context.Context, db *sql.DB, dir string) error {
	_, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)

	for _, file := range files {
		version := strings.TrimSuffix(file, ".sql")
		var applied bool
		if err := db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`,
			version,
		).Scan(&applied); err != nil {
			return err
		}
		if applied {
			log.Printf("skip %s (already applied)", file)
			continue
		}

		content, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return err
		}

		migrateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		tx, err := db.BeginTx(migrateCtx, nil)
		if err != nil {
			cancel()
			return err
		}
		if _, err := tx.ExecContext(migrateCtx, string(content)); err != nil {
			_ = tx.Rollback()
			cancel()
			return err
		}
		if _, err := tx.ExecContext(migrateCtx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback()
			cancel()
			return err
		}
		if err := tx.Commit(); err != nil {
			cancel()
			return err
		}
		cancel()
		log.Printf("applied %s", file)
	}
	return nil
}
