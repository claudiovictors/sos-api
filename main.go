package main

import (
	"errors"
	"log"
	"os"

	"github.com/claudiovictors/api-rest/config"
	"github.com/claudiovictors/api-rest/controllers"
	"github.com/claudiovictors/api-rest/middleware"
	"github.com/claudiovictors/api-rest/routes"
	"github.com/gofiber/fiber/v3"
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

	appLogger := log.New(os.Stdout, "schools-api ", log.LstdFlags|log.LUTC)
	auth, err := controllers.NewAuthController(db, cfg.JWTSecret, cfg.QueryTimeout)
	if err != nil {
		log.Fatalf("configure authentication: %v", err)
	}
	users, err := controllers.NewUserController(db, cfg.QueryTimeout)
	if err != nil {
		log.Fatalf("configure users: %v", err)
	}

	app := fiber.New(fiber.Config{ErrorHandler: middleware.ErrorHandler(appLogger)})
	routes.Register(app, cfg, db, auth, users, appLogger)

	log.Printf("listening on %s", cfg.Addr)
	if err := app.Listen(cfg.Addr); err != nil {
		log.Fatal(err)
	}
}
