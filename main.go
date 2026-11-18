package main

import (
	"errors"
	"log"
	"os"

	"github.com/claudiovictors/api-rest/config"
	"github.com/claudiovictors/api-rest/controllers"
	"github.com/gofiber/fiber/v3"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("load .env: %v", err)
	}

	db, err := config.Connect()
	if err != nil {
		log.Fatalf("connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	auth, err := controllers.NewAuthController(db, os.Getenv("AUTH_SECRET"))
	if err != nil {
		log.Fatalf("configure authentication: %v", err)
	}

	app := fiber.New()

	app.Post("/auth/register", auth.Store)
	app.Post("/auth/login", auth.Login)
	app.Post("/auth/refresh", auth.Refresh)
	app.Post("/auth/logout", auth.Logout)
	app.Get("/auth/me", auth.Me)

	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}
