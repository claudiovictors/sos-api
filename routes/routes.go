package routes

import (
	"database/sql"
	"log"

	"github.com/claudiovictors/api-rest/config"
	"github.com/claudiovictors/api-rest/controllers"
	"github.com/claudiovictors/api-rest/middleware"
	"github.com/claudiovictors/api-rest/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

func Register(
	app *fiber.App,
	cfg config.Config,
	db *sql.DB,
	auth *controllers.AuthController,
	users *controllers.UserController,
	appLogger *log.Logger,
) {
	app.Use(requestid.New())
	app.Use(middleware.SecurityHeaders())
	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
		PanicHandler:     middleware.PanicHandler(appLogger),
	}))
	app.Use(logger.New(logger.Config{
		Format: "${time} ${status} ${method} ${path} ${latency} rid=${reqHeader:X-Request-ID}\n",
	}))

	api := app.Group("/api/v1")

	api.Get("/health", func(c fiber.Ctx) error {
		return utils.OK(c, fiber.StatusOK, fiber.Map{"status": "ok"})
	})
	api.Get("/health/ready", func(c fiber.Ctx) error {
		if err := config.Ping(c.Context(), db); err != nil {
			return utils.Fail(c, fiber.StatusServiceUnavailable, "database unavailable")
		}
		return utils.OK(c, fiber.StatusOK, fiber.Map{"status": "ready"})
	})

	authLimiter := limiter.New(limiter.Config{
		Max:        cfg.RateLimitMax,
		Expiration: cfg.RateLimitWindow,
		KeyGenerator: func(c fiber.Ctx) string {
			return c.IP() + "|" + c.Path()
		},
		LimitReached: func(c fiber.Ctx) error {
			return utils.Fail(c, fiber.StatusTooManyRequests, "too many requests")
		},
	})

	authRoutes := api.Group("/auth")
	authRoutes.Post("/register", authLimiter, auth.Store)
	authRoutes.Post("/login", authLimiter, auth.Login)
	authRoutes.Post("/refresh", authLimiter, auth.Refresh)

	authenticate := middleware.Authenticate(db, []byte(cfg.JWTSecret), cfg.QueryTimeout)
	authRoutes.Post("/logout", authenticate, auth.Logout)
	authRoutes.Get("/me", authenticate, auth.Me)

	api.Get("/users", authenticate, middleware.RequireAdmin(), users.Index)
	userRoutes := api.Group("/users")
	userRoutes.Use(authenticate)
	userRoutes.Get("/:id", users.Show)
	userRoutes.Patch("/:id", users.Update)
	userRoutes.Delete("/:id", users.Delete)
}
