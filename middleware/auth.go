package middleware

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/claudiovictors/api-rest/models"
	"github.com/claudiovictors/api-rest/utils"
	"github.com/gofiber/fiber/v3"
)

const userContextKey = "auth.user"

func Authenticate(db *sql.DB, secret []byte, timeout time.Duration) fiber.Handler {
	return func(c fiber.Ctx) error {
		tokenString, err := utils.BearerToken(c.Get("Authorization"))
		if err != nil {
			return utils.Fail(c, fiber.StatusUnauthorized, "unauthorized")
		}
		claims, err := utils.ParseAccessToken(tokenString, secret)
		if err != nil {
			return utils.Fail(c, fiber.StatusUnauthorized, "unauthorized")
		}
		userID, err := strconv.ParseInt(claims.Subject, 10, 64)
		if err != nil || userID < 1 {
			return utils.Fail(c, fiber.StatusUnauthorized, "unauthorized")
		}

		ctx, cancel := context.WithTimeout(c.Context(), timeout)
		defer cancel()

		var user models.User
		err = db.QueryRowContext(ctx,
			`SELECT id, name, email, role, is_active, created_at, updated_at
			 FROM users WHERE id = $1`,
			userID,
		).Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !user.IsActive) {
			return utils.Fail(c, fiber.StatusUnauthorized, "unauthorized")
		}
		if err != nil {
			return utils.Fail(c, fiber.StatusInternalServerError, "could not load account")
		}

		fiber.Locals(c, userContextKey, &user)
		return c.Next()
	}
}

func CurrentUser(c fiber.Ctx) (models.User, bool) {
	user := fiber.Locals[*models.User](c, userContextKey)
	if user == nil {
		return models.User{}, false
	}
	return *user, true
}

func RequireAdmin() fiber.Handler {
	return func(c fiber.Ctx) error {
		user, ok := CurrentUser(c)
		if !ok || !user.IsAdmin() {
			return utils.Fail(c, fiber.StatusForbidden, "administrator access required")
		}
		return c.Next()
	}
}
