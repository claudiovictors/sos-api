package middleware

import (
	"errors"
	"log"

	"github.com/claudiovictors/api-rest/utils"
	"github.com/gofiber/fiber/v3"
)

func ErrorHandler(logger *log.Logger) fiber.ErrorHandler {
	return func(c fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		message := utils.StatusMessage(code)

		var fiberErr *fiber.Error
		if errors.As(err, &fiberErr) {
			code = fiberErr.Code
			message = fiberErr.Message
		}
		if code >= fiber.StatusInternalServerError {
			logger.Printf("request_id=%s method=%s path=%s error=%v", c.Get("X-Request-ID"), c.Method(), c.Path(), err)
			return utils.Fail(c, code, "internal server error")
		}
		return utils.Fail(c, code, message)
	}
}

func PanicHandler(logger *log.Logger) func(fiber.Ctx, any) error {
	return func(c fiber.Ctx, recovered any) error {
		logger.Printf("request_id=%s panic=%v", c.Get("X-Request-ID"), recovered)
		return utils.Fail(c, fiber.StatusInternalServerError, "internal server error")
	}
}

func SecurityHeaders() fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Referrer-Policy", "no-referrer")
		return c.Next()
	}
}
