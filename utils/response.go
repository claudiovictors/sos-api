package utils

import (
	"net/http"

	"github.com/gofiber/fiber/v3"
)

type Envelope struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	Meta    any    `json:"meta,omitempty"`
}

func OK(c fiber.Ctx, status int, data any) error {
	return c.Status(status).JSON(Envelope{Success: true, Data: data})
}

func OKWithMeta(c fiber.Ctx, status int, data any, meta any) error {
	return c.Status(status).JSON(Envelope{Success: true, Data: data, Meta: meta})
}

func Fail(c fiber.Ctx, status int, message string) error {
	return c.Status(status).JSON(Envelope{Success: false, Error: message})
}

func NoStore(c fiber.Ctx) {
	c.Set("Cache-Control", "no-store")
}

func StatusMessage(status int) string {
	if message := http.StatusText(status); message != "" {
		return message
	}
	return "unexpected error"
}
