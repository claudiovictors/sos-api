package controllers

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/claudiovictors/api-rest/models"
	"github.com/gofiber/fiber/v3"
)

const testSecret = "0123456789abcdef0123456789abcdef"

type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error"`
	Meta    json.RawMessage `json:"meta"`
}

func newTestDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

func newTestAuth(t *testing.T, db *sql.DB) *AuthController {
	t.Helper()
	auth, err := NewAuthController(db, testSecret, time.Second)
	if err != nil {
		t.Fatalf("NewAuthController: %v", err)
	}
	return auth
}

func newTestUsers(t *testing.T, db *sql.DB) *UserController {
	t.Helper()
	users, err := NewUserController(db, time.Second)
	if err != nil {
		t.Fatalf("NewUserController: %v", err)
	}
	return users
}

func expectAuthUser(mock sqlmock.Sqlmock, user models.User) {
	mock.ExpectQuery("SELECT id, name, email, role, is_active, created_at, updated_at").
		WithArgs(user.ID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "email", "role", "is_active", "created_at", "updated_at",
		}).AddRow(user.ID, user.Name, user.Email, user.Role, user.IsActive, user.CreatedAt, user.UpdatedAt))
}

func request(t *testing.T, app *fiber.App, method, path, body, token string) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(responseBody)
}

func decodeEnvelope(t *testing.T, body string) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("invalid response JSON %q: %v", body, err)
	}
	return env
}
