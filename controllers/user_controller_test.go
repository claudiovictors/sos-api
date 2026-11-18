package controllers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/claudiovictors/api-rest/middleware"
	"github.com/claudiovictors/api-rest/models"
	"github.com/claudiovictors/api-rest/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
)

func testUser(role string, id int64) models.User {
	return models.User{
		ID: id, Name: "Ana", Email: "ana@example.com", Role: role, IsActive: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
}

func TestUsersIndexRequiresAdmin(t *testing.T) {
	db, mock := newTestDB(t)
	users := newTestUsers(t, db)
	app := fiber.New()
	auth := middleware.Authenticate(db, []byte(testSecret), time.Second)
	app.Get("/users", auth, middleware.RequireAdmin(), users.Index)

	regular := testUser(models.RoleUser, 1)
	expectAuthUser(mock, regular)
	token, _, err := utils.NewAccessToken([]byte(testSecret), regular, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, body := request(t, app, http.MethodGet, "/users?limit=999", "", token)
	if status != fiber.StatusForbidden {
		t.Fatalf("regular user should get 403, got %d: %s", status, body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUsersIndexListsActiveUsers(t *testing.T) {
	db, mock := newTestDB(t)
	users := newTestUsers(t, db)
	app := fiber.New()
	auth := middleware.Authenticate(db, []byte(testSecret), time.Second)
	app.Get("/users", auth, middleware.RequireAdmin(), users.Index)

	admin := testUser(models.RoleAdmin, 1)
	expectAuthUser(mock, admin)
	mock.ExpectQuery("FROM users WHERE is_active = TRUE ORDER BY id").
		WithArgs(2, 0).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "email", "role", "created_at"}).
			AddRow(2, "Bruno", "bruno@example.com", models.RoleUser, time.Now()))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	token, _, err := utils.NewAccessToken([]byte(testSecret), admin, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, body := request(t, app, http.MethodGet, "/users?limit=2", "", token)
	if status != fiber.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	env := decodeEnvelope(t, body)
	if !strings.Contains(string(env.Data), "bruno@example.com") ||
		!strings.Contains(string(env.Meta), `"total":1`) {
		t.Fatalf("unexpected response: %s", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUsersIndexRejectsInvalidPagination(t *testing.T) {
	db, mock := newTestDB(t)
	users := newTestUsers(t, db)
	app := fiber.New()
	auth := middleware.Authenticate(db, []byte(testSecret), time.Second)
	app.Get("/users", auth, middleware.RequireAdmin(), users.Index)

	admin := testUser(models.RoleAdmin, 1)
	expectAuthUser(mock, admin)
	token, _, err := utils.NewAccessToken([]byte(testSecret), admin, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, body := request(t, app, http.MethodGet, "/users?offset=-1", "", token)
	if status != fiber.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUsersShowOwnAndForeignAccounts(t *testing.T) {
	db, mock := newTestDB(t)
	users := newTestUsers(t, db)
	app := fiber.New()
	auth := middleware.Authenticate(db, []byte(testSecret), time.Second)
	app.Get("/users/:id", auth, users.Show)

	current := testUser(models.RoleUser, 1)
	token, _, err := utils.NewAccessToken([]byte(testSecret), current, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	expectAuthUser(mock, current)
	status, body := request(t, app, http.MethodGet, "/users/2", "", token)
	if status != fiber.StatusNotFound {
		t.Fatalf("foreign account should be hidden, got %d: %s", status, body)
	}

	expectAuthUser(mock, current)
	mock.ExpectQuery("FROM users WHERE id = \\$1 AND is_active = TRUE").
		WithArgs(int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "email", "role", "created_at", "updated_at"}).
			AddRow(1, current.Name, current.Email, current.Role, current.CreatedAt, current.UpdatedAt))
	status, body = request(t, app, http.MethodGet, "/users/1", "", token)
	if status != fiber.StatusOK || strings.Contains(body, "password") {
		t.Fatalf("status=%d body=%s", status, body)
	}

	expectAuthUser(mock, current)
	status, body = request(t, app, http.MethodGet, "/users/abc", "", token)
	if status != fiber.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUsersUpdateSelfAndForeignAccounts(t *testing.T) {
	db, mock := newTestDB(t)
	users := newTestUsers(t, db)
	app := fiber.New()
	auth := middleware.Authenticate(db, []byte(testSecret), time.Second)
	app.Patch("/users/:id", auth, users.Update)

	current := testUser(models.RoleUser, 1)
	token, _, err := utils.NewAccessToken([]byte(testSecret), current, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	expectAuthUser(mock, current)
	status, body := request(t, app, http.MethodPatch, "/users/2", `{"name":"Other"}`, token)
	if status != fiber.StatusForbidden {
		t.Fatalf("foreign update should be forbidden, got %d: %s", status, body)
	}

	expectAuthUser(mock, current)
	status, body = request(t, app, http.MethodPatch, "/users/1", `{}`, token)
	if status != fiber.StatusBadRequest {
		t.Fatalf("empty update should be rejected, got %d: %s", status, body)
	}

	expectAuthUser(mock, current)
	status, body = request(t, app, http.MethodPatch, "/users/1", `{"password":"short"}`, token)
	if status != fiber.StatusBadRequest {
		t.Fatalf("short password should be rejected, got %d: %s", status, body)
	}

	expectAuthUser(mock, current)
	mock.ExpectQuery("UPDATE users SET").
		WithArgs("Ana Silva", int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "email", "role", "created_at", "updated_at"}).
			AddRow(1, "Ana Silva", current.Email, current.Role, current.CreatedAt, current.UpdatedAt))
	status, body = request(t, app, http.MethodPatch, "/users/1", `{"name":" Ana Silva "}`, token)
	if status != fiber.StatusOK || !strings.Contains(body, "Ana Silva") {
		t.Fatalf("status=%d body=%s", status, body)
	}

	expectAuthUser(mock, current)
	mock.ExpectQuery("UPDATE users SET").
		WillReturnError(&pgconn.PgError{Code: "23505"})
	status, body = request(t, app, http.MethodPatch, "/users/1", `{"email":"taken@example.com"}`, token)
	if status != fiber.StatusConflict {
		t.Fatalf("duplicate email should conflict, got %d: %s", status, body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUsersDeleteDeactivatesAndRevokesTokens(t *testing.T) {
	db, mock := newTestDB(t)
	users := newTestUsers(t, db)
	app := fiber.New()
	auth := middleware.Authenticate(db, []byte(testSecret), time.Second)
	app.Delete("/users/:id", auth, users.Delete)

	current := testUser(models.RoleUser, 1)
	token, _, err := utils.NewAccessToken([]byte(testSecret), current, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	expectAuthUser(mock, current)
	status, body := request(t, app, http.MethodDelete, "/users/2", "", token)
	if status != fiber.StatusForbidden {
		t.Fatalf("foreign deletion should be forbidden, got %d: %s", status, body)
	}

	expectAuthUser(mock, current)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE users SET is_active = FALSE").
		WithArgs(int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE auth_refresh_tokens SET revoked_at").
		WithArgs(int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	status, _ = request(t, app, http.MethodDelete, "/users/1", "", token)
	if status != fiber.StatusNoContent {
		t.Fatalf("status=%d", status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestErrorEnvelopeShape(t *testing.T) {
	env := decodeEnvelope(t, `{"success":false,"error":"unauthorized"}`)
	if env.Success || env.Error != "unauthorized" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	var data map[string]any
	if err := json.Unmarshal(env.Data, &data); err == nil {
		t.Fatal("empty data should not decode into an object")
	}
}
