package middleware

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/claudiovictors/api-rest/models"
	"github.com/claudiovictors/api-rest/utils"
	"github.com/gofiber/fiber/v3"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func testUser(role string, active bool) models.User {
	return models.User{
		ID: 7, Name: "Ana", Email: "ana@example.com", Role: role, IsActive: active,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
}

func expectUserLookup(mock sqlmock.Sqlmock, user models.User) {
	mock.ExpectQuery("SELECT id, name, email, role, is_active, created_at, updated_at").
		WithArgs(user.ID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "email", "role", "is_active", "created_at", "updated_at",
		}).AddRow(user.ID, user.Name, user.Email, user.Role, user.IsActive, user.CreatedAt, user.UpdatedAt))
}

func newProtectedApp(db *sql.DB) *fiber.App {
	app := fiber.New()
	app.Get("/protected", Authenticate(db, []byte(testSecret), time.Second), func(c fiber.Ctx) error {
		user, ok := CurrentUser(c)
		if !ok {
			return utils.Fail(c, fiber.StatusUnauthorized, "unauthorized")
		}
		return utils.OK(c, fiber.StatusOK, user.Public())
	})
	app.Get("/admin", Authenticate(db, []byte(testSecret), time.Second), RequireAdmin(), func(c fiber.Ctx) error {
		return utils.OK(c, fiber.StatusOK, fiber.Map{"admin": true})
	})
	return app
}

func request(t *testing.T, app *fiber.App, path, token string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func TestAuthenticateRejectsMissingOrInvalidTokens(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	app := newProtectedApp(db)

	for _, token := range []string{"", "not-a-token"} {
		status, body := request(t, app, "/protected", token)
		if status != fiber.StatusUnauthorized || body == "" {
			t.Fatalf("token %q: status=%d body=%s", token, status, body)
		}
	}
	otherSecretToken, _, err := utils.NewAccessToken([]byte("another-secret-long-enough-32"), testUser(models.RoleUser, true), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := request(t, app, "/protected", otherSecretToken); status != fiber.StatusUnauthorized {
		t.Fatalf("wrong secret should be rejected, got %d", status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticateLoadsActiveUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	app := newProtectedApp(db)

	user := testUser(models.RoleUser, true)
	expectUserLookup(mock, user)
	token, _, err := utils.NewAccessToken([]byte(testSecret), user, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, body := request(t, app, "/protected", token)
	if status != fiber.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if want := `"email":"ana@example.com"`; !strings.Contains(body, want) {
		t.Fatalf("response missing user: %s", body)
	}
	if strings.Contains(body, "password_hash") {
		t.Fatalf("response leaked password hash: %s", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticateRejectsInactiveUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	app := newProtectedApp(db)

	user := testUser(models.RoleUser, false)
	expectUserLookup(mock, user)
	token, _, err := utils.NewAccessToken([]byte(testSecret), user, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := request(t, app, "/protected", token); status != fiber.StatusUnauthorized {
		t.Fatalf("inactive user should be rejected, got %d", status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireAdmin(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	app := newProtectedApp(db)

	regular := testUser(models.RoleUser, true)
	expectUserLookup(mock, regular)
	regularToken, _, err := utils.NewAccessToken([]byte(testSecret), regular, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := request(t, app, "/admin", regularToken); status != fiber.StatusForbidden {
		t.Fatalf("regular user should get 403, got %d", status)
	}

	admin := testUser(models.RoleAdmin, true)
	expectUserLookup(mock, admin)
	adminToken, _, err := utils.NewAccessToken([]byte(testSecret), admin, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := request(t, app, "/admin", adminToken); status != fiber.StatusOK {
		t.Fatalf("admin should get 200, got %d", status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
