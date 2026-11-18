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
	"golang.org/x/crypto/bcrypt"
)

func TestRegisterValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"invalid json", "{"},
		{"missing name", `{"email":"ana@example.com","password":"password123"}`},
		{"invalid email", `{"name":"Ana","email":"ana@example","password":"password123"}`},
		{"short password", `{"name":"Ana","email":"ana@example.com","password":"short"}`},
		{"long password", `{"name":"Ana","email":"ana@example.com","password":"` + strings.Repeat("x", 73) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := newTestDB(t)
			app := fiber.New()
			app.Post("/register", newTestAuth(t, db).Store)

			status, body := request(t, app, http.MethodPost, "/register", tt.body, "")
			if status != fiber.StatusBadRequest {
				t.Fatalf("status=%d body=%s", status, body)
			}
			if env := decodeEnvelope(t, body); env.Success || env.Error == "" {
				t.Fatalf("unexpected envelope: %s", body)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRegisterNormalizesEmailAndHidesHash(t *testing.T) {
	db, mock := newTestDB(t)
	app := fiber.New()
	app.Post("/register", newTestAuth(t, db).Store)

	now := time.Now()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("Ana", "ana@example.com", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "email", "role", "is_active", "created_at", "updated_at",
		}).AddRow(1, "Ana", "ana@example.com", models.RoleUser, true, now, now))

	status, body := request(t, app, http.MethodPost, "/register",
		`{"name":"  Ana  ","email":" ANA@Example.com ","password":"password123"}`, "")
	if status != fiber.StatusCreated {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if strings.Contains(body, "password") {
		t.Fatalf("response leaked password data: %s", body)
	}
	var env envelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatal(err)
	}
	if !env.Success || !strings.Contains(string(env.Data), `"id":1`) {
		t.Fatalf("unexpected response: %s", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	db, mock := newTestDB(t)
	app := fiber.New()
	app.Post("/register", newTestAuth(t, db).Store)

	mock.ExpectQuery("INSERT INTO users").
		WillReturnError(&pgconn.PgError{Code: "23505"})
	status, body := request(t, app, http.MethodPost, "/register",
		`{"name":"Ana","email":"ana@example.com","password":"password123"}`, "")
	if status != fiber.StatusConflict {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	t.Run("unknown email", func(t *testing.T) {
		db, mock := newTestDB(t)
		app := fiber.New()
		app.Post("/login", newTestAuth(t, db).Login)
		mock.ExpectQuery("FROM users WHERE email").
			WithArgs("missing@example.com").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "name", "email", "password_hash", "role", "is_active", "created_at", "updated_at",
			}))

		status, body := request(t, app, http.MethodPost, "/login",
			`{"email":"missing@example.com","password":"password123"}`, "")
		if status != fiber.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", status, body)
		}
		if !strings.Contains(body, "invalid email or password") {
			t.Fatalf("error should not reveal whether email exists: %s", body)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		db, mock := newTestDB(t)
		app := fiber.New()
		app.Post("/login", newTestAuth(t, db).Login)
		hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		mock.ExpectQuery("FROM users WHERE email").
			WithArgs("ana@example.com").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "name", "email", "password_hash", "role", "is_active", "created_at", "updated_at",
			}).AddRow(1, "Ana", "ana@example.com", string(hash), models.RoleUser, true, now, now))

		status, body := request(t, app, http.MethodPost, "/login",
			`{"email":"ana@example.com","password":"wrong-password"}`, "")
		if status != fiber.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", status, body)
		}
		if !strings.Contains(body, "invalid email or password") {
			t.Fatalf("unexpected error body: %s", body)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLoginIssuesTokens(t *testing.T) {
	db, mock := newTestDB(t)
	app := fiber.New()
	app.Post("/login", newTestAuth(t, db).Login)

	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mock.ExpectQuery("FROM users WHERE email").
		WithArgs("ana@example.com").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "email", "password_hash", "role", "is_active", "created_at", "updated_at",
		}).AddRow(1, "Ana", "ana@example.com", string(hash), models.RoleUser, true, now, now))
	mock.ExpectExec("INSERT INTO auth_refresh_tokens").
		WithArgs(sqlmock.AnyArg(), int64(1), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	status, body := request(t, app, http.MethodPost, "/login",
		`{"email":"ANA@example.com","password":"password123"}`, "")
	if status != fiber.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var response struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
			User         struct {
				ID int64 `json:"id"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.AccessToken == "" || response.Data.RefreshToken == "" || response.Data.TokenType != "Bearer" {
		t.Fatalf("missing tokens: %s", body)
	}
	claims, err := utils.ParseAccessToken(response.Data.AccessToken, []byte(testSecret))
	if err != nil {
		t.Fatalf("invalid access token: %v", err)
	}
	if claims.Subject != "1" || claims.Role != models.RoleUser {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if response.Data.User.ID != 1 {
		t.Fatalf("unexpected user: %s", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRotatesToken(t *testing.T) {
	db, mock := newTestDB(t)
	app := fiber.New()
	app.Post("/refresh", newTestAuth(t, db).Refresh)

	oldToken, oldHash, err := utils.GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mock.ExpectBegin()
	mock.ExpectQuery("FROM auth_refresh_tokens t").
		WithArgs(oldHash).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "email", "role", "is_active", "created_at", "updated_at",
		}).AddRow(1, "Ana", "ana@example.com", models.RoleUser, true, now, now))
	mock.ExpectExec("UPDATE auth_refresh_tokens SET revoked_at").
		WithArgs(oldHash).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO auth_refresh_tokens").
		WithArgs(sqlmock.AnyArg(), int64(1), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	status, body := request(t, app, http.MethodPost, "/refresh",
		`{"refresh_token":"`+oldToken+`"}`, "")
	if status != fiber.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var env envelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatal(err)
	}
	var data struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.RefreshToken == "" || data.RefreshToken == oldToken {
		t.Fatalf("refresh token was not rotated: %s", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRejectsReusedToken(t *testing.T) {
	db, mock := newTestDB(t)
	app := fiber.New()
	app.Post("/refresh", newTestAuth(t, db).Refresh)

	token, hash, err := utils.GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("FROM auth_refresh_tokens t").
		WithArgs(hash).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "email", "role", "is_active", "created_at", "updated_at",
		}))
	mock.ExpectQuery("SELECT user_id FROM auth_refresh_tokens").
		WithArgs(hash).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(1))
	mock.ExpectExec("UPDATE auth_refresh_tokens SET revoked_at").
		WithArgs(int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	status, body := request(t, app, http.MethodPost, "/refresh",
		`{"refresh_token":"`+token+`"}`, "")
	if status != fiber.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestLogoutAndMeRequireBearerToken(t *testing.T) {
	db, mock := newTestDB(t)
	auth := newTestAuth(t, db)
	app := fiber.New()
	app.Post("/logout", middleware.Authenticate(db, []byte(testSecret), time.Second), auth.Logout)
	app.Get("/me", middleware.Authenticate(db, []byte(testSecret), time.Second), auth.Me)

	if status, _ := request(t, app, http.MethodPost, "/logout", `{}`, ""); status != fiber.StatusUnauthorized {
		t.Fatalf("logout without token: %d", status)
	}
	if status, _ := request(t, app, http.MethodGet, "/me", "", ""); status != fiber.StatusUnauthorized {
		t.Fatalf("me without token: %d", status)
	}

	user := models.User{ID: 1, Name: "Ana", Email: "ana@example.com", Role: models.RoleUser,
		IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	token, _, err := utils.NewAccessToken([]byte(testSecret), user, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	expectAuthUser(mock, user)
	status, body := request(t, app, http.MethodGet, "/me", "", token)
	if status != fiber.StatusOK || strings.Contains(body, "password") {
		t.Fatalf("me: status=%d body=%s", status, body)
	}

	expectAuthUser(mock, user)
	refreshToken, hash, err := utils.GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("UPDATE auth_refresh_tokens SET revoked_at").
		WithArgs(hash, int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	status, _ = request(t, app, http.MethodPost, "/logout",
		`{"refresh_token":"`+refreshToken+`"}`, token)
	if status != fiber.StatusNoContent {
		t.Fatalf("logout: status=%d", status)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
