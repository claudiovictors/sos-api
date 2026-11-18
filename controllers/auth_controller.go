package controllers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/claudiovictors/api-rest/middleware"
	"github.com/claudiovictors/api-rest/models"
	"github.com/claudiovictors/api-rest/utils"
	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessTokenDuration  = 24 * time.Hour
	refreshTokenDuration = 30 * 24 * time.Hour
)

var dummyPasswordHash = func() []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte("unused-password"), bcrypt.DefaultCost)
	return hash
}()

type AuthController struct {
	db           *sql.DB
	jwtSecret    []byte
	queryTimeout time.Duration
}

type credentials struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func NewAuthController(db *sql.DB, secret string, timeout time.Duration) (*AuthController, error) {
	if db == nil {
		return nil, errors.New("database connection is required")
	}
	if len(secret) < 32 {
		return nil, errors.New("AUTH_SECRET must contain at least 32 characters")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &AuthController{db: db, jwtSecret: []byte(secret), queryTimeout: timeout}, nil
}

func (a *AuthController) Store(c fiber.Ctx) error {
	var input credentials
	if err := decodeBody(c, &input); err != nil {
		return utils.Fail(c, fiber.StatusBadRequest, "invalid JSON body")
	}

	name, validName := utils.ValidateName(input.Name)
	email := utils.NormalizeEmail(input.Email)
	if !validName || !utils.ValidEmail(email) || !utils.ValidatePassword(input.Password) {
		return utils.Fail(c, fiber.StatusBadRequest,
			"name, valid email, and password (8-72 bytes) are required")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not create user")
	}

	ctx, cancel := context.WithTimeout(c.Context(), a.queryTimeout)
	defer cancel()

	var user models.User
	err = a.db.QueryRowContext(ctx,
		`INSERT INTO users (name, email, password_hash)
		 VALUES ($1, $2, $3)
		 RETURNING id, name, email, role, is_active, created_at, updated_at`,
		name, email, string(passwordHash),
	).Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if utils.IsUniqueViolation(err) {
			return utils.Fail(c, fiber.StatusConflict, "email is already registered")
		}
		return utils.Fail(c, fiber.StatusInternalServerError, "could not create user")
	}

	return utils.OK(c, fiber.StatusCreated, user.Public())
}

func (a *AuthController) Login(c fiber.Ctx) error {
	var input credentials
	if err := decodeBody(c, &input); err != nil {
		return utils.Fail(c, fiber.StatusBadRequest, "invalid JSON body")
	}

	email := utils.NormalizeEmail(input.Email)
	ctx, cancel := context.WithTimeout(c.Context(), a.queryTimeout)
	defer cancel()

	var user models.User
	var passwordHash string
	err := a.db.QueryRowContext(ctx,
		`SELECT id, name, email, password_hash, role, is_active, created_at, updated_at
		 FROM users WHERE email = $1`,
		email,
	).Scan(&user.ID, &user.Name, &user.Email, &passwordHash, &user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(input.Password))
		return utils.Fail(c, fiber.StatusUnauthorized, "invalid email or password")
	}
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not authenticate user")
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(input.Password)) != nil || !user.IsActive {
		return utils.Fail(c, fiber.StatusUnauthorized, "invalid email or password")
	}

	refreshToken, tokenHash, err := utils.GenerateRefreshToken()
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not create refresh token")
	}
	_, err = a.db.ExecContext(ctx,
		`INSERT INTO auth_refresh_tokens (token_hash, user_id, expires_at)
		 VALUES ($1, $2, $3)`,
		tokenHash, user.ID, time.Now().Add(refreshTokenDuration),
	)
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not create refresh token")
	}
	return a.writeTokens(c, user, refreshToken)
}

func (a *AuthController) Refresh(c fiber.Ctx) error {
	var input refreshRequest
	if err := decodeBody(c, &input); err != nil || input.RefreshToken == "" {
		return utils.Fail(c, fiber.StatusBadRequest, "refresh_token is required")
	}

	ctx, cancel := context.WithTimeout(c.Context(), a.queryTimeout)
	defer cancel()

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not refresh session")
	}
	defer func() { _ = tx.Rollback() }()

	var user models.User
	err = tx.QueryRowContext(ctx,
		`SELECT u.id, u.name, u.email, u.role, u.is_active, u.created_at, u.updated_at
		 FROM auth_refresh_tokens t
		 JOIN users u ON u.id = t.user_id
		 WHERE t.token_hash = $1 AND t.expires_at > NOW()
		   AND t.revoked_at IS NULL AND u.is_active = TRUE
		 FOR UPDATE OF t`,
		utils.HashRefreshToken(input.RefreshToken),
	).Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if a.revokeReusedToken(ctx, tx, input.RefreshToken) {
			_ = tx.Commit()
		}
		return utils.Fail(c, fiber.StatusUnauthorized, "invalid refresh token")
	}
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not refresh session")
	}

	refreshToken, tokenHash, err := utils.GenerateRefreshToken()
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not create refresh token")
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE auth_refresh_tokens SET revoked_at = NOW()
		 WHERE token_hash = $1 AND revoked_at IS NULL`,
		utils.HashRefreshToken(input.RefreshToken),
	); err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not refresh session")
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO auth_refresh_tokens (token_hash, user_id, expires_at)
		 VALUES ($1, $2, $3)`,
		tokenHash, user.ID, time.Now().Add(refreshTokenDuration),
	); err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not refresh session")
	}
	if err := tx.Commit(); err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not refresh session")
	}

	return a.writeTokens(c, user, refreshToken)
}

func (a *AuthController) Logout(c fiber.Ctx) error {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		return utils.Fail(c, fiber.StatusUnauthorized, "unauthorized")
	}
	var input refreshRequest
	if err := decodeBody(c, &input); err != nil || input.RefreshToken == "" {
		return utils.Fail(c, fiber.StatusBadRequest, "refresh_token is required")
	}

	ctx, cancel := context.WithTimeout(c.Context(), a.queryTimeout)
	defer cancel()
	_, err := a.db.ExecContext(ctx,
		`UPDATE auth_refresh_tokens SET revoked_at = NOW()
		 WHERE token_hash = $1 AND user_id = $2 AND revoked_at IS NULL`,
		utils.HashRefreshToken(input.RefreshToken), user.ID,
	)
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not revoke refresh token")
	}
	utils.NoStore(c)
	return c.SendStatus(fiber.StatusNoContent)
}

func (a *AuthController) Me(c fiber.Ctx) error {
	user, ok := middleware.CurrentUser(c)
	if !ok {
		return utils.Fail(c, fiber.StatusUnauthorized, "unauthorized")
	}
	return utils.OK(c, fiber.StatusOK, user.Public())
}

func (a *AuthController) writeTokens(c fiber.Ctx, user models.User, refreshToken string) error {
	accessToken, expiresAt, err := utils.NewAccessToken(a.jwtSecret, user, accessTokenDuration)
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not create access token")
	}

	utils.NoStore(c)
	return utils.OK(c, fiber.StatusOK, fiber.Map{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_at":    expiresAt.UTC().Format(time.RFC3339),
		"refresh_token": refreshToken,
		"user":          user.Public(),
	})
}

func (a *AuthController) revokeReusedToken(ctx context.Context, tx *sql.Tx, token string) bool {
	var userID int64
	err := tx.QueryRowContext(ctx,
		`SELECT user_id FROM auth_refresh_tokens
		 WHERE token_hash = $1 AND expires_at > NOW()`,
		utils.HashRefreshToken(token),
	).Scan(&userID)
	if err != nil {
		return false
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE auth_refresh_tokens SET revoked_at = NOW()
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)
	return err == nil
}

func decodeBody(c fiber.Ctx, target any) error {
	if len(c.Body()) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(c.Body(), target)
}
