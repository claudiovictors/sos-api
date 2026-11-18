package controllers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/claudiovictors/api-rest/models"
	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const accessTokenDuration = 24 * time.Hour
const refreshTokenDuration = 30 * 24 * time.Hour

type AuthController struct {
	db        *sql.DB
	jwtSecret []byte
}

type credentials struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenClaims struct {
	jwt.RegisteredClaims
}

func NewAuthController(db *sql.DB, secret string) (*AuthController, error) {
	if db == nil {
		return nil, errors.New("database connection is required")
	}
	if len(secret) < 32 {
		return nil, errors.New("AUTH_SECRET must contain at least 32 characters")
	}

	return &AuthController{db: db, jwtSecret: []byte(secret)}, nil
}

func (a *AuthController) Store(c fiber.Ctx) error {
	var input credentials
	if err := json.Unmarshal(c.Body(), &input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}

	input.Name = strings.TrimSpace(input.Name)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if input.Name == "" || len(input.Name) > 100 || !validEmail(input.Email) ||
		len(input.Password) < 8 || len(input.Password) > 72 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "name, valid email, and password (8-72 bytes) are required",
		})
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create user"})
	}

	var user models.User
	err = a.db.QueryRowContext(c.Context(),
		`INSERT INTO users (name, email, password_hash)
		 VALUES ($1, $2, $3)
		 RETURNING id, name, email, created_at`,
		input.Name, input.Email, string(passwordHash),
	).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if err != nil {
		var sqlState interface{ SQLState() string }
		if errors.As(err, &sqlState) && sqlState.SQLState() == "23505" {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "email is already registered"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create user"})
	}

	return c.Status(fiber.StatusCreated).JSON(user)
}

func (a *AuthController) Login(c fiber.Ctx) error {
	var input credentials
	if err := json.Unmarshal(c.Body(), &input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}

	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	var user models.User
	var passwordHash string
	err := a.db.QueryRowContext(c.Context(),
		`SELECT id, name, email, created_at, password_hash
		 FROM users WHERE email = $1`,
		input.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid email or password"})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not authenticate user"})
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(input.Password)) != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid email or password"})
	}

	refreshToken, tokenHash, err := generateRefreshToken()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create refresh token"})
	}
	_, err = a.db.ExecContext(c.Context(),
		`INSERT INTO auth_refresh_tokens (token_hash, user_id, expires_at)
		 VALUES ($1, $2, $3)`,
		tokenHash, user.ID, time.Now().Add(refreshTokenDuration),
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create refresh token"})
	}
	return a.writeTokens(c, user, refreshToken)
}

func (a *AuthController) Logout(c fiber.Ctx) error {
	userID, err := a.userIDFromRequest(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var input refreshRequest
	if err := json.Unmarshal(c.Body(), &input); err != nil || input.RefreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token is required"})
	}
	_, err = a.db.ExecContext(c.Context(),
		`DELETE FROM auth_refresh_tokens WHERE token_hash = $1 AND user_id = $2`,
		hashRefreshToken(input.RefreshToken), userID,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not revoke refresh token"})
	}
	c.Set("Cache-Control", "no-store")
	return c.SendStatus(fiber.StatusNoContent)
}

func (a *AuthController) Refresh(c fiber.Ctx) error {
	var input refreshRequest
	if err := json.Unmarshal(c.Body(), &input); err != nil || input.RefreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token is required"})
	}

	tx, err := a.db.BeginTx(c.Context(), nil)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not refresh session"})
	}
	defer tx.Rollback()

	var user models.User
	err = tx.QueryRowContext(c.Context(),
		`SELECT u.id, u.name, u.email, u.created_at
		 FROM auth_refresh_tokens t
		 JOIN users u ON u.id = t.user_id
		 WHERE t.token_hash = $1 AND t.expires_at > NOW()
		 FOR UPDATE OF t`,
		hashRefreshToken(input.RefreshToken),
	).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not refresh session"})
	}

	refreshToken, tokenHash, err := generateRefreshToken()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create refresh token"})
	}
	if _, err := tx.ExecContext(c.Context(),
		`DELETE FROM auth_refresh_tokens WHERE token_hash = $1`,
		hashRefreshToken(input.RefreshToken),
	); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not refresh session"})
	}
	if _, err := tx.ExecContext(c.Context(),
		`INSERT INTO auth_refresh_tokens (token_hash, user_id, expires_at)
		 VALUES ($1, $2, $3)`,
		tokenHash, user.ID, time.Now().Add(refreshTokenDuration),
	); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not refresh session"})
	}
	if err := tx.Commit(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not refresh session"})
	}

	return a.writeTokens(c, user, refreshToken)
}

func (a *AuthController) Me(c fiber.Ctx) error {
	userID, err := a.userIDFromRequest(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	var user models.User
	err = a.db.QueryRowContext(c.Context(),
		`SELECT id, name, email, created_at FROM users WHERE id = $1`,
		userID,
	).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not load user"})
	}
	return c.JSON(user)
}

func (a *AuthController) writeTokens(c fiber.Ctx, user models.User, refreshToken string) error {
	now := time.Now()
	expiresAt := now.Add(accessTokenDuration)
	claims := tokenClaims{RegisteredClaims: jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(user.ID, 10),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtSecret)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create access token"})
	}

	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{
		"access_token":  token,
		"token_type":    "Bearer",
		"expires_at":    expiresAt,
		"refresh_token": refreshToken,
		"user":          user,
	})
}

func generateRefreshToken() (string, string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	return token, hashRefreshToken(token), nil
}

func hashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (a *AuthController) userIDFromRequest(c fiber.Ctx) (int64, error) {
	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return 0, errors.New("missing bearer token")
	}

	claims := new(tokenClaims)
	token, err := jwt.ParseWithClaims(parts[1], claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return a.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return 0, errors.New("invalid bearer token")
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID < 1 {
		return 0, errors.New("invalid token subject")
	}
	return userID, nil
}

func validEmail(email string) bool {
	address, err := mail.ParseAddress(email)
	return err == nil && address.Address == email
}
