package controllers

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/claudiovictors/api-rest/middleware"
	"github.com/claudiovictors/api-rest/models"
	"github.com/claudiovictors/api-rest/utils"
	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

type UserController struct {
	db           *sql.DB
	queryTimeout time.Duration
}

type userUpdate struct {
	Name     *string `json:"name"`
	Email    *string `json:"email"`
	Password *string `json:"password"`
}

func NewUserController(db *sql.DB, timeout time.Duration) (*UserController, error) {
	if db == nil {
		return nil, errors.New("database connection is required")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &UserController{db: db, queryTimeout: timeout}, nil
}

func (u *UserController) Index(c fiber.Ctx) error {
	limit, offset, ok := pagination(c)
	if !ok {
		return utils.Fail(c, fiber.StatusBadRequest, "limit must be 1-100 and offset must be non-negative")
	}
	ctx, cancel := context.WithTimeout(c.Context(), u.queryTimeout)
	defer cancel()

	rows, err := u.db.QueryContext(ctx,
		`SELECT id, name, email, role, created_at
		 FROM users WHERE is_active = TRUE ORDER BY id LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not list users")
	}
	defer func() { _ = rows.Close() }()

	users := make([]models.PublicUser, 0)
	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.CreatedAt); err != nil {
			return utils.Fail(c, fiber.StatusInternalServerError, "could not list users")
		}
		users = append(users, user.Public())
	}
	if err := rows.Err(); err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not list users")
	}

	var total int
	if err := u.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE is_active = TRUE`,
	).Scan(&total); err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not list users")
	}

	return utils.OKWithMeta(c, fiber.StatusOK, users, fiber.Map{
		"limit": limit, "offset": offset, "total": total,
	})
}

func (u *UserController) Show(c fiber.Ctx) error {
	id, ok := userIDParam(c)
	if !ok {
		return utils.Fail(c, fiber.StatusBadRequest, "invalid user id")
	}
	current, _ := middleware.CurrentUser(c)
	if !current.IsAdmin() && current.ID != id {
		return utils.Fail(c, fiber.StatusNotFound, "user not found")
	}

	ctx, cancel := context.WithTimeout(c.Context(), u.queryTimeout)
	defer cancel()

	var user models.User
	err := u.db.QueryRowContext(ctx,
		`SELECT id, name, email, role, created_at, updated_at
		 FROM users WHERE id = $1 AND is_active = TRUE`,
		id,
	).Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return utils.Fail(c, fiber.StatusNotFound, "user not found")
	}
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not load user")
	}
	return utils.OK(c, fiber.StatusOK, user.Public())
}

func (u *UserController) Update(c fiber.Ctx) error {
	id, ok := userIDParam(c)
	if !ok {
		return utils.Fail(c, fiber.StatusBadRequest, "invalid user id")
	}
	current, _ := middleware.CurrentUser(c)
	if !current.IsAdmin() && current.ID != id {
		return utils.Fail(c, fiber.StatusForbidden, "you can only update your own account")
	}

	var input userUpdate
	if err := decodeBody(c, &input); err != nil {
		return utils.Fail(c, fiber.StatusBadRequest, "invalid JSON body")
	}
	if input.Name == nil && input.Email == nil && input.Password == nil {
		return utils.Fail(c, fiber.StatusBadRequest, "at least one field is required")
	}

	sets := make([]string, 0, 4)
	args := make([]any, 0, 5)
	if input.Name != nil {
		name, valid := utils.ValidateName(*input.Name)
		if !valid {
			return utils.Fail(c, fiber.StatusBadRequest, "invalid name")
		}
		args = append(args, name)
		sets = append(sets, "name = $"+strconv.Itoa(len(args)))
	}
	if input.Email != nil {
		email := utils.NormalizeEmail(*input.Email)
		if !utils.ValidEmail(email) {
			return utils.Fail(c, fiber.StatusBadRequest, "invalid email")
		}
		args = append(args, email)
		sets = append(sets, "email = $"+strconv.Itoa(len(args)))
	}
	if input.Password != nil {
		if !utils.ValidatePassword(*input.Password) {
			return utils.Fail(c, fiber.StatusBadRequest, "password must be 8-72 bytes")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*input.Password), bcrypt.DefaultCost)
		if err != nil {
			return utils.Fail(c, fiber.StatusInternalServerError, "could not update password")
		}
		args = append(args, string(hash))
		sets = append(sets, "password_hash = $"+strconv.Itoa(len(args)))
	}
	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)

	ctx, cancel := context.WithTimeout(c.Context(), u.queryTimeout)
	defer cancel()

	var user models.User
	err := u.db.QueryRowContext(ctx,
		`UPDATE users SET `+strings.Join(sets, ", ")+
			` WHERE id = $`+strconv.Itoa(len(args))+` AND is_active = TRUE
		 RETURNING id, name, email, role, created_at, updated_at`,
		args...,
	).Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return utils.Fail(c, fiber.StatusNotFound, "user not found")
	}
	if utils.IsUniqueViolation(err) {
		return utils.Fail(c, fiber.StatusConflict, "email is already registered")
	}
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not update user")
	}
	return utils.OK(c, fiber.StatusOK, user.Public())
}

func (u *UserController) Delete(c fiber.Ctx) error {
	id, ok := userIDParam(c)
	if !ok {
		return utils.Fail(c, fiber.StatusBadRequest, "invalid user id")
	}
	current, _ := middleware.CurrentUser(c)
	if !current.IsAdmin() && current.ID != id {
		return utils.Fail(c, fiber.StatusForbidden, "you can only deactivate your own account")
	}

	ctx, cancel := context.WithTimeout(c.Context(), u.queryTimeout)
	defer cancel()

	tx, err := u.db.BeginTx(ctx, nil)
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not deactivate user")
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET is_active = FALSE, updated_at = NOW()
		 WHERE id = $1 AND is_active = TRUE`,
		id,
	)
	if err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not deactivate user")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return utils.Fail(c, fiber.StatusNotFound, "user not found")
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE auth_refresh_tokens SET revoked_at = NOW()
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		id,
	); err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not deactivate user")
	}
	if err := tx.Commit(); err != nil {
		return utils.Fail(c, fiber.StatusInternalServerError, "could not deactivate user")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func userIDParam(c fiber.Ctx) (int64, bool) {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	return id, err == nil && id > 0
}

func pagination(c fiber.Ctx) (limit, offset int, ok bool) {
	limit = defaultPageSize
	offset = 0
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxPageSize {
			return 0, 0, false
		}
		limit = parsed
	}
	if raw := c.Query("offset"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return 0, 0, false
		}
		offset = parsed
	}
	return limit, offset, true
}
