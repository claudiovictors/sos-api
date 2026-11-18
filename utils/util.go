package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/mail"
	"strings"
)

const (
	MaxNameLength     = 100
	MinPasswordLength = 8
	MaxPasswordLength = 72
)

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidEmail(email string) bool {
	if email == "" || strings.ContainsAny(email, " \t\r\n") {
		return false
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return false
	}
	at := strings.LastIndex(email, "@")
	return at > 0 && strings.Contains(email[at+1:], ".")
}

func ValidateName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	return name, name != "" && len(name) <= MaxNameLength
}

func ValidatePassword(password string) bool {
	return len(password) >= MinPasswordLength && len(password) <= MaxPasswordLength
}

func GenerateRefreshToken() (token, hash string, err error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(random)
	return token, HashRefreshToken(token), nil
}

func HashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func IsUniqueViolation(err error) bool {
	var state interface{ SQLState() string }
	return errors.As(err, &state) && state.SQLState() == "23505"
}
