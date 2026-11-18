package utils

import (
	"testing"
	"time"

	"github.com/claudiovictors/api-rest/models"
	"github.com/golang-jwt/jwt/v5"
)

func TestNormalizeEmail(t *testing.T) {
	if got := NormalizeEmail("  Ana.Pereira@Example.COM "); got != "ana.pereira@example.com" {
		t.Fatalf("unexpected normalized email: %q", got)
	}
}

func TestValidEmail(t *testing.T) {
	tests := map[string]bool{
		"ana@example.com":       true,
		"a.b+tag@example.co.uk": true,
		"ana@example":           false,
		"ana@example.com extra": false,
		"Ana <ana@example.com>": false,
		"@example.com":          false,
		"":                      false,
	}
	for email, want := range tests {
		if got := ValidEmail(email); got != want {
			t.Errorf("ValidEmail(%q) = %v, want %v", email, got, want)
		}
	}
}

func TestValidateNameAndPassword(t *testing.T) {
	if name, ok := ValidateName("  Ana  "); !ok || name != "Ana" {
		t.Fatalf("ValidateName: got %q, %v", name, ok)
	}
	if _, ok := ValidateName("   "); ok {
		t.Fatal("empty name should be rejected")
	}
	if _, ok := ValidateName(string(make([]byte, MaxNameLength+1))); ok {
		t.Fatal("long name should be rejected")
	}
	if !ValidatePassword("12345678") || ValidatePassword("1234567") {
		t.Fatal("password length validation is incorrect")
	}
	if ValidatePassword(string(make([]byte, MaxPasswordLength+1))) {
		t.Fatal("password over bcrypt limit should be rejected")
	}
}

func TestRefreshTokenHashing(t *testing.T) {
	token, hash, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	if token == "" || hash == "" || token == hash {
		t.Fatal("token and hash must differ and not be empty")
	}
	if len(hash) != 64 {
		t.Fatalf("hash length = %d, want 64", len(hash))
	}
	if HashRefreshToken(token) != hash {
		t.Fatal("hash is not deterministic")
	}
	other, _, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	if token == other {
		t.Fatal("tokens must be unique")
	}
}

func TestAccessTokenValidation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	user := models.User{ID: 7, Name: "Ana", Email: "ana@example.com", Role: models.RoleUser}

	token, expiresAt, err := NewAccessToken(secret, user, time.Hour)
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}
	if expiresAt.Before(time.Now()) {
		t.Fatal("expiration must be in the future")
	}
	claims, err := ParseAccessToken(token, secret)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	if claims.Subject != "7" || claims.Role != models.RoleUser {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if _, err := ParseAccessToken(token, []byte("another-secret-that-is-long-enough")); err == nil {
		t.Fatal("token signed with another secret must be rejected")
	}

	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "7",
			Issuer:    TokenIssuer,
			Audience:  jwt.ClaimStrings{TokenAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
		Role: models.RoleUser,
	}).SignedString(secret)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}
	if _, err := ParseAccessToken(expired, secret); err == nil {
		t.Fatal("expired token must be rejected")
	}

	wrongIssuer, err := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "7",
			Issuer:    "other-api",
			Audience:  jwt.ClaimStrings{TokenAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Role: models.RoleUser,
	}).SignedString(secret)
	if err != nil {
		t.Fatalf("sign wrong issuer token: %v", err)
	}
	if _, err := ParseAccessToken(wrongIssuer, secret); err == nil {
		t.Fatal("token with wrong issuer must be rejected")
	}
}

func TestBearerToken(t *testing.T) {
	if token, err := BearerToken("Bearer abc"); err != nil || token != "abc" {
		t.Fatalf("BearerToken: %q, %v", token, err)
	}
	if token, err := BearerToken("bearer abc"); err != nil || token != "abc" {
		t.Fatalf("BearerToken should be case insensitive: %q, %v", token, err)
	}
	for _, header := range []string{"", "abc", "Basic abc", "Bearer abc def"} {
		if _, err := BearerToken(header); err == nil {
			t.Errorf("header %q should be rejected", header)
		}
	}
}
