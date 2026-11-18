package utils

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/claudiovictors/api-rest/models"
	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenIssuer   = "schools-api"
	TokenAudience = "schools-api-clients"
)

type TokenClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func NewAccessToken(secret []byte, user models.User, ttl time.Duration) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(ttl)
	claims := TokenClaims{
		Role: user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(user.ID, 10),
			Issuer:    TokenIssuer,
			Audience:  jwt.ClaimStrings{TokenAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	return token, expiresAt, err
}

func ParseAccessToken(tokenString string, secret []byte) (*TokenClaims, error) {
	claims := new(TokenClaims)
	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) { return secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(TokenIssuer),
		jwt.WithAudience(TokenAudience),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return nil, errors.New("invalid access token")
	}
	if claims.Role == "" {
		return nil, errors.New("invalid access token")
	}
	return claims, nil
}

func BearerToken(header string) (string, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("missing bearer token")
	}
	return parts[1], nil
}
