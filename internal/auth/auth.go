package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const Issuer = "aswired-server"

var ErrInvalidToken = errors.New("invalid or expired authentication token")

type Claims struct {
	TokenVersion int64 `json:"ver"`
	jwt.RegisteredClaims
}

type Signer struct {
	secret []byte
	ttl    time.Duration
}

func NewSigner(secret []byte, ttl time.Duration) (*Signer, error) {
	if len(secret) < 32 {
		return nil, errors.New("JWT signing secret must contain at least 32 bytes")
	}
	if ttl <= 0 || ttl > 30*24*time.Hour {
		return nil, errors.New("JWT lifetime must be positive and at most 30 days")
	}
	return &Signer{secret: append([]byte(nil), secret...), ttl: ttl}, nil
}

func (s *Signer) Issue(userID string, tokenVersion int64) (string, error) {
	if strings.TrimSpace(userID) == "" || tokenVersion < 0 {
		return "", ErrInvalidToken
	}
	now := time.Now().UTC()
	claims := Claims{TokenVersion: tokenVersion, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: Issuer, Subject: userID,
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
	}}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

func (s *Signer) Parse(raw string) (Claims, error) {
	var claims Claims
	if raw == "" || len(raw) > 8192 {
		return claims, ErrInvalidToken
	}
	token, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidToken
		}
		return s.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || token == nil || !token.Valid || strings.TrimSpace(claims.Subject) == "" ||
		claims.TokenVersion < 0 || claims.IssuedAt == nil || claims.ExpiresAt == nil ||
		!claims.ExpiresAt.After(claims.IssuedAt.Time) {
		return Claims{}, ErrInvalidToken
	}
	return claims, nil
}

func HashPassword(password string) (string, error) {
	if len(password) < 10 || len(password) > 72 {
		return "", fmt.Errorf("password must contain between 10 and 72 UTF-8 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func VerifyPassword(hash, password string) bool {
	if len(password) > 72 || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
