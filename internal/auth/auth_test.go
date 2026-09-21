package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTValidation(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	s, err := NewSigner(key, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.Issue("user-1", 7)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Parse(token)
	if err != nil || c.Subject != "user-1" || c.TokenVersion != 7 {
		t.Fatalf("round trip: %+v %v", c, err)
	}
	other, _ := NewSigner([]byte(strings.Repeat("x", 32)), time.Hour)
	if _, err := other.Parse(token); err == nil {
		t.Fatal("token accepted under wrong key")
	}
	now := time.Now()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": "user-1", "iss": Issuer, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(), "ver": 7}
	}
	tests := []struct {
		name   string
		method jwt.SigningMethod
		mutate func(jwt.MapClaims)
		secret any
	}{
		{"expired", jwt.SigningMethodHS256, func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Second).Unix() }, key},
		{"missing expiration", jwt.SigningMethodHS256, func(c jwt.MapClaims) { delete(c, "exp") }, key},
		{"missing subject", jwt.SigningMethodHS256, func(c jwt.MapClaims) { delete(c, "sub") }, key},
		{"wrong issuer", jwt.SigningMethodHS256, func(c jwt.MapClaims) { c["iss"] = "other" }, key},
		{"missing issuance", jwt.SigningMethodHS256, func(c jwt.MapClaims) { delete(c, "iat") }, key},
		{"future issuance", jwt.SigningMethodHS256, func(c jwt.MapClaims) { c["iat"] = now.Add(time.Hour).Unix() }, key},
		{"future activation", jwt.SigningMethodHS256, func(c jwt.MapClaims) { c["nbf"] = now.Add(time.Hour).Unix() }, key},
		{"negative version", jwt.SigningMethodHS256, func(c jwt.MapClaims) { c["ver"] = -1 }, key},
		{"different HMAC algorithm", jwt.SigningMethodHS512, func(c jwt.MapClaims) {}, key},
		{"unsigned", jwt.SigningMethodNone, func(c jwt.MapClaims) {}, jwt.UnsafeAllowNoneSignatureType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			raw, err := jwt.NewWithClaims(tc.method, c).SignedString(tc.secret)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Parse(raw); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
	if _, err := NewSigner([]byte("short"), time.Hour); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := s.Parse(strings.Repeat("a", 8193)); err == nil {
		t.Fatal("oversize token accepted")
	}
}

func TestPasswordSecurity(t *testing.T) {
	password := "correct horse battery staple"
	a, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("password hashes must have independent salts")
	}
	if !VerifyPassword(a, password) || VerifyPassword(a, "incorrect password") || VerifyPassword("malformed", password) {
		t.Fatal("incorrect password verification")
	}
	if _, err := HashPassword(strings.Repeat("a", 73)); err == nil {
		t.Fatal("bcrypt truncation must be rejected")
	}
	if VerifyPassword(a, strings.Repeat("a", 73)) {
		t.Fatal("long password was accepted")
	}
}
