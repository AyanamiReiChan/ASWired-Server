package httpapi

import (
	"bytes"
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReleaseFirstAdministratorWithKomari(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASWIRED_SETUP_TOKEN", "")
	db, err := store.Open(store.Config{Driver: "sqlite", DSN: filepath.Join(dir, "aswired.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a, err := New(config.Config{DataDir: dir, JWTSecret: bytes.Repeat([]byte{1}, 32), JWTTTL: time.Hour, PublicURL: "http://localhost:5174", KomariPublicURL: "https://probe.example.test", KomariBridgeSecret: strings.Repeat("x", 32)}, db)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	h := a.Handler()
	users, err := db.ListUsers(context.Background())
	if err != nil || len(users) != 0 {
		t.Fatal("deployment created an account", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "setup-token"))
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"username": "chosen-owner", "password": "chosen-secret-password-2026", "setupToken": "wrong"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/setup", "", input), 403)
	input["setupToken"] = strings.TrimSpace(string(raw))
	res := controllerRequest(t, h, "POST", "/api/setup", "", input)
	requireStatus(t, res, 200)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", text(responseMap(t, res), "token"), nil), 200)
	u, err := db.UserByUsername(context.Background(), "chosen-owner")
	if err != nil || u.Role != "admin" || !auth.VerifyPassword(u.PasswordHash, input["password"].(string)) || u.PasswordHash == input["password"] {
		t.Fatal("invalid administrator persistence", err)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/setup", "", input), 409)
	a.Config.AdminUsernames = []string{"different-owner"}
	if a.permittedAdmin(u) {
		t.Fatal("explicit administrator restriction ignored")
	}
}
