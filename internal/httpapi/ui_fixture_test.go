package httpapi

import (
	"bytes"
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUIFixture(t *testing.T) {
	if os.Getenv("ASWIRED_UI_FIXTURE") != "local-only" {
		t.Skip("interactive browser fixture is disabled")
	}
	dir := t.TempDir()
	db, err := store.Open(store.Config{Driver: "sqlite", DSN: filepath.Join(dir, "ui-fixture.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app, err := New(config.Config{DataDir: dir, PublicURL: "http://localhost:5176", AllowedOrigins: []string{"http://localhost:5176"}, JWTSecret: bytes.Repeat([]byte{43}, 32), JWTTTL: time.Hour}, db)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	hash, err := auth.HashPassword("ASWired-test-only-5176")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []store.User{{ID: "fixture-admin", Username: "fixture-admin", Role: "admin", PasswordHash: hash, TokenVersion: 1}, {ID: "fixture-member", Username: "fixture-member", Role: "user", PasswordHash: hash, TokenVersion: 1}} {
		if err = db.CreateUser(context.Background(), u); err != nil {
			t.Fatal(err)
		}
		if _, err = db.SaveRecord(context.Background(), store.Record{Collection: "members", ID: u.ID, OwnerID: u.ID, Data: map[string]any{"name": u.Username, "username": u.Username, "role": u.Role, "status": "正常"}}); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:12890")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Log("isolated UI fixture listening on 127.0.0.1:12890")
	select {
	case err = <-done:
		if err != http.ErrServerClosed {
			t.Fatal(err)
		}
	case <-time.After(45 * time.Minute):
		_ = server.Close()
	}
}
