package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestResetPasswordChangesRealAccountAndRevokesSessions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASWIRED_DATA_DIR", dir)
	t.Setenv("ASWIRED_DATABASE_DSN", "")
	t.Setenv("ASWIRED_DATABASE_DRIVER", "sqlite")
	t.Setenv("ASWIRED_JWT_SECRET", "")
	t.Setenv("JWT_SECRET", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(store.Config{Driver: "sqlite", DSN: cfg.DatabaseDSN})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash, _ := auth.HashPassword("original-password-123")
	if err := db.InitializeAdmin(ctx, store.User{ID: "user", Username: "administrator", Role: "admin", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	for _, collection := range []string{"_identity", "_passkeys"} {
		if _, err := db.SaveRecord(ctx, store.Record{Collection: collection, ID: "user", OwnerID: "user", Data: map[string]any{"registered": true}}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, "jwt.key"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	var output bytes.Buffer
	if err := resetPasswordCommand([]string{"--username", "administrator", "--password-stdin", "--clear-mfa"}, strings.NewReader("replacement-password-456\n"), &output); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(store.Config{Driver: "sqlite", DSN: cfg.DatabaseDSN})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user, err := db.UserByUsername(ctx, "administrator")
	if err != nil {
		t.Fatal(err)
	}
	if user.TokenVersion != 1 || !auth.VerifyPassword(user.PasswordHash, "replacement-password-456") {
		t.Fatal("credentials were not actually changed")
	}
	if auth.VerifyPassword(user.PasswordHash, "original-password-123") {
		t.Fatal("old password still accepted")
	}
	for _, collection := range []string{"_identity", "_passkeys"} {
		rows, err := db.ListRecords(ctx, collection, "user")
		if err != nil || len(rows) != 0 {
			t.Fatal("MFA records not removed")
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "jwt.key"))
	if !bytes.Equal(before, after) {
		t.Fatal("reset rotated persistent keys")
	}
	if strings.Contains(output.String(), "replacement-password") {
		t.Fatal("password exposed in output")
	}
}

func TestReleaseValidationAndAtomicReplacement(t *testing.T) {
	binary := []byte("fixture-binary")
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "aswired-server", Mode: 0755, Size: int64(len(binary))}); err != nil {
		t.Fatal(err)
	}
	archive.Write(binary)
	archive.Close()
	gz.Close()
	extracted, err := extractReleaseBinary(buffer.Bytes(), false, "aswired-server")
	if err != nil || !bytes.Equal(extracted, binary) {
		t.Fatalf("extract %v", err)
	}
	sum := sha256.Sum256(buffer.Bytes())
	entry := hex.EncodeToString(sum[:]) + "  aswired-server_v0.2.0_linux_amd64.tar.gz\n"
	if _, err := releaseChecksum([]byte(entry), "aswired-server_v0.2.0_linux_amd64.tar.gz"); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseChecksum([]byte(entry+entry), "aswired-server_v0.2.0_linux_amd64.tar.gz"); err == nil {
		t.Fatal("duplicate checksum accepted")
	}
	if _, err := extractReleaseBinary(buffer.Bytes(), false, "../aswired-server"); err == nil {
		t.Fatal("archive traversal name accepted")
	}
	destination := filepath.Join(t.TempDir(), "aswired-server")
	if err := replaceBinary(destination, extracted); err != nil {
		t.Fatal(err)
	}
	installed, _ := os.ReadFile(destination)
	if !bytes.Equal(installed, binary) {
		t.Fatal("binary replacement failed")
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"message": "not found"})
	}))
	defer api.Close()
	if _, err := downloadRelease(context.Background(), api.Client(), api.URL, 4096); err == nil || !strings.Contains(err.Error(), "not have been published") {
		t.Fatal("unpublished release did not fail clearly")
	}
}
