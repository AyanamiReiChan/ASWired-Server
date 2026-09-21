package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptedRemoteBackupRoundTrip(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	objects := map[string][]byte{}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test" || pass != "webdav-test" {
			w.WriteHeader(401)
			return
		}
		switch r.Method {
		case "PUT":
			raw, _ := io.ReadAll(r.Body)
			objects[r.URL.Path] = raw
			w.WriteHeader(201)
		case "GET":
			data, ok := objects[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(data)
		default:
			w.WriteHeader(405)
		}
	}))
	defer remote.Close()
	cfg := map[string]any{"remoteBackup": map[string]any{"provider": "webdav", "url": remote.URL, "username": "test", "password": "webdav-test", "encryptionPassword": "different-backup-password-2026"}}
	if e := a.DB.SetSetting(ctx, "settings", cfg); e != nil {
		t.Fatal(e)
	}
	u, _ := a.DB.UserByUsername(ctx, "test-admin")
	uploaded, e := a.remoteBackup(ctx, u, "backup.remote.upload", nil)
	if e != nil {
		t.Fatal(e)
	}
	id := text(uploaded, "id")
	raw := objects["/"+id+".aswb"]
	if !bytes.HasPrefix(raw, []byte("ASWBACK1")) || bytes.Contains(raw, []byte("manifest.json")) {
		t.Fatal("remote object not encrypted")
	}
	if _, e = backupOpen(raw, "incorrect-password"); e == nil {
		t.Fatal("wrong backup password accepted")
	}
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)-1] ^= 1
	if _, e = backupOpen(corrupt, "different-backup-password-2026"); e == nil {
		t.Fatal("corrupt object accepted")
	}
	download, e := a.remoteBackup(ctx, u, "backup.remote.download", map[string]any{"id": id})
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := os.ReadFile(filepath.Join(a.Config.DataDir, "backups", text(download, "id")+".zip"))
	if e != nil || !bytes.HasPrefix(recovered, []byte("PK")) {
		t.Fatalf("backup download not ZIP: %v", e)
	}
	projection := settingsProjection(cfg)
	encoded := string(mustJSON(projection))
	if strings.Contains(encoded, "webdav-test") || strings.Contains(encoded, "different-backup-password") {
		t.Fatal("backup secret exposed to settings listing")
	}
}
func mustJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }

func TestRemoteBackupRetentionIsDestinationScopedAndReadTestDoesNotUpload(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	deleted := []string{}
	writes := 0
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "backup" || password != "secret" {
			w.WriteHeader(401)
			return
		}
		switch r.Method {
		case "PROPFIND":
			w.WriteHeader(207)
		case "DELETE":
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(204)
		default:
			writes++
			w.WriteHeader(405)
		}
	}))
	defer remote.Close()
	cfg := map[string]any{"provider": "webdav", "url": remote.URL, "username": "backup", "password": "secret", "keepLast": 1}
	if _, err := a.testRemoteBackup(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatal("connection test changed storage")
	}
	for _, id := range []string{"a-old", "z-new", "unrelated", "historical"} {
		destination := backupDestination(cfg)
		if id == "unrelated" {
			destination = "different"
		}
		if id == "historical" {
			destination = ""
		}
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_remoteBackups", ID: id, Data: map[string]any{"object": id + ".aswb", "destination": destination}}); err != nil {
			t.Fatal(err)
		}
	}
	count, err := a.pruneRemoteBackups(ctx, store.User{ID: "admin", Role: "admin"}, cfg)
	if err != nil || count != 1 || len(deleted) != 1 || deleted[0] != "/a-old.aswb" {
		t.Fatalf("unsafe retention: %d %v %v", count, deleted, err)
	}
	for _, id := range []string{"z-new", "unrelated", "historical"} {
		if _, err := a.DB.GetRecord(ctx, "_remoteBackups", id); err != nil {
			t.Fatal("retention deleted protected record", id)
		}
	}
}
