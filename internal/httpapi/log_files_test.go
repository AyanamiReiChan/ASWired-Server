package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/logfiles"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/http"
	"strings"
	"testing"
)

func TestLogFileManagement(t *testing.T) {
	a, h, token := controllerFixture(t)
	m, err := logfiles.Open(t.TempDir(), 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	a.LogFiles = m
	member := store.User{ID: "log-reader", Username: "log-reader", Role: "user", TokenVersion: 1, PasswordHash: "fixture"}
	if err = a.DB.CreateUser(context.Background(), member); err != nil {
		t.Fatal(err)
	}
	memberToken, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/logs/files", memberToken, nil), http.StatusForbidden)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logs/files/remove", memberToken, map[string]any{"all": true, "confirm": true}), http.StatusForbidden)
	_, _ = m.Write([]byte("runtime log\n"))
	requireStatus(t, controllerRequest(t, h, "GET", "/api/logs/files", "", nil), http.StatusUnauthorized)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logs/files/remove", "", map[string]any{"all": true, "confirm": true}), http.StatusUnauthorized)
	r := controllerRequest(t, h, "GET", "/api/logs/files", token, nil)
	requireStatus(t, r, 200)
	if !strings.Contains(r.Body.String(), "aswired.log") || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(r.Body.String())
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logs/files/remove", token, map[string]any{"all": true}), 400)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logs/files/remove", token, map[string]any{"name": "../aswired.db", "confirm": true}), 400)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logs/files/remove", token, map[string]any{"name": "aswired.log", "confirm": true}), 200)
	list, _ := m.List()
	if list.TotalSize != 0 {
		t.Fatal("active log not cleared")
	}
	_, _ = m.Write([]byte("continued\n"))
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logs/files/remove", token, map[string]any{"all": true, "confirm": true}), 200)
	list, _ = m.List()
	if len(list.Files) != 1 || list.TotalSize != 0 {
		t.Fatal("clear failed")
	}
}
