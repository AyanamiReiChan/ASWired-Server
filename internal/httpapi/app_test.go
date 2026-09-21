package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func controllerFixture(t *testing.T) (*App, http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	db, e := store.Open(store.Config{Driver: "sqlite", DSN: filepath.Join(dir, "test.db")})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	a, e := New(config.Config{DataDir: dir, JWTSecret: bytes.Repeat([]byte{9}, 32), JWTTTL: time.Hour, PublicURL: "http://localhost:5174", AllowedOrigins: []string{"http://localhost:5174"}}, db)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(a.Close)
	h := a.Handler()
	raw, e := os.ReadFile(filepath.Join(dir, "setup-token"))
	if e != nil {
		t.Fatal(e)
	}
	res := controllerRequest(t, h, "POST", "/api/setup", "", map[string]any{"username": "test-admin", "password": "test-admin-password-2026", "setupToken": strings.TrimSpace(string(raw))})
	if res.Code != 200 {
		t.Fatalf("setup: %d %s", res.Code, res.Body)
	}
	var login map[string]any
	json.Unmarshal(res.Body.Bytes(), &login)
	return a, h, text(login, "token")
}
func controllerRequest(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:10001"
	r.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(token, "asw_") {
		r.Header.Set("Authorization", "Bearer "+token)
	} else if token != "" {
		r.Header.Set("MM-Authorization", token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}
func responseMap(t *testing.T, r *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if e := json.Unmarshal(r.Body.Bytes(), &out); e != nil {
		t.Fatalf("response %d: %s", r.Code, r.Body)
	}
	return out
}
func requireStatus(t *testing.T, r *httptest.ResponseRecorder, status int) {
	t.Helper()
	if r.Code != status {
		t.Fatalf("expected %d, got %d: %s", status, r.Code, r.Body)
	}
}
func TestControllerAuthAndAPIScopes(t *testing.T) {
	a, h, token := controllerFixture(t)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", "", nil), 401)
	created := controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "token.create", "params": map[string]any{"name": "read only", "scopes": []string{"read"}}})
	requireStatus(t, created, 200)
	apiToken := text(responseMap(t, created), "token")
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", apiToken, nil), 200)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", apiToken, map[string]any{"action": "backup.create"}), 403)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/account/security", apiToken, nil), 403)
	rpc := controllerRequest(t, h, "POST", "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "run_action", "arguments": map[string]any{"action": "backup.create"}}})
	if !strings.Contains(rpc.Body.String(), "scope denied") {
		t.Fatalf("MCP write allowed: %s", rpc.Body)
	}
	raw := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"test-admin","password":"test-admin-password-2026"} garbage`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, raw)
	requireStatus(t, rec, 400)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logout", token, map[string]any{}), 200)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", token, nil), 401)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", apiToken, nil), 401)

	rawSetup, _ := os.ReadFile(filepath.Join(a.Config.DataDir, "setup-token"))
	if len(rawSetup) < 32 {
		t.Fatal("weak setup token")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/setup", "", map[string]any{"username": "someone", "password": "new-password-2026"}), 403)
}
func TestControllerBackupRoundTripAndWrongKey(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	u, _ := a.DB.UserByUsername(ctx, "test-admin")
	_, e := a.DB.SaveRecord(ctx, store.Record{Collection: "certificates", ID: "secret-cert", Data: map[string]any{"name": "fixture", "privateKey": "private-value-never-public"}})
	if e != nil {
		t.Fatal(e)
	}
	backup, e := a.createBackup(ctx, u)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(a.Config.DataDir, "backups", text(backup, "id")+".zip"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("private-value-never-public")) {
		t.Fatal("unencrypted database secret in backup")
	}

	source, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	var bad bytes.Buffer
	writer := zip.NewWriter(&bad)
	for _, f := range source.File {
		reader, _ := f.Open()
		data, _ := io.ReadAll(reader)
		reader.Close()
		if f.Name == "identity/data-encryption.key" {
			data = []byte(strings.Repeat("A", 43))
		}
		out, _ := writer.Create(f.Name)
		out.Write(data)
	}
	writer.Close()
	restore := func(data []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/backups/restore?confirm=restore", bytes.NewReader(data))
		req.Header.Set("MM-Authorization", token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	requireStatus(t, restore(bad.Bytes()), 400)
	rec, _ := a.DB.GetRecord(ctx, "certificates", "secret-cert")
	rec.Data["privateKey"] = "changed"
	if _, e = a.DB.SaveRecord(ctx, rec); e != nil {
		t.Fatal(e)
	}
	requireStatus(t, restore(raw), 200)
	rec, e = a.DB.GetRecord(ctx, "certificates", "secret-cert")
	if e != nil || text(rec.Data, "privateKey") != "private-value-never-public" {
		t.Fatalf("restore failed: %v", e)
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", token, nil), 401)
	login := controllerRequest(t, h, "POST", "/api/login", "", map[string]any{"username": "test-admin", "password": "test-admin-password-2026"})
	requireStatus(t, login, 200)

	u, _ = a.DB.UserByID(ctx, u.ID)
	if _, e = a.createBackup(ctx, u); e != nil {
		t.Fatal(e)
	}
}
func TestControllerKomariVersionBindingsAndNoAccounting(t *testing.T) {
	a, _, _ := controllerFixture(t)
	sampleTime := time.Now().UTC().Format(time.RFC3339Nano)
	online := true
	version := "1.2.5-fix2"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			respond(w, 200, map[string]any{"status": "success", "data": map[string]any{"version": version}})
			return
		}
		if r.Header.Get("Authorization") != "Bearer upstream-test-key" {
			w.WriteHeader(401)
			return
		}
		var call map[string]any
		json.NewDecoder(r.Body).Decode(&call)
		switch text(call, "method") {
		case "common:getNodes":
			respond(w, 200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"node-a": map[string]any{"uuid": "node-a", "name": "private name", "region": "🇺🇸", "token": "upstream-private"}}})
		case "common:getNodesLatestStatus":
			respond(w, 200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"node-a": map[string]any{"time": sampleTime, "cpu": 12.5, "ram": 100, "ram_total": 1000, "online": online, "net_total_down": 9999999}}})
		default:
			t.Errorf("non-read Komari method %q", call["method"])
			w.WriteHeader(400)
		}
	}))
	defer upstream.Close()
	ctx := context.Background()
	a.DB.SetSetting(ctx, "settings", map[string]any{"probeBaseUrl": upstream.URL, "probeApiKey": "upstream-test-key"})
	a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "bound", Data: map[string]any{"name": "bound", "komariUUID": "node-a"}})
	result, e := a.syncKomari(ctx, true)
	if e != nil || number(result, "saved") != 1 {
		t.Fatalf("sync: %v %#v", e, result)
	}
	obs, e := a.DB.GetRecord(ctx, "_komariObservations", "bound")
	if e != nil || number(obs.Data, "cpu_percent") != 12.5 {
		t.Fatal("wrong metric mapping")
	}
	if text(obs.Data, "region") != "🇺🇸" || number(obs.Data, "network_rx_bytes") != 9999999 {
		t.Fatal("Komari country or cumulative traffic was lost")
	}
	if _, exists := obs.Data["token"]; exists {
		t.Fatal("Komari credential copied into observation")
	}
	if strings.Contains(fmt.Sprint(result), "upstream-private") {
		t.Fatal("upstream credential exposed")
	}
	result, e = a.syncKomari(ctx, true)
	if e != nil || number(result, "saved") != 0 {
		t.Fatal("duplicate snapshot generated fake history")
	}
	online = false
	if _, e = a.syncKomari(ctx, true); e != nil {
		t.Fatal(e)
	}
	obs, e = a.DB.GetRecord(ctx, "_komariObservations", "bound")
	if e != nil || boolean(obs.Data, "online") {
		t.Fatal("offline update lost at unchanged sample timestamp")
	}
	metrics, e := a.DB.ListMetrics(ctx, "komari:bound", time.Now().Add(-time.Hour), 10)
	if e != nil || len(metrics) != 0 {
		t.Fatal("Komari history duplicated locally", e)
	}
	var count int
	a.DB.DB().QueryRow("SELECT COUNT(*) FROM traffic_ledger").Scan(&count)
	if count != 0 {
		t.Fatal("Komari modified billing")
	}
	version = "1.3.0"
	if _, e = a.syncKomari(ctx, true); e == nil {
		t.Fatal("unsupported version accepted")
	}
}
func TestControllerNotificationWebhookActualDelivery(t *testing.T) {
	a, _, _ := controllerFixture(t)
	received := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.HasPrefix(r.Header.Get("X-ASWired-Signature"), "sha256=") {
			t.Error("missing signed webhook")
		}
		received++
		w.WriteHeader(204)
	}))
	defer target.Close()
	ctx := context.Background()
	a.DB.SetSetting(ctx, "settings", map[string]any{"webhook": target.URL, "webhookSecret": "test-signing-secret"})
	u, _ := a.DB.UserByUsername(ctx, "test-admin")
	if _, e := a.notificationTest(ctx, u, "", nil); e != nil || received != 1 {
		t.Fatalf("delivery: %v", e)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func TestControllerRealAgentLifecycle(t *testing.T) {
	binary := os.Getenv("ASWIRED_TEST_AGENT")
	if binary == "" {
		t.Skip("set ASWIRED_TEST_AGENT to run the built Agent integration")
	}
	for _, transport := range []string{"websocket", "http", "pull", "auto-http", "auto-pull"} {
		t.Run(transport, func(t *testing.T) {
			a, handler, token := controllerFixture(t)
			mode := transport
			if strings.HasPrefix(mode, "auto-") {
				mode = "auto"
			}
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "auto" && r.URL.Path == "/api/agent/ws" {
					http.Error(w, "upgrade unavailable", 503)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer httpServer.Close()
			a.Config.PublicURL = httpServer.URL
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.Start(ctx)
			defer a.Close()
			proxyPort := freeTCPPort(t)
			agentPort := freeTCPPort(t)
			row := map[string]any{"id": "integration-node", "name": "integration", "address": "127.0.0.1", "connection": mode, "agentPort": agentPort, "xray_mode": "embedded"}
			if transport == "auto-pull" {
				unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "direct unavailable", 503) }))
				defer unreachable.Close()
				row["agentUrl"] = unreachable.URL
			}
			save := controllerRequest(t, handler, "POST", "/api/collections/servers", token, map[string]any{"row": row})
			requireStatus(t, save, 200)
			enrollment := controllerRequest(t, handler, "GET", "/api/servers/integration-node/enrollment", token, nil)
			requireStatus(t, enrollment, 200)
			cfg := responseMap(t, enrollment)["config"].(map[string]any)
			cfg["data_dir"] = filepath.Join(t.TempDir(), "agent-data")
			cfg["observation_interval"] = 1
			cfg["xray_config"] = filepath.Join(cfg["data_dir"].(string), "xray", "config.json")
			raw, _ := json.Marshal(cfg)
			configPath := filepath.Join(t.TempDir(), "agent.json")
			os.WriteFile(configPath, raw, 0600)
			cmd := exec.CommandContext(ctx, binary, "-config", configPath)
			var logs bytes.Buffer
			cmd.Stdout = &logs
			cmd.Stderr = &logs
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				cancel()
				_ = cmd.Wait()
				if t.Failed() {
					t.Log(logs.String())
				}
			}()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "actual-proxy-response") }))
			defer target.Close()
			apply := func(cfg any) store.Task {
				response := controllerRequest(t, handler, "POST", "/api/actions", token, map[string]any{"action": "core.config.apply", "targetId": "integration-node", "params": map[string]any{"config": cfg}})
				requireStatus(t, response, 202)
				id := text(responseMap(t, response)["task"].(map[string]any), "id")
				deadline := time.Now().Add(40 * time.Second)
				for time.Now().Before(deadline) {
					task, e := a.DB.GetTask(ctx, id)
					if e == nil && (task.Status == "success" || task.Status == "failed" || task.Status == "unsupported") {
						return task
					}
					time.Sleep(100 * time.Millisecond)
				}
				t.Fatalf("Agent did not finish %s command", transport)
				return store.Task{}
			}
			valid := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"tag": "test-socks", "listen": "127.0.0.1", "port": proxyPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
			if task := apply(valid); task.Status != "success" {
				t.Fatalf("apply failed: %s", task.Error)
			}
			wantTransport := map[string]string{"websocket": "WebSocket", "http": "HTTP", "pull": "Pull", "auto-http": "HTTP", "auto-pull": "Pull"}[transport]
			a.mu.Lock()
			actual := a.peers["integration-node"].Transport
			a.mu.Unlock()
			if actual != wantTransport {
				t.Fatalf("expected %s transport, got %s", wantTransport, actual)
			}
			if transport == "websocket" || transport == "pull" {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(agentPort)), time.Second)
				if err == nil {
					conn.Close()
					t.Fatal("outbound-only mode exposed management listener")
				}
			}
			proxyRequest := func() {
				conn, e := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(proxyPort), 3*time.Second)
				if e != nil {
					t.Fatal(e)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				conn.Write([]byte{5, 1, 0})
				reply := make([]byte, 2)
				if _, e = io.ReadFull(conn, reply); e != nil || reply[1] != 0 {
					t.Fatal("SOCKS auth failed")
				}
				_, portString, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
				p, _ := strconv.Atoi(portString)
				conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(p >> 8), byte(p)})
				response := make([]byte, 10)
				if _, e = io.ReadFull(conn, response); e != nil || response[1] != 0 {
					t.Fatal("SOCKS connect failed")
				}
				fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
				body, e := io.ReadAll(conn)
				if e != nil || !bytes.Contains(body, []byte("actual-proxy-response")) {
					t.Fatalf("no actual proxy result: %v", e)
				}
			}
			proxyRequest()
			if task := apply(map[string]any{"inbounds": []any{map[string]any{"protocol": "invalid-protocol"}}}); task.Status != "failed" {
				t.Fatal("invalid core config reported successful")
			}
			proxyRequest()
			if transport == "websocket" {
				for _, next := range []string{"pull", "http", "auto", "websocket"} {
					update := controllerRequest(t, handler, "PUT", "/api/collections/servers/integration-node", token, map[string]any{"row": map[string]any{"connection": next}})
					requireStatus(t, update, 200)
					if task := apply(valid); task.Status != "success" {
						t.Fatalf("switch to %s failed: %s", next, task.Error)
					}
					persisted, err := os.ReadFile(configPath)
					var local map[string]any
					if err != nil || json.Unmarshal(persisted, &local) != nil || local["connection_mode"] != next {
						t.Fatalf("switch to %s not persisted", next)
					}
					proxyRequest()
				}
			}
		})
	}
}
