package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func TestInstallEnrollmentIsScopedExpiringAndRevocable(t *testing.T) {
	a, h, admin := controllerFixture(t)
	create := controllerRequest(t, h, "POST", "/api/collections/servers", admin, map[string]any{"row": map[string]any{"id": "install-node", "name": "node ' $(touch unsafe)", "address": "192.0.2.10", "connection": "WebSocket"}})
	requireStatus(t, create, 200)
	path := "/api/servers/install-node/enrollment"
	requireStatus(t, controllerRequest(t, h, "GET", path, "", nil), 401)
	missing := responseMap(t, controllerRequest(t, h, "GET", path, admin, nil))
	if missing["installation"].(map[string]any)["available"] != false {
		t.Fatal("offered nonexistent package")
	}
	artifact := []byte("controlled test artifact")
	if err := os.MkdirAll(filepath.Dir(a.agentArtifact("amd64")), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.agentArtifact("amd64"), artifact, 0600); err != nil {
		t.Fatal(err)
	}
	enroll := controllerRequest(t, h, "GET", path, admin, nil)
	requireStatus(t, enroll, 200)
	if enroll.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credentials may be cached")
	}
	data := responseMap(t, enroll)
	cfg := data["config"].(map[string]any)
	if cfg["connection_mode"] != "websocket" || cfg["xray_mode"] != "embedded" || cfg["listen_address"] != "0.0.0.0:23889" || cfg["listen_port"] != nil {
		t.Fatalf("incorrect agent config: %+v", cfg)
	}
	offer := data["installation"].(map[string]any)
	if offer["available"] != true || offer["localOnly"] != true || !strings.Contains(text(offer, "command"), "curl -fSsL") {
		t.Fatal("missing installation offer")
	}
	cred, err := a.DB.GetRecord(context.Background(), "_agentCredentials", "install-node")
	if err != nil {
		t.Fatal(err)
	}
	expires := strconv.FormatInt(time.Now().Add(20*time.Minute).Unix(), 10)
	ticket := a.installTicket("install-node", expires, cred)
	download := "/api/agent/install/install-node/"
	request := func(file, ticket string) int {
		return controllerRequest(t, h, "GET", download+file+"?ticket="+url.QueryEscape(ticket), "", nil).Code
	}
	for _, invalid := range []string{"", ticket + "tampered", a.installTicket("other-node", expires, cred), a.installTicket("install-node", strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10), cred)} {
		if request("install.sh", invalid) != 403 {
			t.Fatal("invalid installer ticket accepted")
		}
	}
	script := controllerRequest(t, h, "GET", download+"install.sh?ticket="+url.QueryEscape(ticket), "", nil)
	requireStatus(t, script, 200)
	body := script.Body.String()
	if strings.Contains(body, "@@") || !strings.Contains(body, a.artifactHash("amd64")) || !strings.Contains(body, "sha256sum -c -") || !strings.Contains(body, "refusing to overwrite") || strings.Contains(body, "$(touch unsafe)") {
		t.Fatal("unsafe or incomplete installer")
	}
	raw, _ := json.Marshal(cfg)
	if !strings.Contains(body, base64.StdEncoding.EncodeToString(raw)) {
		t.Fatal("installer did not carry selected configuration")
	}
	binary := controllerRequest(t, h, "GET", download+"linux-amd64?ticket="+url.QueryEscape(ticket), "", nil)
	requireStatus(t, binary, 200)
	if binary.Body.String() != string(artifact) {
		t.Fatal("wrong artifact")
	}
	if request("linux-arm64", ticket) != 404 || request("jwt.key", ticket) != 404 {
		t.Fatal("unexpected file exposed")
	}
	if err = a.DB.SetSetting(context.Background(), "settings", map[string]any{"silentMode": true, "entryKey": "fixture-entry-secret-more-than-24"}); err != nil {
		t.Fatal(err)
	}
	if request("install.sh", ticket) != 200 || request("install.sh", "invalid") != 403 {
		t.Fatal("silent entry interfered with scoped installer authentication")
	}
	server, err := a.DB.GetRecord(context.Background(), "servers", "install-node")
	if err != nil {
		t.Fatal(err)
	}
	server.Data["status"] = "禁用"
	server, err = a.DB.SaveRecord(context.Background(), server)
	if err != nil {
		t.Fatal(err)
	}
	if request("install.sh", ticket) != 403 {
		t.Fatal("disabled server can install")
	}
	server.Data["status"] = "待接入"
	if _, err = a.DB.SaveRecord(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	cred.Data["agentToken"] = "rotated"
	if _, err = a.DB.SaveRecord(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if request("install.sh", ticket) != 403 {
		t.Fatal("rotation did not revoke installer")
	}
}

func TestOnlyEmbeddedCoreCanBeRegisteredOrDispatched(t *testing.T) {
	a, h, admin := controllerFixture(t)
	create := controllerRequest(t, h, "POST", "/api/collections/servers", admin, map[string]any{"row": map[string]any{"id": "node", "name": "node", "address": "192.0.2.1", "xray_mode": "external"}})
	requireStatus(t, create, 400)
	create = controllerRequest(t, h, "POST", "/api/collections/servers", admin, map[string]any{"row": map[string]any{"id": "node", "name": "node", "address": "192.0.2.1"}})
	requireStatus(t, create, 200)
	if responseMap(t, create)["row"].(map[string]any)["xray_mode"] != "embedded" {
		t.Fatal("wrong default")
	}
	cred, _ := a.DB.GetRecord(context.Background(), "_agentCredentials", "node")
	if _, err := a.acceptReport(context.Background(), agentwire.Report{ServerID: "node", Token: text(cred.Data, "serverToken"), Mode: "external", Timestamp: time.Now().Unix()}, "WebSocket"); err == nil {
		t.Fatal("external report accepted")
	}
	task := storedAgentTask(t, a, "node", "old-migration", "core.mode.migrate", "core.mode.migrate")
	if a.permitDispatch(context.Background(), task) {
		t.Fatal("persisted mode migration was dispatched")
	}
	server, _ := a.DB.GetRecord(context.Background(), "servers", "node")
	server.Data["xray_mode"] = "external"
	if nativeServer(server) {
		t.Fatal("legacy external server remains dispatchable")
	}
	if got := shellQuote("https://example.test/a'b$(id)"); got != "'https://example.test/a'\"'\"'b$(id)'" {
		t.Fatal("unsafe shell quoting", got)
	}
}
