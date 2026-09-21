package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func TestControllerRealAgentAuxiliaryRawClientCompatibility(t *testing.T) {
	agentBinary, mihomo := os.Getenv("ASWIRED_TEST_AGENT"), os.Getenv("ASWIRED_TEST_MIHOMO")
	if agentBinary == "" || mihomo == "" {
		t.Skip("set ASWIRED_TEST_AGENT and ASWIRED_TEST_MIHOMO for actual auxiliary end-to-end validation")
	}
	home := os.Getenv("ASWIRED_TEST_HOME")
	if home == "" {
		name := "aswired-speedtest"
		if strings.HasSuffix(agentBinary, ".exe") {
			name += ".exe"
		}
		home = filepath.Join(filepath.Dir(agentBinary), name)
	}
	if _, e := os.Stat(home); e != nil {
		t.Fatal("build the matching aswired-speedtest CLI or set ASWIRED_TEST_HOME")
	}
	const hash = "1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b"
	a, h, jwt := controllerFixture(t)
	server := httptest.NewServer(h)
	defer server.Close()
	a.Config.PublicURL = server.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Start(ctx)
	defer a.Close()
	admin, e := a.DB.UserByUsername(ctx, "test-admin")
	if e != nil {
		t.Fatal(e)
	}
	created := controllerRequest(t, h, "POST", "/api/collections/servers", jwt, map[string]any{"row": map[string]any{"id": "aux-node", "name": "actual-aux", "address": "127.0.0.1", "connection": "websocket", "xray_mode": "embedded"}})
	requireStatus(t, created, 200)
	enrolled := controllerRequest(t, h, "GET", "/api/servers/aux-node/enrollment", jwt, nil)
	requireStatus(t, enrolled, 200)
	cfg := responseMap(t, enrolled)["config"].(map[string]any)
	dir := t.TempDir()
	cfg["data_dir"] = filepath.Join(dir, "agent")
	cfg["xray_config"] = filepath.Join(dir, "agent", "xray.json")
	cfg["mihomo_binary"] = mihomo
	cfg["mihomo_version"] = "v1.19.31"
	cfg["mihomo_sha256"] = hash
	cfg["observation_interval"] = 1
	write := func(path string, v any) {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	configPath := filepath.Join(dir, "agent.json")
	write(configPath, cfg)
	cmd := exec.CommandContext(ctx, agentBinary, "-config", configPath)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	wait := func(id string) store.Task {
		t.Helper()
		until := time.Now().Add(50 * time.Second)
		for time.Now().Before(until) {
			task, e := a.DB.GetTask(ctx, id)
			if e == nil && (task.Status == "success" || task.Status == "failed" || task.Status == "unsupported") {
				if task.Status != "success" {
					t.Fatalf("%s failed: %s", task.Kind, task.Error)
				}
				return task
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("real encrypted Agent task timed out")
		return store.Task{}
	}
	queue := func(action string, params map[string]any) store.Task {
		t.Helper()
		task, e := a.queue(ctx, admin, "aux-node", action, params)
		if e != nil {
			t.Fatal(e)
		}
		return wait(task.ID)
	}
	defer func() {
		stop, e := a.queue(context.Background(), admin, "aux-node", "mihomo.stop", nil)
		if e == nil {
			until := time.Now().Add(12 * time.Second)
			for time.Now().Before(until) {
				task, _ := a.DB.GetTask(context.Background(), stop.ID)
				if task.Status == "success" {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	deployed := queue("certificate.deploy", map[string]any{"name": "aux-local-test", "certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))})
	var paths map[string]any
	json.Unmarshal(deployed.Result, &paths)
	if e = a.DB.CreateUser(ctx, store.User{ID: "aux-member", Username: "aux-member", Role: "user", PasswordHash: "test-only-hash"}); e != nil {
		t.Fatal(e)
	}
	if _, e = a.DB.SaveRecord(ctx, store.Record{Collection: "plans", ID: "aux-plan", Data: map[string]any{"name": "Aux test plan", "status": "已发布", "limit": 10, "speed": 2.097152, "cycleDays": 30}}); e != nil {
		t.Fatal(e)
	}
	subData := map[string]any{"name": "Aux instance", "memberId": "aux-member", "planId": "aux-plan", "status": "启用"}
	owner, e := a.prepareSubscription(httptest.NewRequest("POST", "/", nil), "aux-sub", subData, false)
	if e != nil {
		t.Fatal(e)
	}
	sub, e := a.DB.SaveRecord(ctx, store.Record{Collection: "subscriptions", ID: "aux-sub", OwnerID: owner, Data: subData})
	if e != nil {
		t.Fatal(e)
	}
	bridges := []any{}
	listeners := []any{}
	for _, kind := range []string{"anytls", "snell"} {
		port, bridgePort := freeTCPPort(t), freeTCPPort(t)
		email := text(sub.Data, "credentialEmail") + ".actual-" + kind
		bridges = append(bridges, map[string]any{"tag": "manual-bridge-" + kind, "listen": "127.0.0.1", "port": bridgePort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": text(sub.Data, "credentialUUID"), "email": email, "level": 0}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}})
		listener := map[string]any{"name": "manual-" + kind, "type": kind, "listen": "127.0.0.1", "port": port, "udp": false, "users": []any{map[string]any{"email": email, "password": text(sub.Data, "credentialPassword"), "bridge": map[string]any{"port": bridgePort, "id": text(sub.Data, "credentialUUID")}}}}
		node := map[string]any{"name": kind, "protocol": kind, "host": "127.0.0.1", "port": port, "password": text(sub.Data, "credentialPassword"), "status": "启用", "network": "tcp", "security": "none", "snellVersion": 4}
		if kind == "anytls" {
			listener["certificate"] = paths["certificate_path"]
			listener["private_key"] = paths["private_key_path"]
			node["security"] = "tls"
			node["sni"] = "localhost"
			node["skip-cert-verify"] = true
		} else {
			listener["version"] = 4
		}
		listeners = append(listeners, listener)
		if _, e = a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "external-" + kind, Data: node}); e != nil {
			t.Fatal(e)
		}
	}
	queue("core.config.apply", map[string]any{"config": map[string]any{"log": map[string]any{"loglevel": "warning"}, "stats": map[string]any{}, "policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}}, "inbounds": bridges, "outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}}}})
	queue("mihomo.config.apply", map[string]any{"listeners": listeners})
	var requests atomic.Int64
	payload := bytes.Repeat([]byte("controller-agent-client"), 4096)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.Write(payload) }))
	defer target.Close()
	homeConfig := filepath.Join(dir, "home.json")
	write(homeConfig, map[string]any{"mihomo_binary": mihomo, "mihomo_version": "v1.19.31", "mihomo_sha256": hash, "data_dir": filepath.Join(dir, "home"), "server_id": "local-client-validation"})
	measure := func(node map[string]any) agentwire.Result {
		t.Helper()
		commandPath := filepath.Join(dir, "measurement.json")
		write(commandPath, map[string]any{"id": "actual", "action": "speedtest.run", "params": map[string]any{"node": node, "url": target.URL, "duration_seconds": 3, "parallel": 1}})
		cctx, ccancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer ccancel()
		output, e := exec.CommandContext(cctx, home, "-config", homeConfig, "-command", commandPath).Output()
		if e != nil {
			t.Fatalf("generated client node did not proxy: %v %s", e, output)
		}
		var result agentwire.Result
		if e = json.Unmarshal(output, &result); e != nil {
			t.Fatal(e)
		}
		if result.Status != "success" || number(result.Data, "download_bytes") <= 0 {
			t.Fatalf("no actual generated subscription payload: %+v", result)
		}
		return result
	}
	for _, kind := range []string{"anytls", "snell"} {
		node, e := a.DB.GetRecord(ctx, "nodes", "external-"+kind)
		if e != nil {
			t.Fatal(e)
		}
		client, e := clientNodeFor(node, sub)
		if e != nil {
			t.Fatal(e)
		}
		measure(clashNode(client))
	}
	statsTask := queue("core.stats", nil)
	var stats map[string]any
	json.Unmarshal(statsTask.Result, &stats)
	counters, _ := stats["counters"].(map[string]any)
	for _, kind := range []string{"anytls", "snell"} {
		email := text(sub.Data, "credentialEmail") + ".actual-" + kind
		if number(counters, "user>>>"+email+">>>traffic>>>downlink") <= 0 {
			t.Fatalf("generated %s bridge did not emit attributable Xray user bytes", kind)
		}
	}
	if requests.Load() == 0 {
		t.Fatal("no HTTP target traffic")
	}
}
