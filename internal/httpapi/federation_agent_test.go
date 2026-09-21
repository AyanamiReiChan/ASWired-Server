package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func TestTwoControllersOpaqueAgentFederation(t *testing.T) {
	binary := os.Getenv("ASWIRED_TEST_AGENT")
	if binary == "" {
		t.Skip("set ASWIRED_TEST_AGENT for the real Agent integration")
	}
	owner, ownerHandler, ownerToken := controllerFixture(t)
	consumer, consumerHandler, _ := controllerFixture(t)
	ownerHTTP := httptest.NewServer(ownerHandler)
	defer ownerHTTP.Close()
	owner.Config.PublicURL = ownerHTTP.URL
	consumerHTTP := httptest.NewServer(consumerHandler)
	defer consumerHTTP.Close()
	consumer.Config.PublicURL = consumerHTTP.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner.Start(ctx)
	defer owner.Close()
	admin, _ := owner.DB.UserByUsername(ctx, "test-admin")
	consumerAdmin, _ := consumer.DB.UserByUsername(ctx, "test-admin")
	nodeID := "federation-node"
	response := controllerRequest(t, ownerHandler, "POST", "/api/collections/servers", ownerToken, map[string]any{"row": map[string]any{"id": nodeID, "name": "owner node", "address": "127.0.0.1", "connection": "websocket", "xray_mode": "embedded"}})
	requireStatus(t, response, 200)
	enrollment := controllerRequest(t, ownerHandler, "GET", "/api/servers/"+nodeID+"/enrollment", ownerToken, nil)
	requireStatus(t, enrollment, 200)
	cfg := responseMap(t, enrollment)["config"].(map[string]any)
	cfg["data_dir"] = filepath.Join(t.TempDir(), "agent-data")
	cfg["xray_config"] = filepath.Join(cfg["data_dir"].(string), "xray", "config.json")
	cfg["observation_interval"] = 1
	raw, _ := json.Marshal(cfg)
	configPath := filepath.Join(t.TempDir(), "agent.json")
	if e := os.WriteFile(configPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	agentCtx, stopAgent := context.WithCancel(ctx)
	defer stopAgent()
	cmd := exec.CommandContext(agentCtx, binary, "-config", configPath)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		stopAgent()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	coreCfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "stats": map[string]any{}, "inbounds": []any{map[string]any{"tag": "owner-vless", "listen": "127.0.0.1", "port": freeTCPPort(t), "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"email": "owner-user", "id": "11111111-1111-4111-8111-111111111111"}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	apply, e := owner.queue(ctx, admin, nodeID, "core.config.apply", map[string]any{"config": coreCfg})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = owner.waitFederationTask(ctx, apply.ID, 40*time.Second); e != nil {
		t.Fatal(e)
	}
	published, e := owner.federationAgentAction(ctx, admin, actionInput{Action: "federation.agent.publish", TargetID: nodeID, Params: map[string]any{"consumerPublicKey": consumer.MasterPublic, "namespace": "tenantA", "inbounds": map[string]any{"main": "owner-vless"}, "actions": []any{"status.get", "inbound.users.sync", "inbound.users.get", "stats.get"}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = owner.waitFederationTask(ctx, text(published, "install_task_id"), 40*time.Second); e != nil {
		t.Fatal(e)
	}
	shareID, shareToken := text(published, "id"), text(published, "token")
	connected, e := consumer.federationAgentAction(ctx, consumerAdmin, actionInput{Action: "federation.agent.connect", Params: map[string]any{"ownerUrl": ownerHTTP.URL, "shareId": shareID, "token": shareToken}})
	if e != nil {
		t.Fatal(e)
	}
	connectionID := text(connected, "id")
	submit := func(action string, params map[string]any) map[string]any {
		t.Helper()
		out, e := consumer.federationAgentAction(ctx, consumerAdmin, actionInput{Action: "federation.agent.execute", TargetID: connectionID, Params: map[string]any{"action": action, "params": params}})
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	finish := func(requestID string) agentwire.Result {
		t.Helper()
		deadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(deadline) {
			out, e := consumer.federationAgentAction(ctx, consumerAdmin, actionInput{Action: "federation.agent.result", TargetID: requestID})
			if e != nil {
				t.Fatal(e)
			}
			if !boolean(out, "pending") {
				var result agentwire.Result
				b, _ := json.Marshal(out["result"])
				if e = json.Unmarshal(b, &result); e != nil {
					t.Fatal(e)
				}
				if result.Status != "success" {
					t.Fatalf("operation failed: %#v", result)
				}
				return result
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("federation operation timed out")
		return agentwire.Result{}
	}
	submitted := submit("inbound.users.sync", map[string]any{"inbound": "main", "users": []any{map[string]any{"email": "consumer-private-member", "id": "22222222-2222-4222-8222-222222222222"}}})

	task, e := owner.DB.GetTask(ctx, text(submitted, "owner_job_id"))
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"consumer-private-member", "22222222-2222-4222-8222-222222222222", "inbound.users.sync"} {
		if bytes.Contains(task.Input, []byte(secret)) {
			t.Fatalf("owner saw consumer payload %s", secret)
		}
	}
	if !owner.federationTaskPermitted(ctx, task) {
		t.Fatal("valid request rejected before dispatch")
	}
	result := finish(text(submitted, "request_id"))
	if result.Data["applied"] != true {
		t.Fatalf("not actually applied: %#v", result)
	}
	task, e = owner.DB.GetTask(ctx, task.ID)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(task.Result, []byte("namespace")) {
		t.Fatal("plaintext consumer result persisted by owner")
	}
	got := finish(text(submit("inbound.users.get", map[string]any{"inbound": "main"}), "request_id"))
	b, _ := json.Marshal(got.Data)
	if !bytes.Contains(b, []byte("tenantA.consumer-private-member")) || bytes.Contains(b, []byte("owner-user")) {
		t.Fatalf("namespace isolation failed: %s", b)
	}

	synced, e := owner.queue(ctx, admin, nodeID, "core.users.sync", map[string]any{"inbound": "owner-vless", "users": []any{map[string]any{"email": "owner-user", "id": "11111111-1111-4111-8111-111111111111"}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = owner.waitFederationTask(ctx, synced.ID, 40*time.Second); e != nil {
		t.Fatal(e)
	}
	got = finish(text(submit("inbound.users.get", map[string]any{"inbound": "main"}), "request_id"))
	b, _ = json.Marshal(got.Data)
	if !bytes.Contains(b, []byte("tenantA.consumer-private-member")) {
		t.Fatal("owner synchronization erased consumer")
	}
	if _, e = consumer.federationAgentAction(ctx, consumerAdmin, actionInput{Action: "federation.agent.execute", TargetID: connectionID, Params: map[string]any{"action": "core.stop"}}); e == nil {
		t.Fatal("global core operation accepted")
	}
	denied := httptest.NewRequest("GET", "/api/federation/agent/"+shareID, nil)
	denied.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	ownerHandler.ServeHTTP(rec, denied)
	requireStatus(t, rec, http.StatusForbidden)

	stopAgent()
	revoked, e := owner.federationAgentAction(ctx, admin, actionInput{Action: "federation.agent.revoke", TargetID: shareID})
	if e != nil {
		t.Fatal(e)
	}
	if revoked["revoked"] != true {
		t.Fatal("owner revocation failed")
	}
	if owner.federationTaskPermitted(ctx, task) {
		t.Fatal("queued old grant survived revocation")
	}
	if _, e = consumer.federationAgentAction(ctx, consumerAdmin, actionInput{Action: "federation.agent.execute", TargetID: connectionID, Params: map[string]any{"action": "status.get"}}); e == nil || !strings.Contains(e.Error(), "403") {
		t.Fatalf("offline revocation accepted or fell back: %v", e)
	}

	if _, e = owner.DB.GetRecord(ctx, "servers", nodeID); e != nil {
		t.Fatal(e)
	}
	privateRecords, e := consumer.DB.ListRecords(ctx, "_federationAgentRequests", "")
	if e != nil || len(privateRecords) == 0 {
		t.Fatal("consumer result not persisted")
	}
}
