package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func federationCall(t *testing.T, h http.Handler, path, token, origin string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	if token != "" {
		r.Header.Set("MM-Authorization", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	return w.Code, out
}

func TestLoginCallbackPKCEOriginAndSingleUse(t *testing.T) {
	a, user, _, token := identityFixture(t)
	mux := http.NewServeMux()
	a.registerFederation(mux)
	verifier := strings.Repeat("v", 48)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirect := "https://probe.example.test/callback"
	authorize := map[string]any{"redirect_uri": redirect, "code_challenge": challenge, "code_challenge_method": "S256", "state": strings.Repeat("s", 32)}
	status, out := federationCall(t, mux, "/api/auth/callback/authorize", token, "https://panel.example.test", authorize)
	if status != 200 {
		t.Fatal(status, out)
	}
	returned, e := url.Parse(out["redirect_url"].(string))
	if e != nil {
		t.Fatal(e)
	}
	if returned.Query().Get("token") != "" || returned.Query().Get("code") == "" {
		t.Fatal("callback URL exposed token or omitted code")
	}
	code := returned.Query().Get("code")
	exchange := map[string]any{"code": code, "code_verifier": verifier, "redirect_uri": redirect}
	status, _ = federationCall(t, mux, "/api/auth/callback/exchange", "", "https://evil.example.test", exchange)
	if status != 403 {
		t.Fatal("foreign origin accepted")
	}
	wrong := clone(exchange)
	wrong["code_verifier"] = strings.Repeat("w", 48)
	status, _ = federationCall(t, mux, "/api/auth/callback/exchange", "", "https://probe.example.test", wrong)
	if status != 401 {
		t.Fatal("wrong verifier accepted")
	}
	var success atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Go(func() {
			status, _ := federationCall(t, mux, "/api/auth/callback/exchange", "", "https://probe.example.test", exchange)
			if status == 200 {
				success.Add(1)
			} else if status != 401 {
				t.Errorf("unexpected exchange status %d", status)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("code was not consumed exactly once")
	}
	status, out = federationCall(t, mux, "/api/auth/callback/authorize", token, "https://panel.example.test", authorize)
	if status != 200 {
		t.Fatal(out)
	}
	returned, _ = url.Parse(out["redirect_url"].(string))
	exchange["code"] = returned.Query().Get("code")
	user.TokenVersion++
	if e = a.DB.UpdateUser(context.Background(), user); e != nil {
		t.Fatal(e)
	}
	status, _ = federationCall(t, mux, "/api/auth/callback/exchange", "", "https://probe.example.test", exchange)
	if status != 401 {
		t.Fatal("callback survived session revocation")
	}
}

func TestLoginCallbackRejectsUnapprovedOriginAndPlainPKCE(t *testing.T) {
	a, _, _, token := identityFixture(t)
	mux := http.NewServeMux()
	a.registerFederation(mux)
	for _, raw := range []string{"https://probe.example.test.evil.invalid/callback", "https://probe.example.test@evil.invalid/callback", "http://probe.example.test/callback"} {
		status, _ := federationCall(t, mux, "/api/auth/callback/authorize", token, "https://panel.example.test", map[string]any{"redirect_uri": raw})
		if status != 400 {
			t.Fatalf("unapproved callback accepted: %s", raw)
		}
	}
	status, _ := federationCall(t, mux, "/api/auth/callback/authorize", token, "https://panel.example.test", map[string]any{"redirect_uri": "https://probe.example.test/callback", "code_challenge": strings.Repeat("v", 43), "code_challenge_method": "plain", "state": strings.Repeat("s", 32)})
	if status != 400 {
		t.Fatal("plain PKCE accepted")
	}
}

func TestTwoControllerSelectedNodeFederationAndRevocation(t *testing.T) {
	owner, admin, _, _ := identityFixture(t)
	consumer, consumerAdmin, _, _ := identityFixture(t)
	ctx := context.Background()
	for _, id := range []string{"selected", "not-shared"} {
		data := realityClientFixtureData()
		data["name"], data["host"] = id, "example.test"
		data["privateKey"], data["agentToken"] = "never-share-reality-private", "never-share-agent-token"
		_, e := owner.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: id, Data: data})
		if e != nil {
			t.Fatal(e)
		}
	}
	mux := http.NewServeMux()
	owner.registerFederation(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	published, e := owner.federationAction(ctx, admin, actionInput{Action: "federation.publish", Params: map[string]any{"name": "test share", "nodeIds": []any{"selected"}}})
	if e != nil {
		t.Fatal(e)
	}
	response, e := http.Get(server.URL + "/api/federation/shares/" + text(published, "id") + "/nodes")
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("share feed exposed without token")
	}
	connected, e := consumer.federationAction(ctx, consumerAdmin, actionInput{Action: "federation.connect", Params: map[string]any{"name": "peer", "ownerUrl": server.URL, "shareId": published["id"], "token": published["token"]}})
	if e != nil {
		t.Fatal(e)
	}
	nodes, e := consumer.DB.ListRecords(ctx, "nodes", "")
	if e != nil || len(nodes) != 1 {
		t.Fatal("scope did not restrict imported nodes", e)
	}
	if nodes[0].Data["privateKey"] != nil || nodes[0].Data["agentToken"] != nil || text(nodes[0].Data, "uuid") == "" {
		t.Fatal("node projection exposed management secrets or removed authorized node credential")
	}
	views, _ := consumer.DB.ListRecords(ctx, "shares", "")
	for _, view := range views {
		if view.Data["token"] != nil {
			t.Fatal("consumer token leaked into UI records")
		}
	}
	_, e = owner.federationAction(ctx, admin, actionInput{Action: "federation.revoke", TargetID: text(published, "id")})
	if e != nil {
		t.Fatal(e)
	}
	_, e = consumer.federationAction(ctx, consumerAdmin, actionInput{Action: "federation.sync", TargetID: text(connected, "id")})
	if e == nil {
		t.Fatal("revoked share still synchronized")
	}
	cached, _ := consumer.DB.GetRecord(ctx, "nodes", nodes[0].ID)
	if !boolean(cached.Data, "federationStale") {
		t.Fatal("disconnected cache presented as live")
	}
	if _, e = owner.DB.GetRecord(ctx, "nodes", "selected"); e != nil {
		t.Fatal("share revocation deleted owner node")
	}
	if _, e = owner.federationAction(ctx, store.User{ID: "member", Role: "user"}, actionInput{Action: "federation.publish", Params: map[string]any{"nodeIds": []any{"selected"}}}); e == nil {
		t.Fatal("ordinary member could publish admin nodes")
	}
}
