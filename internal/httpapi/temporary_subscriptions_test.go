package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func temporaryFixture(t *testing.T) (*App, store.Record, http.Handler, string) {
	t.Helper()
	a, sub := subscriptionFixture(t)
	mux := http.NewServeMux()
	a.registerTemporarySubscriptions(mux)
	u, e := a.DB.UserByID(context.Background(), sub.OwnerID)
	if e != nil {
		t.Fatal(e)
	}
	jwt, e := a.Signer.Issue(u.ID, u.TokenVersion)
	if e != nil {
		t.Fatal(e)
	}
	return a, sub, mux, jwt
}
func temporaryCall(h http.Handler, method, path, jwt string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.RemoteAddr = "192.0.2.8:12345"
	r.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		r.Header.Set("MM-Authorization", jwt)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func temporaryLink(t *testing.T, h http.Handler, jwt, node string, uses int) map[string]any {
	t.Helper()
	w := temporaryCall(h, "POST", "/api/temporary-subscriptions", jwt, map[string]any{"subscriptionId": "subscription", "nodeId": node, "expiresInSeconds": 3600, "maxUses": uses})
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}
func TestTemporarySubscriptionsAtomicFinalUseAndRedactedList(t *testing.T) {
	a, _, h, jwt := temporaryFixture(t)
	out := temporaryLink(t, h, jwt, "ss-node", 1)
	link := out["url"].(string)
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := temporaryCall(h, "GET", link+"&format=clash", "", nil)
			if w.Code == 200 {
				success.Add(1)
				if !strings.Contains(w.Body.String(), "Test Reality") {
					t.Error("rendered wrong node")
				}
			} else if w.Code != 403 && w.Code != 409 {
				t.Errorf("unexpected response %d %s", w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("last use served %d times", success.Load())
	}
	rec, e := a.DB.GetRecord(context.Background(), temporaryCollection, out["row"].(map[string]any)["id"].(string))
	if e != nil || number(rec.Data, "used") != 1 {
		t.Fatal("counter not atomic", e)
	}
	list := temporaryCall(h, "GET", "/api/temporary-subscriptions", jwt, nil)
	if list.Code != 200 || strings.Contains(list.Body.String(), out["token"].(string)) || strings.Contains(list.Body.String(), "parentTokenHash") || strings.Contains(list.Body.String(), text(realityClientFixtureData(), "uuid")) {
		t.Fatalf("list leaked credential: %s", list.Body.String())
	}
	if strings.Contains(link, "subscription=") || len(out["token"].(string)) < 48 {
		t.Fatal("guessable link")
	}
}
func TestTemporarySubscriptionsFailedRenderHeadAndFormatSharing(t *testing.T) {
	a, sub, h, jwt := temporaryFixture(t)
	ctx := context.Background()
	_, e := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "inbound-test", Data: map[string]any{"name": "Managed Reality", "serverId": "server", "protocol": "VLESS", "transport": "TCP / Reality", "status": "启用"}})
	if e != nil {
		t.Fatal(e)
	}
	managed := realityClientFixtureData()
	managed["name"], managed["host"], managed["managedInbound"] = "Managed Reality", "node.example.test", true
	managed["uuid"], managed["inboundId"] = "unshared-admin-uuid", "inbound-test"
	_, e = a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "managed-node", Data: managed})
	if e != nil {
		t.Fatal(e)
	}
	out := temporaryLink(t, h, jwt, "managed-node", 3)
	link := out["url"].(string)
	if w := temporaryCall(h, "HEAD", link, "", nil); w.Code != 405 {
		t.Fatal("HEAD redeemed link")
	}
	if w := temporaryCall(h, "GET", link+"&format=surge", "", nil); w.Code != 422 {
		t.Fatal("unsupported protocol rendered", w.Code)
	}
	rec, _ := a.DB.GetRecord(ctx, temporaryCollection, out["row"].(map[string]any)["id"].(string))
	if number(rec.Data, "used") != 0 {
		t.Fatal("failed render spent a use")
	}
	for _, format := range []string{"clash", "singbox", "v2ray"} {
		w := temporaryCall(h, "GET", link+"&format="+format, "", nil)
		if w.Code != 200 {
			t.Fatalf("format %s failed: %d %s", format, w.Code, w.Body.String())
		}
		if format != "v2ray" && (!strings.Contains(w.Body.String(), text(sub.Data, "credentialUUID")) || strings.Contains(w.Body.String(), "unshared-admin-uuid") || strings.Contains(w.Body.String(), "Test Reality")) {
			t.Fatal("source credentials or node scope changed")
		}
	}
}
func TestTemporarySubscriptionsOwnershipExpiryRevocationAndCurrentPermission(t *testing.T) {
	a, sub, h, jwt := temporaryFixture(t)
	ctx := context.Background()
	admin, _ := a.DB.UserByID(ctx, "admin")
	adminJWT, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	body := map[string]any{"subscriptionId": sub.ID, "nodeId": "ss-node", "expiresInSeconds": 3600, "maxUses": 2}
	if w := temporaryCall(h, "POST", "/api/temporary-subscriptions", adminJWT, body); w.Code != 403 {
		t.Fatal("admin minted another owner's temporary credentials")
	}
	body["nodeId"] = "not-authorized"
	if w := temporaryCall(h, "POST", "/api/temporary-subscriptions", jwt, body); w.Code != 403 {
		t.Fatal("out-of-scope node granted")
	}
	out := temporaryLink(t, h, jwt, "ss-node", 10)
	id := out["row"].(map[string]any)["id"].(string)
	link := out["url"].(string)
	if w := temporaryCall(h, "DELETE", "/api/temporary-subscriptions/"+id, adminJWT, nil); w.Code != 404 {
		t.Fatal("cross-owner revoke allowed")
	}
	sub.Data["whitelist"] = "198.51.100.0/24"
	sub, _ = a.DB.SaveRecord(ctx, sub)
	if w := temporaryCall(h, "GET", link, "", nil); w.Code != 403 {
		t.Fatal("temporary bypassed source whitelist")
	}
	sub.Data["whitelist"] = ""
	sub.Data["expires"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
	sub, _ = a.DB.SaveRecord(ctx, sub)
	if w := temporaryCall(h, "GET", link, "", nil); w.Code != 403 {
		t.Fatal("temporary outlived source subscription")
	}
	sub.Data["expires"] = ""
	sub.Data["token"] = "rotated-source-token"
	sub, _ = a.DB.SaveRecord(ctx, sub)
	if w := temporaryCall(h, "GET", link, "", nil); w.Code != 403 {
		t.Fatal("temporary survived source token rotation")
	}
	fresh := temporaryLink(t, h, jwt, "ss-node", 10)
	freshID := fresh["row"].(map[string]any)["id"].(string)
	if w := temporaryCall(h, "DELETE", "/api/temporary-subscriptions/"+freshID, jwt, nil); w.Code != 200 {
		t.Fatal("owner could not revoke")
	}
	if w := temporaryCall(h, "GET", fresh["url"].(string), "", nil); w.Code != 403 {
		t.Fatal("revoked link accepted")
	}
	expired := temporaryLink(t, h, jwt, "ss-node", 10)
	rec, _ := a.DB.GetRecord(ctx, temporaryCollection, expired["row"].(map[string]any)["id"].(string))
	rec.Data["expiresAt"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
	_, _ = a.DB.SaveRecord(ctx, rec)
	if w := temporaryCall(h, "GET", expired["url"].(string), "", nil); w.Code != 403 {
		t.Fatal("expired temporary link accepted")
	}
}

func TestTemporarySubscriptionsInheritQuotaAndNodeWithdrawal(t *testing.T) {
	a, sub, h, jwt := temporaryFixture(t)
	ctx := context.Background()
	sub.Data["expires"] = time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)
	sub, e := a.DB.SaveRecord(ctx, sub)
	if e != nil {
		t.Fatal(e)
	}
	out := temporaryLink(t, h, jwt, "ss-node", 2)
	link := out["url"].(string)
	row := out["row"].(map[string]any)
	if dateTime(row["expiresAt"].(string)).After(dateTime(text(sub.Data, "expires"))) {
		t.Fatal("temporary TTL exceeded package expiry")
	}
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["nodeIds"] = []any{"another-node"}
	plan, _ = a.DB.SaveRecord(ctx, plan)
	if w := temporaryCall(h, "GET", link, "", nil); w.Code != 403 {
		t.Fatal("withdrawn node still distributed", w.Code)
	}
	plan.Data["nodeIds"] = []any{"ss-node"}
	_, _ = a.DB.SaveRecord(ctx, plan)
	if e = a.ensureTrafficSchema(ctx); e != nil {
		t.Fatal(e)
	}
	_, e = a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), "temporary-quota", "server", sub.ID, sub.OwnerID, "fixture", "downlink", int64(11*gib), 1, 11*gib, time.Now().UnixMilli(), 0, "")
	if e != nil {
		t.Fatal(e)
	}
	if w := temporaryCall(h, "GET", link, "", nil); w.Code != 403 {
		t.Fatal("temporary bypassed exhausted quota", w.Code, w.Body.String())
	}
	record, _ := a.DB.GetRecord(ctx, temporaryCollection, row["id"].(string))
	if number(record.Data, "used") != 0 {
		t.Fatal("permission failures consumed downloads")
	}
}
