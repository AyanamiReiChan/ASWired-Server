package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func qrFixture(t *testing.T) (*App, http.Handler, string) {
	a, _, _, token := identityFixture(t)
	mux := http.NewServeMux()
	a.registerQRIdentity(mux)
	return a, mux, token
}
func qrBegin(t *testing.T, h http.Handler) (map[string]any, string) {
	t.Helper()
	status, start := identityCall(t, h, "/api/auth/qr/start", "", map[string]any{"deviceName": "Fixture desktop"})
	if status != 200 {
		t.Fatal(status, start)
	}
	u, e := url.Parse(start["qrURL"].(string))
	if e != nil {
		t.Fatal(e)
	}
	if u.Query().Get("pollSecret") != "" || u.Query().Get("token") != "" {
		t.Fatal("QR URL contains a login credential")
	}
	return start, u.Query().Get("code")
}
func TestQRIdentityOriginalBrowserOnlyAndExactlyOnce(t *testing.T) {
	_, h, phoneJWT := qrFixture(t)
	start, nonce := qrBegin(t, h)
	poll := map[string]any{"requestId": start["requestId"], "pollSecret": start["pollSecret"]}
	status, pending := identityCall(t, h, "/api/auth/qr/poll", "", poll)
	if status != 200 || pending["status"] != "pending" {
		t.Fatal(status, pending)
	}
	approve := map[string]any{"code": nonce, "confirmed": true, "verificationCode": start["verificationCode"]}
	status, _ = identityCall(t, h, "/api/auth/qr/approve", "", approve)
	if status != 401 {
		t.Fatal("unauthed phone approved", status)
	}
	status, result := identityCall(t, h, "/api/auth/qr/approve", phoneJWT, approve)
	if status != 200 || result["token"] != nil {
		t.Fatal("phone received JWT or approval failed", status, result)
	}
	status, _ = identityCall(t, h, "/api/auth/qr/poll", "", map[string]any{"requestId": start["requestId"], "pollSecret": nonce})
	if status != 401 {
		t.Fatal("QR nonce replaced browser secret")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, result := identityCall(t, h, "/api/auth/qr/poll", "", poll)
			if status == 200 && result["token"] != nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("issued %d JWTs", successes.Load())
	}
	status, _ = identityCall(t, h, "/api/auth/qr/poll", "", poll)
	if status == 200 {
		t.Fatal("poll replay accepted")
	}
	status, _ = identityCall(t, h, "/api/auth/qr/approve", phoneJWT, approve)
	if status == 200 {
		t.Fatal("approval replay accepted")
	}
}
func TestQRIdentityExpiryCancellationAndCodeMatch(t *testing.T) {
	a, h, jwt := qrFixture(t)
	start, nonce := qrBegin(t, h)
	status, _ := identityCall(t, h, "/api/auth/qr/approve", jwt, map[string]any{"code": nonce, "confirmed": true, "verificationCode": "WRONG!"})
	if status != 400 {
		t.Fatal("incorrect visual verification code accepted")
	}
	rec, _ := a.DB.GetRecord(context.Background(), "_qrLogins", start["requestId"].(string))
	rec.Data["expiresAt"] = time.Now().Add(-time.Second).Unix()
	_, _ = a.DB.SaveRecord(context.Background(), rec)
	status, _ = identityCall(t, h, "/api/auth/qr/poll", "", map[string]any{"requestId": start["requestId"], "pollSecret": start["pollSecret"]})
	if status != 410 {
		t.Fatal("expired QR accepted", status)
	}
	next, nextNonce := qrBegin(t, h)
	poll := map[string]any{"requestId": next["requestId"], "pollSecret": next["pollSecret"]}
	status, _ = identityCall(t, h, "/api/auth/qr/cancel", "", poll)
	if status != 200 {
		t.Fatal("cancel failed", status)
	}
	status, _ = identityCall(t, h, "/api/auth/qr/approve", jwt, map[string]any{"code": nextNonce, "confirmed": true, "verificationCode": next["verificationCode"]})
	if status != 410 {
		t.Fatal("cancelled QR approved", status)
	}
}
