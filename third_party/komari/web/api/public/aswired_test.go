package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestUnifiedCallbackOriginAndCookie(t *testing.T) {
	secret := strings.Repeat("s", 32)
	ticket := strings.Repeat("t", 64)
	calls := 0
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/internal/komari/redeem" || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("invalid bridge request")
			w.WriteHeader(401)
			return
		}
		var input struct { Ticket string }
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Ticket != ticket {
			t.Error("invalid ticket body")
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"session": "kprobe_" + strings.Repeat("x", 64),
			"id": "probe", "username": "probe",
			"expiresAt": time.Now().Add(time.Hour),
		})
	}))
	defer identity.Close()
	t.Setenv("ASWIRED_IDENTITY_URL", identity.URL)
	t.Setenv("ASWIRED_LOGIN_URL", "https://aswired.example.test/login")
	t.Setenv("ASWIRED_BRIDGE_SECRET", secret)
	t.Setenv("KOMARI_PUBLIC_URL", "https://probe.example.test")
	router := gin.New()
	router.POST("/auth/aswired/session", ASWiredSession)
	router.POST("/api/login", Login)
	request := func(origin, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(url.Values{"ticket": {ticket}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		out := httptest.NewRecorder()
		router.ServeHTTP(out, req)
		return out
	}
	for _, origin := range []string{"", "null", "https://other.example.test"} {
		if out := request(origin, "/auth/aswired/session"); out.Code != 403 {
			t.Fatalf("untrusted origin accepted: %q (%d)", origin, out.Code)
		}
	}
	if calls != 0 { t.Fatal("untrusted request reached identity service") }
	out := request("https://aswired.example.test", "/auth/aswired/session")
	if out.Code != 303 || out.Header().Get("Location") != "/admin" {
		t.Fatalf("unexpected redirect: %d", out.Code)
	}
	cookies := out.Result().Cookies()
	if len(cookies) != 1 { t.Fatal("missing session cookie") }
	cookie := cookies[0]
	if cookie.Name != "session_token" || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge <= 0 || cookie.Domain != "" {
		t.Fatal("unsafe session cookie attributes")
	}
	if request("https://aswired.example.test", "/api/login").Code != 403 {
		t.Fatal("standalone password login remains enabled")
	}
	identity.Close()
	failed := request("https://aswired.example.test", "/auth/aswired/session")
	if len(failed.Result().Cookies()) != 0 || failed.Header().Get("Location") != "https://aswired.example.test/login" {
		t.Fatal("identity service failure did not fail closed")
	}
}
