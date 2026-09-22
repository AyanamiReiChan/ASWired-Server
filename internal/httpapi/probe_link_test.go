package httpapi

import (
	"context"
	"net/http"
	"testing"
)

func TestProbeLinkUsesPublicKomariOrigin(t *testing.T) {
	a, h, _ := controllerFixture(t)
	a.Config.KomariPublicURL = "https://probe.example.test"
	a.Config.KomariBridgeSecret = "private-bridge-secret"
	for _, silent := range []bool{false, true} {
		if err := a.DB.SetSetting(context.Background(), "settings", map[string]any{
			"probeBaseUrl": "http://127.0.0.1:25774", "probeApiKey": "private-api-key",
			"probePublicEnabled": false, "silentMode": silent,
		}); err != nil {
			t.Fatal(err)
		}
		// Public navigation works without administrator credentials or enabling
		// ASWired's old public projection, and never takes a caller's target URL.
		res := controllerRequest(t, h, "GET", "/api/public/probe-link?url=https://untrusted.example.test", "", nil)
		requireStatus(t, res, http.StatusOK)
		data := responseMap(t, res)
		if len(data) != 1 || data["url"] != "https://probe.example.test/" {
			t.Fatalf("unexpected probe link: %v", data)
		}
		if res.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("probe address must not be cached")
		}
	}
}

func TestProbeLinkRequiresPublicOrigin(t *testing.T) {
	a, h, _ := controllerFixture(t)
	if err := a.DB.SetSetting(context.Background(), "settings", map[string]any{"probeBaseUrl": "http://127.0.0.1:25774"}); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "javascript:alert(1)", "https://user:password@probe.example.test"} {
		a.Config.KomariPublicURL = origin
		res := controllerRequest(t, h, "GET", "/api/public/probe-link", "", nil)
		requireStatus(t, res, http.StatusServiceUnavailable)
		if _, ok := responseMap(t, res)["url"]; ok {
			t.Fatal("missing public origin fell back to a private address")
		}
	}
}
