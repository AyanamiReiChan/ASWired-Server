package httpapi

import (
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
)

func TestOriginAllowedRequiresExactSchemeAndHost(t *testing.T) {
	a := &App{Config: config.Config{
		PublicURL:      "https://panel.example.test",
		AllowedOrigins: []string{"https://localhost:5174", "https://panel.example.test:8443"},
	}}
	for _, origin := range []string{
		"https://panel.example.test",
		"https://localhost:5174",
		"https://panel.example.test:8443",
	} {
		if !a.originAllowed(origin) {
			t.Errorf("configured origin rejected: %s", origin)
		}
	}
	for _, origin := range []string{
		"http://panel.example.test",
		"https://panel.example.test:443",
		"https://panel.example.test.evil",
		"https://panel.example.test/path",
		"https://user:pass@panel.example.test",
	} {
		if a.originAllowed(origin) {
			t.Errorf("unconfigured origin accepted: %s", origin)
		}
	}
}
