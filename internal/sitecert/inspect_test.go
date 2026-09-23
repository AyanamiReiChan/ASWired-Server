package sitecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureCaddy() map[string]any {
	var config map[string]any
	if err := json.Unmarshal([]byte(`{"apps":{"http":{"servers":{"https":{"listen":[":443"],"routes":[{"match":[{"host":["panel.example.test","probe.example.test"]}]}]}}}}}`), &config); err != nil {
		panic(err)
	}
	return config
}

func tlsFixture(t *testing.T, names []string, expiry time.Time) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "site test"}, DNSNames: names, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inspection must not send an HTTP request to website")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, roots
}

func TestInspectServedCertificatesWithoutDatabaseRecordsOrPrivateKeys(t *testing.T) {
	server, roots := tlsFixture(t, []string{"panel.example.test", "probe.example.test"}, time.Now().Add(60*24*time.Hour))
	var calls atomic.Int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" {
			t.Error("mutating Caddy request")
		}
		json.NewEncoder(w).Encode(fixtureCaddy())
	}))
	defer admin.Close()
	i := NewInspector()
	i.caddyURL = admin.URL
	i.roots = roots
	i.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "127.0.0.1:443" {
			t.Errorf("non-loopback or wrong port: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	targets := []Target{{"panel", "主控", "https://panel.example.test"}, {"komari", "Komari", "https://probe.example.test"}}
	rows := i.Check(context.Background(), targets)
	for _, row := range rows {
		if !row.Verified || row.Status != "valid" || row.Manager != "caddy" || row.Renewal != "automatic" || row.Serial != "42" || len(row.Fingerprint) != 64 {
			t.Fatalf("bad inspection: %+v", row)
		}
	}
	_ = i.Check(context.Background(), targets)
	if calls.Load() != 1 {
		t.Fatal("duplicate request did not reuse short cache")
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), "automation") {
		t.Fatal("raw Caddy configuration leaked")
	}
}

func TestInspectionReportsInvalidCertificatesInsteadOfTrustingHandshake(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		names  []string
		expiry time.Time
		roots  bool
	}{
		{"expired", []string{"panel.example.test"}, time.Now().Add(-time.Hour), true},
		{"wrong-host", []string{"other.example.test"}, time.Now().Add(48 * time.Hour), true},
		{"untrusted", []string{"panel.example.test"}, time.Now().Add(48 * time.Hour), false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server, roots := tlsFixture(t, scenario.names, scenario.expiry)
			i := NewInspector()
			if scenario.roots {
				i.roots = roots
			}
			i.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, server.Listener.Addr().String())
			}
			row := i.inspect(context.Background(), Target{"panel", "Panel", "https://panel.example.test"}, nil)
			if row.Verified || row.Status != "invalid" || row.Error == "" || row.Serial != "42" {
				t.Fatalf("untrusted certificate represented as valid: %+v", row)
			}
		})
	}
}

func TestCaddyManagementConservativeDetection(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		change  func(map[string]any)
		renewal string
	}{
		{"automatic", func(map[string]any) {}, "automatic"},
		{"disabled", func(c map[string]any) {
			object(object(object(object(c["apps"])["http"])["servers"])["https"])["automatic_https"] = map[string]any{"disable_certificates": true}
		}, "disabled"},
		{"skipped", func(c map[string]any) {
			object(object(object(object(c["apps"])["http"])["servers"])["https"])["automatic_https"] = map[string]any{"skip_certificates": []any{"panel.example.test"}}
		}, "disabled"},
		{"manual", func(c map[string]any) {
			object(c["apps"])["tls"] = map[string]any{"certificates": map[string]any{"load_files": []any{map[string]any{"certificate": "/private/cert.pem", "key": "/private/key.pem"}}}}
		}, "unknown"},
		{"managed", func(c map[string]any) {
			object(object(object(object(c["apps"])["http"])["servers"])["https"])["tls_connection_policies"] = []any{map[string]any{"match": map[string]any{"sni": []any{"panel.example.test"}}, "certificate_selection": map[string]any{"any_tag": []any{"aswired-site-panel"}}}}
		}, "managed"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := fixtureCaddy()
			scenario.change(cfg)
			_, renewal, _ := caddyManagement(cfg, "panel.example.test", "443")
			if renewal != scenario.renewal {
				t.Fatalf("got %s want %s", renewal, scenario.renewal)
			}
		})
	}
	if matches("*.example.test", "nested.panel.example.test") {
		t.Fatal("wildcard matched multiple labels")
	}
	_, renewal, _ := caddyManagement(fixtureCaddy(), "unknown.example.test", "443")
	if renewal != "unknown" {
		t.Fatal("claimed ownership of an unrelated hostname")
	}
}

func TestInspectionDoesNotFollowCaddyRedirects(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	i := NewInspector()
	i.caddyURL = redirect.URL
	rows := i.Check(context.Background(), []Target{{ID: "panel", URL: "http://localhost"}, {ID: "komari"}})
	if followed.Load() || rows[0].Status != "http" || rows[1].Status != "unconfigured" {
		t.Fatal("unsafe redirect or incorrect unconfigured state")
	}
}
