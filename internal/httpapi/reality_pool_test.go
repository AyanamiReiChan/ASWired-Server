package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func realityFixture(t *testing.T) (*App, http.Handler, string, string, string) {
	t.Helper()
	a, admin, _, adminJWT := identityFixture(t)
	mux := http.NewServeMux()
	a.registerRealityPool(mux)
	tokens := []string{}
	for i, age := range []time.Duration{8 * 24 * time.Hour, 6 * 24 * time.Hour} {
		id := []string{"older-contributor", "new-contributor"}[i]
		u := store.User{ID: id, Username: id, Role: "user", PasswordHash: admin.PasswordHash, TokenVersion: 1, CreatedAt: time.Now().UTC().Add(-age)}
		if e := a.DB.CreateUser(context.Background(), u); e != nil {
			t.Fatal(e)
		}
		jwt, e := a.Signer.Issue(id, 1)
		if e != nil {
			t.Fatal(e)
		}
		tokens = append(tokens, jwt)
	}
	return a, mux, adminJWT, tokens[0], tokens[1]
}

func TestRealityDomainValidationAndExactAllowlist(t *testing.T) {
	for _, raw := range []string{"localhost", "127.0.0.1", "[::1]", "https://example.com", "example.com:443", "example.com/path", "example.com.", "*.example.com", "user@example.com", "-a.example.com", "a..example.com", "中文.example.com", strings.Repeat("a", 64) + ".example.com"} {
		if _, e := realityDomain(raw); e == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if domain, e := realityDomain(" EXAMPLE.COM "); e != nil || domain != "example.com" {
		t.Fatal(domain, e)
	}
	a, h, admin, member, young := realityFixture(t)
	for _, token := range []string{admin, member, young} {
		if w := temporaryCall(h, "POST", "/api/reality-targets", token, map[string]any{"domain": "example.com"}); w.Code != 405 {
			t.Fatal("manual creation endpoint still exists", w.Code)
		}
	}
	if w := temporaryCall(h, "PUT", "/api/reality-targets/allowlist", member, map[string]any{"domains": []string{"example.com"}}); w.Code != 403 {
		t.Fatal("member changed allowlist", w.Code)
	}
	if w := temporaryCall(h, "PUT", "/api/reality-targets/allowlist", admin, map[string]any{"domains": []string{"example.com"}}); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	id := "pending-fixture"
	if _, err := a.DB.SaveRecord(context.Background(), store.Record{Collection: realityPoolCollection, ID: id, Data: map[string]any{"domain": "example.com", "name": "Pending", "status": "pending", "enabled": false}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"probe", "review"} {
		if w := temporaryCall(h, "POST", "/api/reality-targets/"+id+"/"+path, member, map[string]any{"approve": true}); w.Code != 403 {
			t.Fatal("member invoked admin operation", path)
		}
	}
	if w := temporaryCall(h, "POST", "/api/reality-targets/"+id+"/review", admin, map[string]any{"approve": true}); w.Code != 400 {
		t.Fatal("approved without verified probe")
	}
	if w := temporaryCall(h, "PUT", "/api/reality-targets/"+id, admin, map[string]any{"name": "bypass", "enabled": true}); w.Code != 400 {
		t.Fatal("enabled pending target")
	}
	records, _ := a.DB.ListRecords(context.Background(), realityPoolCollection, "")
	if len(records) != 1 {
		t.Fatal("rejected requests wrote targets")
	}
	otherList := temporaryCall(h, "GET", "/api/reality-targets", young, nil)
	if strings.Contains(otherList.Body.String(), id) {
		t.Fatal("unreviewed target shared with another member")
	}
}

func realityTLSServer(t *testing.T, domain string, alpn []string, maxVersion uint16) (func(context.Context, string, string) (net.Conn, error), *x509.CertPool) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{domain}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: alpn, MinVersion: tls.VersionTLS12, MaxVersion: maxVersion})
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = secure.HandshakeContext(ctx)
			}()
		}
	}()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "example.test:443" {
			t.Errorf("unexpected dial address %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}, roots
}

func TestRealityTLSActualHandshakeAndCertificateValidation(t *testing.T) {
	for _, tc := range []struct {
		name, domain string
		alpn         []string
		version      uint16
		success      bool
	}{{"valid", "example.test", []string{"h2"}, tls.VersionTLS13, true}, {"wrong-domain", "other.test", []string{"h2"}, tls.VersionTLS13, false}, {"no-h2", "example.test", nil, tls.VersionTLS13, false}, {"old-tls", "example.test", []string{"h2"}, tls.VersionTLS12, false}} {
		t.Run(tc.name, func(t *testing.T) {
			dial, roots := realityTLSServer(t, tc.domain, tc.alpn, tc.version)
			result, e := probeRealityTLS(context.Background(), "example.test", dial, roots)
			if (e == nil) != tc.success {
				t.Fatal("handshake policy", result, e)
			}
			if tc.success && (result["ip"] != "127.0.0.1" || result["alpn"] != "h2" || result["tlsVersion"] != "TLS 1.3" || number(result, "latencyMs") <= 0) {
				t.Fatal("missing actual probe evidence", result)
			}
		})
	}
	dial, _ := realityTLSServer(t, "example.test", []string{"h2"}, tls.VersionTLS13)
	if _, e := probeRealityTLS(context.Background(), "example.test", dial, nil); e == nil {
		t.Fatal("system roots accepted untrusted fixture certificate")
	}
	if conn, e := publicDial(context.Background(), "tcp", "127.0.0.1:443"); e == nil {
		conn.Close()
		t.Fatal("production probe accepted private address")
	}
}

func TestRealityApprovalRequiresFreshEvidenceAndAllowlist(t *testing.T) {
	a, h, admin, _, _ := realityFixture(t)
	ctx := context.Background()
	temporaryCall(h, "PUT", "/api/reality-targets/allowlist", admin, map[string]any{"domains": []string{"example.test"}})
	dial, roots := realityTLSServer(t, "example.test", []string{"h2"}, tls.VersionTLS13)
	evidence, e := probeRealityTLS(ctx, "example.test", dial, roots)
	if e != nil {
		t.Fatal(e)
	}
	rec, e := a.DB.SaveRecord(ctx, store.Record{Collection: realityPoolCollection, ID: "verified-target", OwnerID: "older-contributor", Data: map[string]any{"name": "verified", "domain": "example.test", "status": "pending", "enabled": false, "lastProbe": evidence}})
	if e != nil {
		t.Fatal(e)
	}
	if w := temporaryCall(h, "POST", "/api/reality-targets/"+rec.ID+"/review", admin, map[string]any{"approve": true}); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	list := temporaryCall(h, "GET", "/api/reality-targets", admin, nil)
	if !strings.Contains(list.Body.String(), `"available":true`) {
		t.Fatal("approved target not available")
	}
	temporaryCall(h, "PUT", "/api/reality-targets/allowlist", admin, map[string]any{"domains": []string{}})
	list = temporaryCall(h, "GET", "/api/reality-targets", admin, nil)
	if !strings.Contains(list.Body.String(), rec.ID) || !strings.Contains(list.Body.String(), `"available":false`) {
		t.Fatal("removed allowlist target was deleted or remained available")
	}
	temporaryCall(h, "PUT", "/api/reality-targets/allowlist", admin, map[string]any{"domains": []string{"example.test"}})
	rec, _ = a.DB.GetRecord(ctx, realityPoolCollection, rec.ID)
	evidence["checkedAt"] = time.Now().Add(-16 * time.Minute).Format(time.RFC3339Nano)
	rec.Data["lastProbe"] = evidence
	rec.Data["enabled"] = false
	a.DB.SaveRecord(ctx, rec)
	if w := temporaryCall(h, "POST", "/api/reality-targets/"+rec.ID+"/review", admin, map[string]any{"approve": true}); w.Code != 400 {
		t.Fatal("stale evidence approved")
	}
}
