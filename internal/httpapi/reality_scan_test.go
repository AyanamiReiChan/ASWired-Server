package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

type realityScanTLSFixture struct {
	dial      func(context.Context, string, string) (net.Conn, error)
	roots     *x509.CertPool
	mu        sync.Mutex
	addresses []string
	names     []string
}

func newRealityScanTLSFixture(t *testing.T, domains []string, alpn []string, version uint16, curves []tls.CurveID, expired bool, rejectSNI bool) *realityScanTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	if expired {
		expires = time.Now().Add(-time.Minute)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "Fixture leaf"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, DNSNames: domains, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &realityScanTLSFixture{roots: x509.NewCertPool()}
	fixture.roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, MaxVersion: version, NextProtos: alpn, CurvePreferences: curves}
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		fixture.mu.Lock()
		fixture.names = append(fixture.names, hello.ServerName)
		fixture.mu.Unlock()
		if rejectSNI && hello.ServerName != "" {
			return nil, errors.New("SNI is not served at this IP")
		}
		return nil, nil
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = tls.Server(conn, cfg).HandshakeContext(ctx)
			}()
		}
	}()
	fixture.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		fixture.mu.Lock()
		fixture.addresses = append(fixture.addresses, address)
		fixture.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	return fixture
}

func TestRealityScanParseTargetsAndStrictBounds(t *testing.T) {
	targets, err := parseRealityScanTargets(" EXAMPLE.TEST,example.test:8443\n8.8.8.8\t[2606:4700:4700::1111]:443 2606:4700:4700::1111\n8.8.4.0/31 2606:4700::/127")
	if err != nil || len(targets) != 8 || targets[0].address != "example.test:443" || targets[1].port != 8443 || targets[3].address != "[2606:4700:4700::1111]:443" {
		t.Fatalf("target parsing %v: %#v", err, targets)
	}
	for _, raw := range []string{"8.8.8.0/24", "2606:4700::/120", "8.8.8.0/25,8.8.4.4", "https://example.test", "user@example.test", "example.test:0", "example.test:65536", "example.test:abc", "example.test:0443", "[fe80::1%zone]:443", "1.2.3.4/not-prefix", strings.Repeat("example.test ", 129), "::ffff:8.8.8.0/121"} {
		if _, err := parseRealityScanTargets(raw); err == nil {
			t.Errorf("accepted invalid or oversized input %q", raw)
		}
	}
	if targets, err := parseRealityScanTargets("8.8.8.0/25"); err != nil || len(targets) != 128 {
		t.Fatal("128-address boundary", len(targets), err)
	}
	if targets, err := parseRealityScanTargets(""); err != nil || len(targets) != len(realityScanDefaults) || len(targets) > 10 {
		t.Fatal("default seed list", len(targets), err)
	}
}

func TestRealityScanActualTLSRequirements(t *testing.T) {
	for _, tc := range []struct {
		name, domain string
		alpn         []string
		version      uint16
		curves       []tls.CurveID
		expired      bool
		trusted      bool
		feasible     bool
	}{
		{"valid", "example.test", []string{"h2"}, tls.VersionTLS13, []tls.CurveID{tls.X25519}, false, true, true},
		{"old-tls", "example.test", []string{"h2"}, tls.VersionTLS12, []tls.CurveID{tls.X25519}, false, true, false},
		{"no-h2", "example.test", []string{"http/1.1"}, tls.VersionTLS13, []tls.CurveID{tls.X25519}, false, true, false},
		{"no-x25519", "example.test", []string{"h2"}, tls.VersionTLS13, []tls.CurveID{tls.CurveP256}, false, true, false},
		{"wrong-domain", "other.test", []string{"h2"}, tls.VersionTLS13, []tls.CurveID{tls.X25519}, false, true, false},
		{"untrusted", "example.test", []string{"h2"}, tls.VersionTLS13, []tls.CurveID{tls.X25519}, false, false, false},
		{"expired", "example.test", []string{"h2"}, tls.VersionTLS13, []tls.CurveID{tls.X25519}, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRealityScanTLSFixture(t, []string{tc.domain}, tc.alpn, tc.version, tc.curves, tc.expired, false)
			roots := fixture.roots
			if !tc.trusted {
				roots = x509.NewCertPool()
			}
			target, _ := parseRealityScanTarget("example.test:8443")
			result := scanRealityTarget(context.Background(), target, fixture.dial, roots)
			if result.Feasible != tc.feasible {
				t.Fatalf("wrong outcome: %+v", result)
			}
			// A successful loopback handshake can fall within one Windows clock tick.
			if result.Feasible && (!result.TLS13 || !result.H2 || !result.X25519 || !result.CertValid || !result.CertChainValid || result.CertChainBytes == 0 || result.CurveID != 29 || result.Host != "example.test" || result.Target != "example.test:8443" || result.Reason != "" || result.LatencyMS < 0 || result.CertSubject == "" || result.CertificateExpires == "") {
				t.Fatalf("incomplete actual evidence: %+v", result)
			}
			if !result.Feasible && result.Reason == "" {
				t.Fatal("missing failure reason")
			}
			if tc.name == "wrong-domain" && (!result.CertChainValid || result.CertValid) {
				t.Fatal("chain trust conflated with hostname validation")
			}
			if tc.name == "old-tls" && result.TLS13 {
				t.Fatal("TLS 1.2 was marked TLS 1.3")
			}
			if tc.name == "no-x25519" && result.X25519 {
				t.Fatal("unnegotiated X25519 marked true")
			}
		})
	}
}

func TestRealityScanIPRequiresSameIPAndConfirmedSNI(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		fixture := newRealityScanTLSFixture(t, []string{"*.example.test", "example.test"}, []string{"h2"}, tls.VersionTLS13, nil, false, rejected)
		target, _ := parseRealityScanTarget("8.8.8.8:8443")
		result := scanRealityTarget(context.Background(), target, fixture.dial, fixture.roots)
		if result.Feasible == rejected {
			t.Fatalf("unconfirmed SNI result: %+v", result)
		}
		fixture.mu.Lock()
		if len(fixture.addresses) != 2 || fixture.addresses[0] != "8.8.8.8:8443" || fixture.addresses[1] != fixture.addresses[0] || len(fixture.names) != 2 || fixture.names[0] != "" || fixture.names[1] != "example.test" {
			t.Error("IP discovery changed the destination or omitted confirmation", fixture.addresses, fixture.names)
		}
		fixture.mu.Unlock()
		if !rejected && (result.Host != "example.test" || result.Target != "8.8.8.8:8443" || len(result.ServerNames) != 1) {
			t.Fatal("did not preserve original IP and confirmed SNI", result)
		}
		if rejected && result.Host != "" {
			t.Fatal("unconfirmed hostname exposed as usable")
		}
	}
	fixture := newRealityScanTLSFixture(t, []string{"*.example.test"}, []string{"h2"}, tls.VersionTLS13, nil, false, false)
	target, _ := parseRealityScanTarget("8.8.8.8")
	if result := scanRealityTarget(context.Background(), target, fixture.dial, fixture.roots); result.Feasible || result.Host != "" {
		t.Fatal("wildcard was invented into an SNI hostname", result)
	}
}

func realityScanResponse(t *testing.T, h http.Handler, admin, targets string) map[string]any {
	t.Helper()
	w := temporaryCall(h, "POST", "/api/reality-targets/scan", admin, map[string]any{"targets": targets})
	if w.Code != 200 {
		t.Fatalf("scan: %d %s", w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func realityScanSelection(response map[string]any) map[string]any {
	ids := []string{}
	for _, result := range response["results"].([]any) {
		ids = append(ids, text(result.(map[string]any), "id"))
	}
	return map[string]any{"scanId": response["scanId"], "resultIds": ids}
}

func TestRealityScanPermissionsImportAndStoredProbe(t *testing.T) {
	a, h, admin, member, _ := realityFixture(t)
	fixture := newRealityScanTLSFixture(t, []string{"example.test"}, []string{"h2"}, tls.VersionTLS13, nil, false, false)
	a.realityScanner = &realityScanTransport{dial: fixture.dial, roots: fixture.roots}
	for _, path := range []string{"/api/reality-targets/scan", "/api/reality-targets/scan/import"} {
		if w := temporaryCall(h, "POST", path, "", map[string]any{}); w.Code != 401 {
			t.Fatal("unauthenticated scanner", w.Code)
		}
		if w := temporaryCall(h, "POST", path, member, map[string]any{}); w.Code != 403 {
			t.Fatal("member scanner", w.Code)
		}
	}
	response := realityScanResponse(t, h, admin, "8.8.8.8:8443")
	if text(response, "source") != "controller" || number(response, "total") != 1 || number(response, "feasibleCount") != 1 {
		t.Fatal("invalid scan response", response)
	}
	selection := realityScanSelection(response)
	selection["results"] = response["results"]
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection); w.Code != 400 {
		t.Fatal("accepted client supplied evidence", w.Code)
	}
	delete(selection, "results")
	bad := map[string]any{"scanId": response["scanId"], "resultIds": []string{"invented"}}
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, bad); w.Code != 400 {
		t.Fatal("accepted forged result id", w.Code)
	}
	w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var imported map[string]any
	json.Unmarshal(w.Body.Bytes(), &imported)
	if number(imported, "imported") != 1 || number(imported, "skipped") != 0 {
		t.Fatal(imported)
	}
	rows, _ := a.DB.ListRecords(context.Background(), realityPoolCollection, "")
	if len(rows) != 1 || text(rows[0].Data, "domain") != "example.test" || text(rows[0].Data, "target") != "8.8.8.8:8443" || number(rows[0].Data, "port") != 8443 || boolean(rows[0].Data, "enabled") || text(rows[0].Data, "status") != "pending" {
		t.Fatal("import did not preserve pending destination/SNI", rows)
	}
	allowed, _, _ := a.realityAllowed(context.Background())
	if !allowed["example.test"] || len(allowed) != 1 {
		t.Fatal("confirmed domain not added to allowlist", allowed)
	}
	if w := temporaryCall(h, "POST", "/api/reality-targets/"+rows[0].ID+"/probe", admin, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatal("stored destination re-probe failed", w.Code, w.Body.String())
	}
	fixture.mu.Lock()
	if fixture.addresses[len(fixture.addresses)-1] != "8.8.8.8:8443" || fixture.names[len(fixture.names)-1] != "example.test" {
		t.Error("individual probe lost imported target/SNI", fixture.addresses, fixture.names)
	}
	fixture.mu.Unlock()
	if w := temporaryCall(h, "POST", "/api/reality-targets/"+rows[0].ID+"/review", admin, map[string]any{"approve": true}); w.Code != 200 {
		t.Fatal("imported evidence cannot use existing review", w.Code, w.Body.String())
	}
	w = temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection)
	json.Unmarshal(w.Body.Bytes(), &imported)
	if w.Code != 200 || number(imported, "imported") != 0 || number(imported, "skipped") != 1 {
		t.Fatal("duplicate target/domain created", w.Code, imported)
	}
	row, _ := a.DB.GetRecord(context.Background(), realityPoolCollection, rows[0].ID)
	if !boolean(row.Data, "enabled") || text(row.Data, "status") != "approved" {
		t.Fatal("duplicate import overwrote approved target")
	}
}

func TestRealityScanEvidenceOwnerExpiryAndAtomicAllowlist(t *testing.T) {
	a, h, admin, _, _ := realityFixture(t)
	fixture := newRealityScanTLSFixture(t, []string{"example.test"}, []string{"h2"}, tls.VersionTLS13, nil, false, false)
	a.realityScanner = &realityScanTransport{dial: fixture.dial, roots: fixture.roots}
	response := realityScanResponse(t, h, admin, "example.test")
	selection := realityScanSelection(response)
	ctx := context.Background()
	scan, _ := a.DB.GetRecord(ctx, realityScanCollection, text(response, "scanId"))
	owner := scan.OwnerID
	scan.OwnerID = "other-admin"
	scan, _ = a.DB.SaveRecord(ctx, scan)
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection); w.Code != 403 {
		t.Fatal("imported another administrator's evidence", w.Code)
	}
	scan.OwnerID = owner
	expiry := scan.Data["expiresAt"]
	scan.Data["expiresAt"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
	scan, _ = a.DB.SaveRecord(ctx, scan)
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection); w.Code != 410 {
		t.Fatal("imported expired batch", w.Code)
	}
	scan.Data["expiresAt"] = expiry
	scan, _ = a.DB.SaveRecord(ctx, scan)
	results := scan.Data["results"].([]any)
	result := results[0].(map[string]any)
	for _, field := range []string{"feasible", "x25519", "certValid", "certChainValid"} {
		result[field] = false
		scan, _ = a.DB.SaveRecord(ctx, scan)
		if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection); w.Code != 400 {
			t.Fatal("imported invalid check", field, w.Code)
		}
		result[field] = true
	}
	checked := result["checkedAt"]
	result["checkedAt"] = time.Now().Add(-16 * time.Minute).Format(time.RFC3339Nano)
	scan, _ = a.DB.SaveRecord(ctx, scan)
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection); w.Code != 400 {
		t.Fatal("imported old result inside fresh batch", w.Code)
	}
	result["checkedAt"] = checked
	scan, _ = a.DB.SaveRecord(ctx, scan)
	domains := []string{}
	for i := range 200 {
		domains = append(domains, fmt.Sprintf("d%d.example.test", i))
	}
	if w := temporaryCall(h, "PUT", "/api/reality-targets/allowlist", admin, map[string]any{"domains": domains}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection); w.Code != 400 {
		t.Fatal("import expanded allowlist beyond 200", w.Code, w.Body.String())
	}
	rows, _ := a.DB.ListRecords(ctx, realityPoolCollection, "")
	allowed, _, _ := a.realityAllowed(ctx)
	if len(rows) != 0 || len(allowed) != 200 || allowed["example.test"] {
		t.Fatal("failed import partially committed records or domains", len(rows), len(allowed))
	}
}

func TestRealityScanConcurrentImportDeduplicatesAtomically(t *testing.T) {
	a, h, admin, _, _ := realityFixture(t)
	fixture := newRealityScanTLSFixture(t, []string{"example.test", "other.test"}, []string{"h2"}, tls.VersionTLS13, nil, false, false)
	a.realityScanner = &realityScanTransport{dial: fixture.dial, roots: fixture.roots}
	response := realityScanResponse(t, h, admin, "example.test:8443 other.test:9443")
	selection := realityScanSelection(response)
	var imported atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, selection)
			var out map[string]any
			json.Unmarshal(w.Body.Bytes(), &out)
			if w.Code != 200 {
				t.Errorf("concurrent import %d: %s", w.Code, w.Body.String())
			}
			imported.Add(int32(number(out, "imported")))
		})
	}
	wg.Wait()
	rows, _ := a.DB.ListRecords(context.Background(), realityPoolCollection, "")
	allowed, _, _ := a.realityAllowed(context.Background())
	if imported.Load() != 2 || len(rows) != 2 || len(allowed) != 2 || !allowed["example.test"] || !allowed["other.test"] {
		t.Fatal("concurrent import lost or duplicated targets/domains", imported.Load(), len(rows), allowed)
	}
}

func TestRealityScanConcurrencyGateAndCancellation(t *testing.T) {
	a, h, admin, _, _ := realityFixture(t)
	entered := make(chan struct{}, 128)
	var active, peak atomic.Int32
	a.realityScanner = &realityScanTransport{dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	targets := []string{}
	for i := range 32 {
		targets = append(targets, fmt.Sprintf("d%d.example.test", i))
	}
	raw, _ := json.Marshal(map[string]any{"targets": strings.Join(targets, ",")})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "/api/reality-targets/scan", bytes.NewReader(raw)).WithContext(ctx)
	r.Header.Set("MM-Authorization", admin)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, r); close(done) }()
	for range 16 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan", admin, map[string]any{"targets": "example.test"}); w.Code != 409 {
		t.Fatal("overlapping batch was accepted", w.Code)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not stop scan")
	}
	if w.Code != 408 || peak.Load() > 16 || active.Load() != 0 {
		t.Fatal("cancellation/concurrency bound", w.Code, peak.Load(), active.Load())
	}
	records, _ := a.DB.ListRecords(context.Background(), realityScanCollection, "")
	if len(records) != 0 {
		t.Fatal("cancelled batch persisted incomplete evidence")
	}
	a.realityScanner = &realityScanTransport{dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("fixture failure") }}
	response := realityScanResponse(t, h, admin, "example.test")
	if number(response, "feasibleCount") != 0 {
		t.Fatal("failed dial became feasible")
	}
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, realityScanSelection(response)); w.Code != 400 {
		t.Fatal("failed result imported", w.Code)
	}
}

func TestRealityScanCloseCancelsActiveProbe(t *testing.T) {
	a, h, admin, _, _ := realityFixture(t)
	entered := make(chan struct{})
	a.realityScanner = &realityScanTransport{dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	done := make(chan int, 1)
	go func() {
		done <- temporaryCall(h, "POST", "/api/reality-targets/scan", admin, map[string]any{"targets": "example.test"}).Code
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("scan did not start")
	}
	a.Close()
	select {
	case code := <-done:
		if code != 408 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("App.Close did not cancel active scan")
	}
}

func TestRealityScanProductionPublicGuard(t *testing.T) {
	a, h, admin, _, _ := realityFixture(t)
	response := realityScanResponse(t, h, admin, "127.0.0.1 10.0.0.1 169.254.169.254 ::1 100.64.0.1 192.0.2.1 0.1.2.3 240.0.0.1")
	if number(response, "total") != 8 || number(response, "feasibleCount") != 0 {
		t.Fatal("nonpublic scan result", response)
	}
	for _, raw := range response["results"].([]any) {
		result := raw.(map[string]any)
		if boolean(result, "feasible") || text(result, "ip") != "" || !strings.Contains(text(result, "reason"), "不能请求") {
			t.Fatal("nonpublic target reached dial/TLS instead of guard", result)
		}
	}
	rows, _ := a.DB.ListRecords(context.Background(), realityPoolCollection, "")
	if len(rows) != 0 {
		t.Fatal("scanning wrote target pool entries")
	}
}

func TestRealityScanImportDoesNotReactivateWithdrawnTargets(t *testing.T) {
	a, h, admin, _, _ := realityFixture(t)
	fixture := newRealityScanTLSFixture(t, []string{"example.test"}, []string{"h2"}, tls.VersionTLS13, nil, false, false)
	a.realityScanner = &realityScanTransport{dial: fixture.dial, roots: fixture.roots}
	first := realityScanResponse(t, h, admin, "example.test:443")
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, realityScanSelection(first)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	ctx := context.Background()
	rows, _ := a.DB.ListRecords(ctx, realityPoolCollection, "")
	id := rows[0].ID
	if w := temporaryCall(h, "POST", "/api/reality-targets/"+id+"/review", admin, map[string]any{"approve": true}); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := temporaryCall(h, "PUT", "/api/reality-targets/allowlist", admin, map[string]any{"domains": []string{}}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, realityScanSelection(first)); w.Code != 200 || !strings.Contains(w.Body.String(), `"skipped":1`) {
		t.Fatal("duplicate import not skipped", w.Code, w.Body.String())
	}
	allowed, _, _ := a.realityAllowed(ctx)
	if len(allowed) != 0 {
		t.Fatal("duplicate import restored a withdrawn domain", allowed)
	}
	second := realityScanResponse(t, h, admin, "example.test:8443")
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan/import", admin, realityScanSelection(second)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	allowed, _, _ = a.realityAllowed(ctx)
	old, _ := a.DB.GetRecord(ctx, realityPoolCollection, id)
	if !allowed["example.test"] || boolean(old.Data, "enabled") || realityAvailable(old, allowed) || text(old.Data, "status") != "approved" || old.Data["lastProbe"] == nil {
		t.Fatal("new endpoint import reactivated or damaged withdrawn target", old.Data, allowed)
	}
	rows, _ = a.DB.ListRecords(ctx, realityPoolCollection, "")
	if len(rows) != 2 {
		t.Fatal("new target not imported", len(rows))
	}
	for _, row := range rows {
		if row.ID != id && (text(row.Data, "status") != "pending" || boolean(row.Data, "enabled") || text(row.Data, "target") != "example.test:8443") {
			t.Fatal("new endpoint bypassed review", row.Data)
		}
	}
}

func TestRealityScanTTLHistoryAndNoImplicitImport(t *testing.T) {
	a, h, admin, _, _ := realityFixture(t)
	a.realityScanner = &realityScanTransport{dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("fixture offline") }}
	response := realityScanResponse(t, h, admin, "")
	if number(response, "total") != float64(len(realityScanDefaults)) {
		t.Fatal("blank scan did not use small seed list", response)
	}
	ctx := context.Background()
	scan, _ := a.DB.GetRecord(ctx, realityScanCollection, text(response, "scanId"))
	if scan.OwnerID == "" || time.Until(dateTime(text(scan.Data, "expiresAt"))) > 15*time.Minute || time.Until(dateTime(text(scan.Data, "expiresAt"))) < 14*time.Minute {
		t.Fatal("invalid owner or evidence TTL", scan)
	}
	scan.Data["expiresAt"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
	a.DB.SaveRecord(ctx, scan)
	realityScanResponse(t, h, admin, "example.test")
	if _, err := a.DB.GetRecord(ctx, realityScanCollection, scan.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired evidence not pruned", err)
	}
	for i := range 63 {
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: realityScanCollection, ID: fmt.Sprintf("active-%d", i), OwnerID: scan.OwnerID, Data: map[string]any{"expiresAt": time.Now().Add(time.Minute).Format(time.RFC3339Nano)}}); err != nil {
			t.Fatal(err)
		}
	}
	if w := temporaryCall(h, "POST", "/api/reality-targets/scan", admin, map[string]any{"targets": "example.test"}); w.Code != 429 {
		t.Fatal("unbounded unexpired evidence history", w.Code)
	}
	rows, _ := a.DB.ListRecords(ctx, realityPoolCollection, "")
	allowed, _, _ := a.realityAllowed(ctx)
	if len(rows) != 0 || len(allowed) != 0 {
		t.Fatal("scanning changed allowlist or pool before explicit import")
	}
}
