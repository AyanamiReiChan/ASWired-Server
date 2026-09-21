package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func localACMEFixture(t *testing.T, challengePort int, requireEAB ...bool) (*httptest.Server, *int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ASWired Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var base string
	var accountKey *ecdsa.PublicKey
	var jwkRaw map[string]any
	var certPEM []byte
	valid := false
	issued := 0
	nonces := map[string]bool{}
	token := "aswired-acme-fixture"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		nonce := newID()
		nonces[nonce] = true
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Content-Type", "application/json")
		var payload map[string]any
		if r.Method != "GET" && r.Method != "HEAD" {
			var body struct{ Protected, Payload, Signature string }
			if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body) != nil {
				http.Error(w, "bad jws", 400)
				return
			}
			protectedBytes, _ := base64.RawURLEncoding.DecodeString(body.Protected)
			var protected map[string]any
			if json.Unmarshal(protectedBytes, &protected) != nil {
				http.Error(w, "bad header", 400)
				return
			}
			n, _ := protected["nonce"].(string)
			if !nonces[n] {
				http.Error(w, "bad nonce", 400)
				return
			}
			delete(nonces, n)
			if protected["alg"] != "ES256" || protected["url"] != base+r.URL.Path {
				http.Error(w, "bad protected header", 400)
				return
			}
			if raw, ok := protected["jwk"].(map[string]any); ok {
				jwkRaw = raw
				x, _ := base64.RawURLEncoding.DecodeString(text(raw, "x"))
				y, _ := base64.RawURLEncoding.DecodeString(text(raw, "y"))
				accountKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			}
			signature, _ := base64.RawURLEncoding.DecodeString(body.Signature)
			hash := sha256.Sum256([]byte(body.Protected + "." + body.Payload))
			if accountKey == nil || len(signature) != 64 || !ecdsa.Verify(accountKey, hash[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
				http.Error(w, "bad signature", 400)
				return
			}
			decoded, _ := base64.RawURLEncoding.DecodeString(body.Payload)
			if len(decoded) > 0 {
				if json.Unmarshal(decoded, &payload) != nil {
					http.Error(w, "bad payload", 400)
					return
				}
			}
		}
		emit := func(status int, value any) { w.WriteHeader(status); _ = json.NewEncoder(w).Encode(value) }
		order := func(status string) map[string]any {
			return map[string]any{"status": status, "identifiers": []any{map[string]any{"type": "dns", "value": "node.example.test"}}, "authorizations": []string{base + "/authz/1"}, "finalize": base + "/finalize/1", "certificate": base + "/cert/1"}
		}
		switch r.URL.Path {
		case "/directory":
			emit(200, map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/new-order", "revokeCert": base + "/revoke", "keyChange": base + "/key-change"})
		case "/nonce":
			w.WriteHeader(200)
		case "/account":
			if len(requireEAB) > 0 && requireEAB[0] {
				binding, _ := payload["externalAccountBinding"].(map[string]any)
				protected, _ := base64.RawURLEncoding.DecodeString(text(binding, "protected"))
				var header map[string]any
				_ = json.Unmarshal(protected, &header)
				mac := hmac.New(sha256.New, []byte("fixture-eab-key-with-at-least-32-bytes"))
				mac.Write([]byte(text(binding, "protected") + "." + text(binding, "payload")))
				signature, _ := base64.RawURLEncoding.DecodeString(text(binding, "signature"))
				if text(header, "kid") != "fixture-account" || !hmac.Equal(signature, mac.Sum(nil)) {
					t.Error("invalid EAB registration")
					http.Error(w, "invalid EAB", 400)
					return
				}
			}
			w.Header().Set("Location", base+"/account/1")
			emit(201, map[string]any{"status": "valid", "contact": []string{"mailto:admin@example.test"}})
		case "/new-order":
			valid = false
			certPEM = nil
			w.Header().Set("Location", base+"/order/1")
			emit(201, order("pending"))
		case "/authz/1":
			status := "pending"
			if valid {
				status = "valid"
			}
			emit(200, map[string]any{"status": status, "identifier": map[string]any{"type": "dns", "value": "node.example.test"}, "challenges": []any{map[string]any{"type": "http-01", "url": base + "/challenge/1", "token": token, "status": status}}})
		case "/challenge/1":
			request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/%s", challengePort, token), nil)
			request.Host = "node.example.test"
			response, e := http.DefaultClient.Do(request)
			if e != nil {
				t.Errorf("HTTP-01 endpoint: %v", e)
				http.Error(w, "challenge failed", 400)
				return
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			canonical, _ := json.Marshal(map[string]any{"crv": jwkRaw["crv"], "kty": jwkRaw["kty"], "x": jwkRaw["x"], "y": jwkRaw["y"]})
			thumbprint := sha256.Sum256(canonical)
			expected := token + "." + base64.RawURLEncoding.EncodeToString(thumbprint[:])
			if response.StatusCode != 200 || strings.TrimSpace(string(body)) != expected {
				t.Errorf("invalid HTTP-01 key authorization")
				http.Error(w, "challenge failed", 400)
				return
			}
			valid = true
			emit(200, map[string]any{"type": "http-01", "url": base + "/challenge/1", "token": token, "status": "valid"})
		case "/finalize/1":
			if !valid {
				http.Error(w, "not authorized", 400)
				return
			}
			csrDER, e := base64.RawURLEncoding.DecodeString(text(payload, "csr"))
			if e != nil {
				http.Error(w, "bad csr", 400)
				return
			}
			csr, e := x509.ParseCertificateRequest(csrDER)
			if e != nil || csr.CheckSignature() != nil {
				http.Error(w, "bad csr signature", 400)
				return
			}
			issued++
			leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(issued + 100)), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, e := x509.CreateCertificate(rand.Reader, leaf, caCert, csr.PublicKey, key)
			if e != nil {
				t.Errorf("sign fixture CSR: %v", e)
				http.Error(w, "sign failed", 500)
				return
			}
			certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
			emit(200, order("valid"))
		case "/order/1":
			state := "pending"
			if certPEM != nil {
				state = "valid"
			} else if valid {
				state = "ready"
			}
			emit(200, order(state))
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(200)
			_, _ = w.Write(certPEM)
		default:
			http.Error(w, "unknown endpoint", 404)
		}
	})
	server := httptest.NewTLSServer(handler)
	base = server.URL
	t.Cleanup(server.Close)
	return server, &issued
}

func TestACMEHTTP01IssueRenewAndValidateMaterial(t *testing.T) {
	a, _ := subscriptionFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ca, issued := localACMEFixture(t, port)
	ctx := context.Background()
	asset, err := a.DB.SaveRecord(ctx, store.Record{Collection: "certificates", ID: "test-cert", Data: map[string]any{"name": "node.example.test", "email": "admin@example.test", "challenge": "HTTP-01", "httpChallengeHost": "127.0.0.1", "httpChallengePort": port, "acmeDirectory": ca.URL + "/directory", "caCertificatePEM": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate().Raw})), "termsAgreed": true}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.issueCertificate(ctx, store.User{ID: "admin", Role: "admin"}, asset.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if result["success"] != true || *issued != 1 {
		t.Fatal("certificate was not actually issued")
	}
	first, _ := a.DB.GetRecord(ctx, "_certificateMaterial", asset.ID)
	if _, err := validateCertificatePair(text(first.Data, "certificate"), text(first.Data, "privateKey"), []string{"node.example.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.issueCertificate(ctx, store.User{ID: "admin", Role: "admin"}, asset.ID, true); err != nil {
		t.Fatal(err)
	}
	second, _ := a.DB.GetRecord(ctx, "_certificateMaterial", asset.ID)
	if *issued != 2 || text(first.Data, "serial") == text(second.Data, "serial") {
		t.Fatal("renewal reused an invented certificate")
	}
	if _, err := validateCertificatePair(text(first.Data, "certificate"), text(second.Data, "privateKey"), []string{"node.example.test"}); err == nil {
		t.Fatal("mismatched private key accepted")
	}
	if _, err := validateCertificatePair(text(second.Data, "certificate"), text(second.Data, "privateKey"), []string{"wrong.example.test"}); err == nil {
		t.Fatal("wrong certificate hostname accepted")
	}
	if _, err := validateCertificatePair(text(second.Data, "certificate"), text(second.Data, "privateKey"), []string{"*.example.test"}); err == nil {
		t.Fatal("a single host certificate satisfied a wildcard")
	}
}

func TestACMEEABAndAutomaticDeployment(t *testing.T) {
	a, _ := subscriptionFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ca, _ := localACMEFixture(t, port, true)
	ctx := context.Background()
	_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "auto-cert-node", Data: map[string]any{"name": "Auto deploy", "address": "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := a.DB.SaveRecord(ctx, store.Record{Collection: "certificates", ID: "auto-cert", Data: map[string]any{
		"name": "node.example.test", "email": "admin@example.test", "challenge": "HTTP-01", "httpChallengeHost": "127.0.0.1", "httpChallengePort": port,
		"acmeDirectory": ca.URL + "/directory", "caCertificatePEM": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate().Raw})),
		"termsAgreed": true, "eabKid": "fixture-account", "eabHmacKey": base64.RawURLEncoding.EncodeToString([]byte("fixture-eab-key-with-at-least-32-bytes")),
		"autoDeploy": true, "serverIds": []string{"auto-cert-node"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.issueCertificate(ctx, store.User{ID: "admin", Role: "admin"}, asset.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result["tasks"].([]any)) != 1 {
		t.Fatal("automatic deployment missing", result)
	}
	tasks, err := a.DB.ListPendingTasks(ctx, "auto-cert-node", 10)
	if err != nil || len(tasks) != 1 {
		t.Fatal("automatic deployment duplicated or missing", tasks, err)
	}
}

func TestCloudflareDDNSUpdateAndIdempotence(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	updates := 0
	address := "192.0.2.1"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case "GET":
			if r.URL.Path != "/zones/test-zone/dns_records" || r.URL.Query().Get("name") != "node.example.test" {
				http.Error(w, "wrong lookup", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []dnsRecord{{ID: "record-1", Type: "A", Name: "node.example.test", Content: address, TTL: 120}}})
		case "PUT":
			if r.URL.Path != "/zones/test-zone/dns_records/record-1" {
				http.Error(w, "wrong update", 400)
				return
			}
			var record dnsRecord
			if json.NewDecoder(r.Body).Decode(&record) != nil {
				http.Error(w, "bad body", 400)
				return
			}
			updates++
			address = record.Content
			record.ID = "record-1"
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": record})
		default:
			http.Error(w, "unexpected method", 405)
		}
	}))
	defer api.Close()
	server, _ := a.DB.GetRecord(ctx, "servers", "server")
	server.Data["ddns"] = map[string]any{"provider": "cloudflare", "zoneId": "test-zone", "name": "node.example.test", "type": "A", "apiToken": "test-token", "apiBaseURL": api.URL, "ttl": 120}
	if _, err := a.DB.SaveRecord(ctx, server); err != nil {
		t.Fatal(err)
	}
	result, err := a.syncDDNS(ctx, store.User{ID: "admin", Role: "admin"}, "server", map[string]any{"address": "192.0.2.2"})
	if err != nil || result["changed"] != true || updates != 1 {
		t.Fatalf("DDNS update: %v %v", result, err)
	}
	result, err = a.syncDDNS(ctx, store.User{ID: "admin", Role: "admin"}, "server", map[string]any{"address": "192.0.2.2"})
	if err != nil || result["changed"] != false || updates != 1 {
		t.Fatal("unchanged record was rewritten")
	}
	if _, err := a.syncDDNS(ctx, store.User{ID: "admin", Role: "admin"}, "server", map[string]any{"address": "2001:db8::1"}); err == nil {
		t.Fatal("IPv6 sent to A record")
	}
}
