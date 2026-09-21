package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func exchangePair(t *testing.T, serial int64) (string, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "exchange.example.test"}, DNSNames: []string{"exchange.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	priv, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}))
}
func TestCertificatePushDownloadAndDomainUpdate(t *testing.T) {
	a, h, token := controllerFixture(t)
	cert, key := exchangePair(t, 101)
	payload := map[string]any{"domain": "exchange.example.test", "cert_pem": base64.StdEncoding.EncodeToString([]byte(cert)), "key_pem": key}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/admin/certificates/upload", "", payload), 401)
	res := controllerRequest(t, h, "POST", "/api/admin/certificates/upload", token, payload)
	requireStatus(t, res, 200)
	id := text(responseMap(t, res), "certificate_id")
	if id == "" {
		t.Fatal("missing certificate id")
	}
	if strings.Contains(res.Body.String(), "PRIVATE KEY") {
		t.Fatal("private key exposed in upload response")
	}
	cert2, key2 := exchangePair(t, 102)
	payload["cert_pem"] = cert2
	payload["key_pem"] = key
	requireStatus(t, controllerRequest(t, h, "POST", "/api/admin/certificates/upload", token, payload), 400)
	old, _ := a.DB.GetRecord(context.Background(), "certificates", id)
	if text(old.Data, "serial") != "101" {
		t.Fatal("invalid pair modified certificate")
	}
	ctx := context.Background()
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "deployment-node", Data: map[string]any{"name": "fixture", "address": "127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "reference", Data: map[string]any{"certificateId": id, "serverId": "deployment-node"}}); err != nil {
		t.Fatal(err)
	}
	payload["key_pem"] = base64.StdEncoding.EncodeToString([]byte(key2))
	res = controllerRequest(t, h, "POST", "/api/admin/certificates/upload", token, payload)
	requireStatus(t, res, 200)
	if text(responseMap(t, res), "certificate_id") != id {
		t.Fatal("same domain duplicated")
	}
	tasks, err := a.DB.ListPendingTasks(ctx, "deployment-node", 10)
	if err != nil || len(tasks) != 1 || tasks[0].Kind != "certificate.deploy" {
		t.Fatal("referenced certificate not queued", tasks, err)
	}
	var cmd map[string]any
	if err = json.Unmarshal(tasks[0].Input, &cmd); err != nil {
		t.Fatal(err)
	}
	params, _ := cmd["params"].(map[string]any)
	if text(params, "private_key") != key2 {
		t.Fatal("deployment did not receive validated new pair")
	}
	if err = a.DB.CreateUser(ctx, store.User{ID: "member-download", Username: "member-download", PasswordHash: "hash", Role: "user"}); err != nil {
		t.Fatal(err)
	}
	memberToken, err := a.Signer.Issue("member-download", 0)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/certificates/"+id+"/download", memberToken, nil), 403)
	download := controllerRequest(t, h, "GET", "/api/certificates/"+id+"/download", token, nil)
	requireStatus(t, download, 200)
	if download.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secret download cached")
	}
	z, e := zip.NewReader(bytes.NewReader(download.Body.Bytes()), int64(download.Body.Len()))
	if e != nil || len(z.File) != 2 {
		t.Fatal(e)
	}
	if z.File[0].Name != "fullchain.pem" || z.File[1].Name != "privkey.pem" {
		t.Fatal("wrong zip entries")
	}
	var count int
	if e = a.DB.DB().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='certificate.download'`).Scan(&count); e != nil || count != 1 {
		t.Fatal("missing download audit", e, count)
	}
}
func TestIndependentDNSProviderConfigurations(t *testing.T) {
	t.Setenv("ALICLOUD_ACCESS_KEY", "must-not-be-used")
	t.Setenv("TENCENTCLOUD_SECRET_ID", "must-not-be-used")
	t.Setenv("NAMESILO_API_KEY", "must-not-be-used")
	for _, row := range []map[string]any{{"provider": "cloudflare", "apiToken": "cloudflare-test"}, {"provider": "alidns", "accessKeyId": "ali-test", "accessKeySecret": "ali-secret"}, {"provider": "dnspodcn", "secretId": "tencent-test", "secretKey": "tencent-secret"}, {"provider": "namesilo", "apiKey": "namesilo-test"}} {
		provider, e := dnsChallengeProvider(row, &http.Client{Timeout: time.Second})
		if e != nil || provider == nil {
			t.Fatalf("%s: %v", text(row, "provider"), e)
		}
		if _, e = dnsChallengeProvider(map[string]any{"provider": row["provider"]}, http.DefaultClient); e == nil {
			t.Fatal("environment credentials used", row["provider"])
		}
	}
}
