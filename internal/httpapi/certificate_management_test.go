package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestCertificateProviderSecretsReferencesAndDeletion(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	provider := map[string]any{"id": "dns-fixture", "name": "DNS fixture", "provider": "cloudflare", "apiToken": "private-dns-token", "zoneToken": "private-zone-token"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/dnsProviders", token, map[string]any{"row": provider}), 200)
	detail := controllerRequest(t, h, "GET", "/api/collections/dnsProviders/dns-fixture", token, nil)
	requireStatus(t, detail, 200)
	if strings.Contains(detail.Body.String(), "private-") {
		t.Fatal("DNS credentials leaked in detail")
	}
	row := responseMap(t, detail)["row"].(map[string]any)
	if row["apiTokenConfigured"] != true {
		t.Fatal("missing credential presence flag")
	}
	row["name"] = "Renamed"
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/dnsProviders/dns-fixture", token, map[string]any{"row": row}), 200)
	saved, _ := a.DB.GetRecord(ctx, "dnsProviders", "dns-fixture")
	if text(saved.Data, "apiToken") != "private-dns-token" {
		t.Fatal("blank credential edit erased saved token")
	}
	cert := map[string]any{"id": "managed-cert", "name": "exchange.example.test", "email": "admin@example.test", "challenge": "DNS-01", "dnsProviderId": "dns-fixture", "termsAgreed": true}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/certificates", token, map[string]any{"row": cert}), 200)
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/dnsProviders/dns-fixture", token, nil), 409)
	certificate, key := exchangePair(t, 201)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/certificates/managed-cert/upload", token, map[string]any{"certificate": certificate, "privateKey": key}), 200)
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "sites", ID: "site-cert", Data: map[string]any{"name": "Site", "certificateId": "managed-cert"}})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/certificates/managed-cert", token, nil), 409)
	if err := a.DB.DeleteRecord(ctx, "sites", "site-cert"); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/certificates/managed-cert", token, nil), 200)
	if _, err := a.DB.GetRecord(ctx, "_certificateMaterial", "managed-cert"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("certificate material retained", err)
	}
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/dnsProviders/dns-fixture", token, nil), 200)
}

func TestCertificateUploadOptOutAndDeploymentProjection(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "cert-node", Data: map[string]any{"name": "Certificate node", "address": "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "certificates", ID: "upload-cert", Data: map[string]any{"name": "exchange.example.test", "serverIds": []string{"cert-node"}, "autoDeploy": true}})
	if err != nil {
		t.Fatal(err)
	}
	cert, key := exchangePair(t, 202)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/admin/certificates/upload", token, map[string]any{"domain": "exchange.example.test", "cert_pem": cert, "key_pem": key, "deploy": false}), 200)
	tasks, err := a.DB.ListPendingTasks(ctx, "cert-node", 10)
	if err != nil || len(tasks) != 0 {
		t.Fatal("opt-out upload contacted agent", tasks, err)
	}
	result, err := a.deployCertificate(ctx, store.User{ID: "admin", Role: "admin"}, "upload-cert", map[string]any{"serverIds": []string{"cert-node", "missing-node", "cert-node"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result["tasks"].([]any)) != 1 || len(result["deployment_errors"].([]any)) != 1 {
		t.Fatal("partial deployment not reported", result)
	}
	tasks, _ = a.DB.ListPendingTasks(ctx, "cert-node", 10)
	projected := taskRow(tasks[0])
	if text(projected, "certificateId") != "upload-cert" {
		t.Fatal("missing deployment identity", projected)
	}
	if text(projected, "certificateSerial") != "202" {
		t.Fatal("missing certificate version in deployment", projected)
	}
	raw, _ := json.Marshal(projected)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("deployment leaked key")
	}
}

func TestCertificateValidationRejectsInvalidAutomation(t *testing.T) {
	a, h, token := controllerFixture(t)
	_ = a
	for _, row := range []map[string]any{
		{"id": "bad-wildcard", "name": "*.example.test", "email": "admin@example.test", "challenge": "HTTP-01", "httpChallengePort": 8080},
		{"id": "bad-dns", "name": "example.test", "email": "admin@example.test", "dnsProviderId": "missing"},
		{"id": "bad-deploy", "name": "example.test", "type": "manual", "autoDeploy": true},
	} {
		requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/certificates", token, map[string]any{"row": row}), 400)
	}
}
