package httpapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/sitecert"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestWebsiteCertificatesRequireAdminAndDefaultToExternal(t *testing.T) {
	a, h, token := controllerFixture(t)
	a.siteCertificateClient = &sitecert.Client{DataDir: t.TempDir(), StateDir: t.TempDir(), Ready: func(context.Context) error { return nil }}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/admin/certificates/sites", "", nil), 401)
	member := store.User{ID: "certificate-member", Username: "certificate-member", Role: "user", PasswordHash: "fixture"}
	if err := a.DB.CreateUser(context.Background(), member); err != nil {
		t.Fatal(err)
	}
	memberToken, err := a.Signer.Issue(member.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/admin/certificates/sites", memberToken, nil), 403)
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/admin/certificates/sites", memberToken, map[string]any{"externalHTTPS": false}), 403)
	result := controllerRequest(t, h, "GET", "/api/admin/certificates/sites", token, nil)
	requireStatus(t, result, 200)
	data := responseMap(t, result)
	if data["externalHTTPS"] != true || len(data["sites"].([]any)) != 2 {
		t.Fatal("missing websites with no certificate records", data)
	}
	if strings.Contains(result.Body.String(), "privateKey") {
		t.Fatal("site endpoint leaked private material")
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/admin/certificates/sites", token, map[string]any{}), 400)
	for _, external := range []bool{false, true, false} {
		requireStatus(t, controllerRequest(t, h, "PUT", "/api/admin/certificates/sites", token, map[string]any{"externalHTTPS": external}), 200)
		actual, err := a.externalSiteHTTPS(context.Background())
		if err != nil || actual != external {
			t.Fatal("mode change did not persist", actual, err)
		}
	}
}

func TestWebsiteOnlyCertificateDeploymentValidatesNamesAndTracksRequest(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	a.Config.PublicURL = "https://exchange.example.test"
	a.Config.KomariPublicURL = "https://other.example.test"
	a.siteCertificateClient = &sitecert.Client{DataDir: t.TempDir(), StateDir: t.TempDir(), Ready: func(context.Context) error { return nil }}
	asset := store.Record{Collection: "certificates", ID: "website-cert", Data: map[string]any{"name": "exchange.example.test", "domains": []string{"exchange.example.test"}, "type": "manual", "websiteTargets": []string{"panel"}, "autoDeploy": true}}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/certificates", token, map[string]any{"row": map[string]any{"id": asset.ID, "name": "exchange.example.test", "type": "manual", "websiteTargets": []string{"panel"}, "autoDeploy": true}}), 200)
	asset, _ = a.DB.GetRecord(ctx, "certificates", asset.ID)
	cert, key := exchangePair(t, 350)
	asset, err := a.saveCertificateMaterial(ctx, asset, cert, key, "manual")
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.deployCertificate(ctx, store.User{Role: "admin"}, asset.ID, nil)
	if err != nil || len(result["deployment_errors"].([]any)) != 1 {
		t.Fatal("external mode was bypassed", result, err)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/admin/certificates/sites", token, map[string]any{"externalHTTPS": false}), 200)
	result, err = a.deployCertificate(ctx, store.User{Role: "admin"}, asset.ID, map[string]any{"websiteTargets": []string{"komari"}})
	if err != nil || len(result["deployment_errors"].([]any)) != 1 {
		t.Fatal("wrong hostname accepted", result, err)
	}
	result, err = a.deployCertificate(ctx, store.User{Role: "admin"}, asset.ID, nil)
	if err != nil || len(result["deployment_errors"].([]any)) != 0 || result["siteDeployment"] == nil {
		t.Fatal("website-only deployment failed", result, err)
	}
	raw, err := os.ReadFile(filepath.Join(a.siteCertificateClient.DataDir, "site-certificate-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request sitecert.Request
	_ = json.Unmarshal(raw, &request)
	if request.Certificate != cert || request.PrivateKey != key || request.Sites[0] != "panel" {
		t.Fatal("bad deployment request")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("private key leaked in deployment result")
	}
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/certificates/website-cert", token, nil), 409)
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/admin/certificates/sites", token, map[string]any{"externalHTTPS": true}), 409)
}
