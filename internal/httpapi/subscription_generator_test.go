package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

func TestGeneratorFilesAndLinkLifecycle(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	nodeData := map[string]any{"name": "Imported Trojan", "protocol": "trojan", "host": "node.example.test", "port": 443, "password": "test-secret", "security": "tls", "network": "tcp", "status": "启用"}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "trojan", Data: nodeData}); err != nil {
		t.Fatal(err)
	}
	input := generatorInput{Name: "Generator test", NodeIDs: []string{"trojan"}, Format: "clash", Mode: "custom", Categories: []string{"private", "ai", "china"}, ExpiresInDays: 7}
	options := controllerRequest(t, h, "GET", "/api/subscription-generator", token, nil)
	requireStatus(t, options, 200)
	if strings.Contains(options.Body.String(), "test-secret") {
		t.Fatal("options leaked credentials")
	}
	for _, format := range []string{"clash", "surge", "loon"} {
		input.Format = format
		res := controllerRequest(t, h, "POST", "/api/subscription-generator", token, input)
		requireStatus(t, res, 200)
		content := text(responseMap(t, res), "content")
		if !strings.Contains(content, "node.example.test") || !strings.Contains(content, "DOMAIN-SUFFIX,openai.com,ASWired") {
			t.Fatal(content)
		}
		if format == "clash" {
			assertClashPorts(t, content, 7890, 443)
			var cfg map[string]any
			if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
				t.Fatal(err)
			}
			if len(mapList(cfg["proxies"])) != 1 {
				t.Fatal(content)
			}
		}
	}
	records, _ := a.DB.ListRecords(ctx, generatedSubscriptionCollection, "")
	if len(records) != 0 {
		t.Fatal("file preview persisted a link")
	}
	input.Format = "clash"
	input.CreateLink = true
	res := controllerRequest(t, h, "POST", "/api/subscription-generator", token, input)
	requireStatus(t, res, 200)
	data := responseMap(t, res)
	link := text(data, "url")
	id := text(data["row"].(map[string]any), "id")
	download := controllerRequest(t, h, "GET", link, "", nil)
	requireStatus(t, download, 200)
	assertClashPorts(t, download.Body.String(), 7890, 443)
	saved, _ := a.DB.GetRecord(ctx, generatedSubscriptionCollection, id)
	if saved.Data["content"] != nil || saved.Data["token"] != nil {
		t.Fatal("link stored output credentials or raw token")
	}
	node, _ := a.DB.GetRecord(ctx, "nodes", "trojan")
	node.Data["status"] = "禁用"
	a.DB.SaveRecord(ctx, node)
	requireStatus(t, controllerRequest(t, h, "GET", link, "", nil), 422)
	node, _ = a.DB.GetRecord(ctx, "nodes", "trojan")
	node.Data["status"] = "启用"
	a.DB.SaveRecord(ctx, node)
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/subscription-generator/"+id, token, nil), 200)
	requireStatus(t, controllerRequest(t, h, "GET", link, "", nil), 404)
	input.NodeIDs = []string{"missing"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/subscription-generator", token, input), 422)
	input.NodeIDs = []string{"trojan"}
	input.Categories = []string{"not-a-rule"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/subscription-generator", token, input), 422)
	if err := a.DB.CreateUser(ctx, store.User{ID: "member", Username: "member", Role: "user", PasswordHash: "test"}); err != nil {
		t.Fatal(err)
	}
	member, _ := a.Signer.Issue("member", 0)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/subscription-generator", member, input), 403)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/subscription-generator", member, nil), 403)
}

func TestGeneratorScopeTemplatesAndParentRevocation(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	actor, _ := a.DB.UserByID(ctx, "admin")
	input := generatorInput{NodeIDs: []string{"ss-node"}, Format: "clash", Mode: "custom", SubscriptionID: sub.ID, Categories: []string{"private"}}
	parentHash := hashOpaque(text(sub.Data, "token"))
	if _, _, _, _, err := a.renderGenerated(ctx, actor, input, "127.0.0.1", parentHash); err != nil {
		t.Fatal(err)
	}
	sub.Data["token"] = "rotated-token"
	sub, _ = a.DB.SaveRecord(ctx, sub)
	if _, _, _, _, err := a.renderGenerated(ctx, actor, input, "127.0.0.1", parentHash); err == nil {
		t.Fatal("parent rotation ignored")
	}
	sub.Data["whitelist"] = "192.0.2.0/24"
	sub, _ = a.DB.SaveRecord(ctx, sub)
	if _, _, _, _, err := a.renderGenerated(ctx, actor, input, "127.0.0.1", ""); err == nil {
		t.Fatal("IP restriction ignored")
	}
	input.SubscriptionID = ""
	hidden := realityClientFixtureData()
	a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "private", OwnerID: "member", Data: hidden})
	managed := realityClientFixtureData()
	managed["managedInbound"] = true
	managed["inboundId"] = "inbound"
	a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "managed", Data: managed})
	a.DB.SaveRecord(ctx, store.Record{Collection: "sources", ID: "disabled-source", Data: map[string]any{"status": "停用"}})
	sourced := realityClientFixtureData()
	sourced["sourceId"] = "disabled-source"
	a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "sourced", Data: sourced})
	for _, id := range []string{"private", "managed", "sourced"} {
		input.NodeIDs = []string{id}
		if _, _, _, _, err := a.renderGenerated(ctx, actor, input, "127.0.0.1", ""); err == nil {
			t.Fatal("unauthorized node accepted", id)
		}
	}
	input.NodeIDs = []string{"ss-node"}
	input.Mode = "template"
	input.TemplateID = "template"
	a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: "template", Data: map[string]any{"type": "Clash", "content": "mixed-port: 9876\n" + blankTemplate("Clash")}})
	output, _, _, _, err := a.renderGenerated(ctx, actor, input, "127.0.0.1", "")
	if err != nil || !strings.Contains(output, "9876") {
		t.Fatal(output, err)
	}
	assertClashPorts(t, output, 9876, 443)
	input.Format = "surge"
	if _, _, _, _, err := a.renderGenerated(ctx, actor, input, "127.0.0.1", ""); err == nil {
		t.Fatal("incompatible node or template accepted")
	}
}

func TestGeneratorExpiryAndCreatorRevocation(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	data := map[string]any{"nodeIds": []string{"ss-node"}, "format": "clash", "mode": "custom", "categories": []string{}, "expiresAt": time.Now().Add(time.Hour).Format(time.RFC3339), "tokenVersion": 0}
	token := strings.Repeat("a", 48)
	rec, _ := a.DB.SaveRecord(ctx, store.Record{Collection: generatedSubscriptionCollection, ID: hashOpaque(token), OwnerID: "admin", Data: data})
	request := func() int {
		w := httptest.NewRecorder()
		a.generatorDownload(w, httptest.NewRequest("GET", "/api/generated-subscribe?token="+token, nil))
		return w.Code
	}
	if code := request(); code != 200 {
		t.Fatal(code, sub.ID)
	}
	rec.Data["tokenVersion"] = 999
	rec, _ = a.DB.SaveRecord(ctx, rec)
	if request() != 403 {
		t.Fatal("creator version ignored")
	}
	rec.Data["tokenVersion"] = 0
	rec.Data["expiresAt"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
	a.DB.SaveRecord(ctx, rec)
	if request() != 404 {
		t.Fatal("expired link accepted")
	}
}
