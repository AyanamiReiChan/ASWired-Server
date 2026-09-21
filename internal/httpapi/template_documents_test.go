package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestNativeTemplateRenderingAndExtraction(t *testing.T) {
	for _, kind := range []string{"Surge", "Loon"} {
		t.Run(kind, func(t *testing.T) {
			node := clientNode{Name: "HK Test", Protocol: "trojan", Host: "node.example.test", Port: 443, Password: "node-secret", Security: "tls", Network: "tcp"}
			raw := blankTemplate(kind)
			output, err := renderINITemplate(raw, []clientNode{node}, strings.ToLower(kind))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output, "node-secret") || strings.Contains(output, "{{PROXY_NODES}}") || !strings.Contains(output, "FINAL,PROXY") {
				t.Fatal(output)
			}
			extracted, err := templateFromSubscription(output, kind)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(extracted, "node-secret") || strings.Contains(extracted, "node.example.test") || !strings.Contains(extracted, "{{PROXY_NODES}}") {
				t.Fatal("extraction leaked node or failed to generalize", extracted)
			}
			node.Name = "JP Test"
			if _, err := renderINITemplate(extracted, []clientNode{node}, strings.ToLower(kind)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, raw := range []string{
		"[Proxy Group]\nA = select, B\nB = select, A\n[Rule]\nFINAL,A\n",
		"[Proxy Group]\nA = select, DIRECT, policy-path=https://untrusted.test/sub\n[Rule]\nFINAL,A\n",
		blankTemplate("Surge") + "\n[Remote Proxy]\nhttps://untrusted.test/sub\n",
	} {
		if _, err := renderINITemplate(raw, nil, "surge"); err == nil {
			t.Fatal("unsafe native template accepted", raw)
		}
	}
}

func TestTemplateLifecycleDefaultsVisibilityHistory(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	create := func(name, kind string) string {
		t.Helper()
		response := controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "template.import", "params": map[string]any{"name": name, "type": kind, "content": blankTemplate(kind)}})
		requireStatus(t, response, 200)
		return text(responseMap(t, response)["row"].(map[string]any), "id")
	}
	first := create("one.yaml", "Clash")
	second := create("two.yaml", "Clash")
	surge := create("surge.conf", "Surge")
	for _, id := range []string{first, second, surge} {
		requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "template.default", "targetId": id}), 200)
	}
	for format, want := range map[string]string{"clash": second, "surge": surge, "loon": ""} {
		rec, err := a.selectedTemplate(ctx, store.Record{}, format)
		if err != nil || rec.ID != want {
			t.Fatalf("default %s: %s %v", format, rec.ID, err)
		}
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "template.visibility", "params": map[string]any{"visibility": map[string]any{second: true}}}), 200)
	request := httptest.NewRequest("GET", "/?template="+first, nil)
	if _, err := a.requestedTemplate(request, store.Record{}, "clash"); err == nil {
		t.Fatal("hidden template accessible")
	}
	request = httptest.NewRequest("GET", "/?template="+second, nil)
	if _, err := a.requestedTemplate(request, store.Record{}, "clash"); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "template.import", "targetId": second, "params": map[string]any{"name": "renamed.yaml", "type": "Clash", "content": "mode: global\n"}}), 200)
	saved, _ := a.DB.GetRecord(ctx, "policies", second)
	if !boolean(saved.Data, "isDefault") || !boolean(saved.Data, "userVisible") {
		t.Fatal("metadata erased")
	}
	history := controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "template.history", "targetId": second})
	requireStatus(t, history, 200)
	versions := responseMap(t, history)["versions"].([]any)
	if len(versions) != 1 {
		t.Fatal("missing history", versions)
	}
	version := text(versions[0].(map[string]any), "id")
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "template.restore", "targetId": second, "params": map[string]any{"versionId": version}}), 200)
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "rules", ID: "template-ref", Data: map[string]any{"name": "Rule", "templateId": second}})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/policies/"+second, token, nil), 409)
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/policies/"+first, token, nil), 200)
}

func TestNativeTemplateQuotedNodeNames(t *testing.T) {
	for _, kind := range []string{"Surge", "Loon"} {
		for _, name := range []string{"HK,JP", "HK=JP", "HK#JP", "HK;JP"} {
			node := clientNode{Name: name, Protocol: "trojan", Host: "node.example.test", Port: 443, Password: "node-secret", Security: "tls", Network: "tcp"}
			output, err := renderINITemplate(blankTemplate(kind), []clientNode{node}, strings.ToLower(kind))
			if err != nil {
				t.Fatalf("%s %q: %v", kind, name, err)
			}
			extracted, err := templateFromSubscription(output, kind)
			if err != nil || !strings.Contains(extracted, "{{PROXY_NODES}}") || strings.Contains(extracted, name) || strings.Contains(extracted, "node-secret") {
				t.Fatalf("%s %q: extraction failed: %v\n%s", kind, name, err, extracted)
			}
			node.Name = "Replacement"
			if _, err := renderINITemplate(extracted, []clientNode{node}, strings.ToLower(kind)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTemplateDefaultsAffectClientOutput(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	node := clientNode{Name: "Test", Protocol: "trojan", Host: "node.example.test", Port: 443, Password: "secret", Security: "tls", Network: "tcp"}
	for _, kind := range []string{"Clash", "Surge", "Loon"} {
		raw := blankTemplate(kind)
		if kind == "Clash" {
			raw = "mixed-port: 9876\n" + raw
		} else {
			raw = strings.Replace(raw, "[General]", "[General]\nloglevel = notify", 1)
		}
		_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: kind, Data: map[string]any{"name": kind, "type": kind, "content": raw, "isDefault": true}})
		if err != nil {
			t.Fatal(err)
		}
		output, _, _, err := a.renderClientNodes(ctx, store.Record{}, []clientNode{node}, nil, strings.ToLower(kind))
		if err != nil {
			t.Fatal(err)
		}
		if kind == "Clash" && !strings.Contains(output, "9876") || kind != "Clash" && !strings.Contains(output, "loglevel = notify") {
			t.Fatal("default not applied", kind, output)
		}
	}
}

func TestTemplateURLAndSubscriptionImport(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	actor := store.User{ID: "admin", Role: "admin"}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/template", http.StatusFound)
			return
		}
		if r.URL.Path == "/large" {
			w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
			return
		}
		w.Write([]byte("[custom]\ncustom_proxy_group=Select`select`[]DIRECT`.*\nruleset=Select,[]FINAL"))
	}))
	defer remote.Close()
	result, err := a.templateManagementAction(ctx, actor, actionInput{Action: "template.import", Params: map[string]any{"url": remote.URL + "/template", "type": "Clash", "version": 2, "name": "remote.yaml"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text(result, "content"), "MATCH,Select") {
		t.Fatal(result)
	}
	for _, path := range []string{"/redirect", "/large"} {
		if _, err := a.templateManagementAction(ctx, actor, actionInput{Action: "template.preview", Params: map[string]any{"url": remote.URL + path, "type": "Clash"}}); err == nil {
			t.Fatal("invalid remote import accepted", path)
		}
	}
	result, err = a.templateManagementAction(ctx, actor, actionInput{Action: "template.import", Params: map[string]any{"subscriptionId": sub.ID, "type": "Clash", "name": "from-sub.yaml"}})
	if err != nil {
		t.Fatal(err)
	}
	content := text(result, "content")
	if strings.Contains(content, "11111111-1111") || strings.Contains(content, "127.0.0.1") || !strings.Contains(content, "include-all-proxies") {
		t.Fatal("subscription credentials persisted", content)
	}
	if _, err := a.templateManagementAction(ctx, actor, actionInput{Action: "template.import", TargetID: text(result["row"].(map[string]any), "id"), Params: map[string]any{"name": "conflict", "recordVersion": 999, "content": blankTemplate("Clash")}}); err == nil {
		t.Fatal("stale edit accepted")
	}
}

func TestTemplateMemberVisibilityMetadataOnly(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	for _, visible := range []bool{true, false} {
		id := "hidden"
		if visible {
			id = "visible"
		}
		_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: id, Data: map[string]any{"name": id, "type": "Clash", "content": "private-template-body", "userVisible": visible}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := a.DB.CreateUser(ctx, store.User{ID: "template-member", Username: "template-member", Role: "user", PasswordHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	member, err := a.Signer.Issue("template-member", 0)
	if err != nil {
		t.Fatal(err)
	}
	response := controllerRequest(t, h, "GET", "/api/templates/options", member, nil)
	requireStatus(t, response, 200)
	if strings.Contains(response.Body.String(), "hidden") || strings.Contains(response.Body.String(), "private-template-body") {
		t.Fatal("private template leaked", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "visible") {
		t.Fatal("visible choice missing")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", member, map[string]any{"action": "template.visibility", "params": map[string]any{"visibility": map[string]any{"hidden": true}}}), 403)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/templates/options", token, nil), 200)
}
