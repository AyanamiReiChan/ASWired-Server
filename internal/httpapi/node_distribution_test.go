package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

func TestRealitySourceImportFiltersProfilesAndPreservesLastValidData(t *testing.T) {
	for _, format := range []string{"uri", "base64", "clash"} {
		t.Run(format, func(t *testing.T) {
			a, _, _ := controllerFixture(t)
			ctx := context.Background()
			valid := realityClientFixtureURI("proxy.example.test", "Allowed")
			invalid := "trojan://fixture-password@legacy.example.test:443?type=xhttp#Unsupported"
			encode := func(includeValid bool) string {
				t.Helper()
				lines := []string{invalid}
				if includeValid {
					lines = append([]string{valid}, lines...)
				}
				if format == "clash" {
					proxies := []any{}
					for _, uri := range lines {
						parsed, err := parseImportedURI(uri)
						if err != nil {
							t.Fatal(err)
						}
						node, err := clientNodeFor(store.Record{Data: parsed}, store.Record{})
						if err != nil {
							t.Fatal(err)
						}
						proxies = append(proxies, clashNode(node))
					}
					raw, err := yaml.Marshal(map[string]any{"proxies": proxies})
					if err != nil {
						t.Fatal(err)
					}
					return string(raw)
				}
				body := strings.Join(lines, "\n")
				if format == "base64" {
					return base64.StdEncoding.EncodeToString([]byte(body))
				}
				return body
			}
			body := encode(true)
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer fixture.Close()
			if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "sources", ID: "profile-source", Data: map[string]any{"name": "Profile fixture", "url": fixture.URL}}); err != nil {
				t.Fatal(err)
			}
			result, err := a.syncSource(ctx, "profile-source")
			if err != nil || !boolean(result, "success") || number(result, "nodes") != 1 || number(result, "updated") != 1 || number(result, "skipped") != 1 || len(stringList(result["reasons"])) != 1 {
				t.Fatalf("mixed source did not report one accepted and one rejected node: %v %v", result, err)
			}
			nodes, err := a.DB.ListRecords(ctx, "nodes", "")
			if err != nil || len(nodes) != 1 || text(nodes[0].Data, "name") != "Allowed" || text(nodes[0].Data, "sourceId") != "profile-source" {
				t.Fatalf("mixed source persisted unexpected nodes: %v %v", nodes, err)
			}
			if _, err := normalizedRealityNode(nodes[0].Data, true); err != nil {
				t.Fatalf("imported node is not complete Reality: %v", err)
			}
			previousNode := nodes[0]
			previousSource, err := a.DB.GetRecord(ctx, "sources", "profile-source")
			if err != nil {
				t.Fatal(err)
			}
			body = encode(false)
			result, err = a.syncSource(ctx, "profile-source")
			if err == nil || boolean(result, "success") || number(result, "updated") != 0 || number(result, "skipped") != 1 || len(stringList(result["reasons"])) != 1 {
				t.Fatalf("all-invalid source was not explicitly rejected: %v %v", result, err)
			}
			currentNode, err := a.DB.GetRecord(ctx, "nodes", previousNode.ID)
			if err != nil || currentNode.Version != previousNode.Version || !reflect.DeepEqual(currentNode.Data, previousNode.Data) || disabledStatus(currentNode.Data) {
				t.Fatalf("all-invalid source altered its last valid node: %v", err)
			}
			currentSource, err := a.DB.GetRecord(ctx, "sources", "profile-source")
			if err != nil || currentSource.Version != previousSource.Version || !reflect.DeepEqual(currentSource.Data, previousSource.Data) {
				t.Fatalf("failed import changed source success metadata: %v", err)
			}
		})
	}
}

func TestRealityFederationRejectsInvalidSelectionBeforePublishing(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	admin, err := a.DB.UserByID(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	good, err := a.federationAction(ctx, admin, actionInput{Action: "federation.publish", TargetID: "valid-share", Params: map[string]any{"nodeIds": []any{"ss-node"}}})
	if err != nil || text(good, "id") != "valid-share" || text(good, "token") == "" {
		t.Fatalf("valid Reality selection could not publish: %v", err)
	}
	previous, err := a.DB.GetRecord(ctx, "_federationShares", "valid-share")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		field string
		value string
	}{{"protocol", "protocol", "Trojan"}, {"security", "security", "tls"}, {"transport", "network", "ws"}, {"public-key", "publicKey", "invalid"}} {
		t.Run(test.name, func(t *testing.T) {
			data := realityClientFixtureData()
			data[test.field] = test.value
			id := "unsupported-" + test.name
			if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: id, Data: data}); err != nil {
				t.Fatal(err)
			}
			for _, shareID := range []string{"valid-share", "new-" + test.name} {
				if _, err := a.federationAction(ctx, admin, actionInput{Action: "federation.publish", TargetID: shareID, Params: map[string]any{"nodeIds": []any{"ss-node", id}}}); err == nil {
					t.Fatal("mixed selection published an unsupported node")
				}
			}
			current, err := a.DB.GetRecord(ctx, "_federationShares", "valid-share")
			if err != nil || current.Version != previous.Version || !reflect.DeepEqual(current.Data, previous.Data) {
				t.Fatalf("invalid replacement altered existing share or token: %v", err)
			}
			if _, err := a.DB.GetRecord(ctx, "_federationShares", "new-"+test.name); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("invalid selection created a share: %v", err)
			}
		})
	}
}

func TestRealitySubscriptionOutputRejectsInjectedProxiesAndProviders(t *testing.T) {
	node, err := clientNodeFor(store.Record{Data: realityClientFixtureData()}, store.Record{})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"clash", "singbox", "egern"} {
		t.Run(format, func(t *testing.T) {
			field := "proxies"
			allowed := clashNode(node)
			injected := map[string]any{"name": "Injected", "type": "trojan", "server": "legacy.example.test", "port": 443, "password": "fixture-password"}
			if format == "singbox" {
				field = "outbounds"
				allowed = singboxNode(node)
				injected = map[string]any{"tag": "Injected", "type": "trojan", "server": "legacy.example.test", "server_port": 443, "password": "fixture-password", "tls": map[string]any{"enabled": true}}
			} else if format == "egern" {
				allowed = egernNode(node)
				injected = map[string]any{"trojan": map[string]any{"name": "Injected", "server": "legacy.example.test", "port": 443, "password": "fixture-password"}}
			}
			valid := map[string]any{field: []any{allowed}}
			if err := validateSubscriptionOutput(valid, format, []clientNode{node}); err != nil {
				t.Fatalf("valid renderer output rejected: %v", err)
			}
			if err := validateSubscriptionOutput(map[string]any{field: []any{allowed, injected}}, format, []clientNode{node}); err == nil {
				t.Fatal("injected unsupported proxy accepted")
			}
			withProviders := map[string]any{field: []any{allowed}, "proxy-providers": map[string]any{"unverified": map[string]any{"type": "http", "url": "https://provider.example.test/subscription"}}}
			if err := validateSubscriptionOutput(withProviders, format, []clientNode{node}); err == nil {
				t.Fatal("unverified remote provider accepted")
			}
		})
	}
	if err := validateSubscriptionOutput(map[string]any{"outbounds": []any{singboxNode(node), map[string]any{"type": "selector", "tag": "Select", "outbounds": []string{node.Name, "direct"}}, map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "block", "tag": "block"}}}, "singbox", []clientNode{node}); err != nil {
		t.Fatalf("infrastructure outbounds were incorrectly rejected: %v", err)
	}
}

func TestRealityDistributionRejectsTemplateAndScriptInjection(t *testing.T) {
	for _, test := range []struct {
		name     string
		template string
		script   string
	}{
		{"template-provider", "proxy-providers:\n  unverified:\n    type: http\n    url: https://provider.example.test/subscription\n", ""},
		{"script-proxy", "", "function main(config) { config.proxies.push({ name: 'Injected', type: 'trojan', server: 'legacy.example.test', port: 443, password: 'fixture-password' }); return config; }"},
		{"script-provider", "", "function main(config) { config['proxy-providers'] = { unverified: { type: 'http', url: 'https://provider.example.test/subscription' } }; return config; }"},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, sub := subscriptionFixture(t)
			ctx := context.Background()
			nodes, err := a.eligibleNodes(ctx, sub)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("valid baseline node unavailable: %v", err)
			}
			if test.template != "" {
				if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: "unsafe-template", Data: map[string]any{"content": test.template}}); err != nil {
					t.Fatal(err)
				}
				sub.Data["templateId"] = "unsafe-template"
			}
			if test.script != "" {
				if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "rules", ID: "unsafe-script", Data: map[string]any{"script": test.script}}); err != nil {
					t.Fatal(err)
				}
				sub.Data["scriptId"] = "unsafe-script"
			}
			if output, _, _, err := a.renderSubscription(ctx, sub, nodes, "clash"); err == nil || output != "" {
				t.Fatalf("post-template output bypassed distribution policy: %v", err)
			}
		})
	}
}
