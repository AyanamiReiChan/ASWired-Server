package httpapi

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

func subscriptionIPv6Output(t *testing.T, output string) map[string]any {
	t.Helper()
	var config map[string]any
	if err := yaml.Unmarshal([]byte(output), &config); err != nil || config == nil {
		t.Fatalf("invalid subscription: %v", err)
	}
	return config
}

func assertSubscriptionIPv6Protected(t *testing.T, config map[string]any, format string) {
	t.Helper()
	dns, ok := config["dns"].(map[string]any)
	if !ok {
		t.Fatal("missing DNS protection")
	}
	switch format {
	case "clash", "stash":
		if config["ipv6"] != false || dns["ipv6"] != false {
			t.Fatal("Clash IPv6 switch not enforced")
		}
		rules := stringList(config["rules"])
		if len(rules) == 0 || rules[0] != "IP-CIDR6,::/0,REJECT,no-resolve" {
			t.Fatal("Clash protection did not precede template rules", rules)
		}
	case "singbox":
		if dns["strategy"] != "ipv4_only" {
			t.Fatal("sing-box DNS strategy not constrained")
		}
		dnsRules := mapList(dns["rules"])
		if len(dnsRules) == 0 || text(dnsRules[0], "action") != "reject" || dnsRules[0]["no_drop"] != true || !reflect.DeepEqual(stringList(dnsRules[0]["query_type"]), []string{"AAAA"}) {
			t.Fatal("sing-box AAAA protection did not precede DNS rules", dnsRules)
		}
		route, _ := config["route"].(map[string]any)
		rules := mapList(route["rules"])
		if len(rules) == 0 || number(rules[0], "ip_version") != 6 || text(rules[0], "action") != "reject" {
			t.Fatal("sing-box destination protection missing", rules)
		}
	case "egern":
		if config["ipv6"] != false || len(stringList(dns["block_ips"])) == 0 || stringList(dns["block_ips"])[0] != "::/0" {
			t.Fatal("Egern IPv6/DNS protection missing")
		}
		rules := mapList(config["rules"])
		if len(rules) == 0 {
			t.Fatal("Egern destination protection missing")
		}
		guard, _ := rules[0]["ip_cidr6"].(map[string]any)
		if text(guard, "match") != "::/0" || text(guard, "policy") != "REJECT" || guard["no_resolve"] != true {
			t.Fatal("Egern destination protection missing", guard)
		}
	}
}

func TestSubscriptionIPv6DefaultsAndExplicitOptOut(t *testing.T) {
	for _, format := range []string{"clash", "singbox", "egern"} {
		t.Run(format, func(t *testing.T) {
			a, sub := subscriptionFixture(t)
			ctx := context.Background()
			nodes, err := a.eligibleNodes(ctx, sub)
			if err != nil || len(nodes) != 1 {
				t.Fatal(nodes, err)
			}
			// Literal IPv6 node addresses remain authorized endpoints. The
			// destination rule must not remove or rewrite subscription nodes.
			nodes[0].Data["host"] = "2001:db8::1234"
			for _, settings := range []map[string]any{{}, {"blockProxyIPv6": nil}, {"blockProxyIPv6": true}} {
				if err := a.DB.SetSetting(ctx, "settings", settings); err != nil {
					t.Fatal(err)
				}
				output, _, skipped, err := a.renderSubscription(ctx, sub, nodes, format)
				if err != nil || skipped != 0 {
					t.Fatalf("protected render failed: %v, skipped %d", err, skipped)
				}
				assertSubscriptionIPv6Protected(t, subscriptionIPv6Output(t, output), format)
				if !strings.Contains(output, "2001:db8::1234") {
					t.Fatal("IPv6 endpoint was filtered or rewritten")
				}
			}
			if err := a.DB.SetSetting(ctx, "settings", map[string]any{"blockProxyIPv6": false}); err != nil {
				t.Fatal(err)
			}
			output, _, _, err := a.renderSubscription(ctx, sub, nodes, format)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output, "IP-CIDR6,::/0,REJECT,no-resolve") || strings.Contains(output, "ipv4_only") || strings.Contains(output, "ip_cidr6:") {
				t.Fatal("explicit opt-out still injected IPv6 protection")
			}
		})
	}
}

func TestSubscriptionIPv6ProtectionWinsAfterJavaScript(t *testing.T) {
	for _, item := range []struct {
		format, script string
	}{
		{"clash", `config.ipv6=true; config.dns={ipv6:true,nameserver:['1.1.1.1']}; config.rules=['MATCH,DIRECT'];`},
		{"singbox", `config.dns={strategy:'ipv6_only',rules:[{domain:['example.test'],action:'reject'}]}; config.route={final:'direct',rules:[{ip_version:6,outbound:'direct'}]};`},
		{"egern", `config.ipv6=true; config.dns={block_ips:['127.0.0.0/8']}; config.rules=[{default:'DIRECT'}];`},
	} {
		t.Run(item.format, func(t *testing.T) {
			a, sub := subscriptionFixture(t)
			ctx := context.Background()
			if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "rules", ID: "ipv6-script", Data: map[string]any{"script": "function main(config){" + item.script + "config.marker='executed'; return config;}"}}); err != nil {
				t.Fatal(err)
			}
			sub.Data["scriptId"] = "ipv6-script"
			nodes, err := a.eligibleNodes(ctx, sub)
			if err != nil {
				t.Fatal(err)
			}
			output, _, _, err := a.renderSubscription(ctx, sub, nodes, item.format)
			if err != nil {
				t.Fatal(err)
			}
			config := subscriptionIPv6Output(t, output)
			if text(config, "marker") != "executed" {
				t.Fatal("test did not execute the override script")
			}
			assertSubscriptionIPv6Protected(t, config, item.format)
			if err := a.DB.SetSetting(ctx, "settings", map[string]any{"blockProxyIPv6": false}); err != nil {
				t.Fatal(err)
			}
			output, _, _, err = a.renderSubscription(ctx, sub, nodes, item.format)
			if err != nil {
				t.Fatal(err)
			}
			config = subscriptionIPv6Output(t, output)
			if item.format == "singbox" {
				dns, _ := config["dns"].(map[string]any)
				if text(dns, "strategy") != "ipv6_only" {
					t.Fatal("opt-out overwrote the script's DNS configuration")
				}
			} else if config["ipv6"] != true {
				t.Fatal("opt-out overwrote explicit IPv6 configuration")
			}
		})
	}
}

func TestSubscriptionIPv6ProtectionPreservesURIAndMergedNodes(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	nodes, err := a.eligibleNodes(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	nodes[0].Data["host"] = "2001:db8::1234"
	for _, format := range []string{"v2ray", "shadowrocket"} {
		output, _, skipped, err := a.renderSubscription(ctx, sub, nodes, format)
		if err != nil || skipped != 0 {
			t.Fatal(output, skipped, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
		if err != nil || !strings.Contains(string(decoded), "@[2001:db8::1234]:443") || !strings.HasPrefix(string(decoded), "vless://") {
			t.Fatal("URI-only output changed or endpoint was filtered", string(decoded), err)
		}
	}
	for _, format := range []string{"clash", "singbox", "egern"} {
		output, _, skipped, err := a.renderMergedSubscription(ctx, []store.Record{sub}, format)
		if err != nil || skipped != 0 {
			t.Fatal(output, skipped, err)
		}
		assertSubscriptionIPv6Protected(t, subscriptionIPv6Output(t, output), format)
	}
}

func TestSubscriptionIPv6GeneratorModesAndLinkDownloads(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	handler := a.Handler()
	token, err := a.Signer.Issue("admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: "guard-template", Data: map[string]any{"type": "Clash", "content": "ipv6: true\ndns:\n  ipv6: true\n" + blankTemplate("Clash")}}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"default", "custom", "template"} {
		t.Run(mode, func(t *testing.T) {
			if err := a.DB.SetSetting(ctx, "settings", map[string]any{}); err != nil {
				t.Fatal(err)
			}
			input := generatorInput{Name: "IPv6 guarded " + mode, NodeIDs: []string{"ss-node"}, SubscriptionID: sub.ID, Format: "clash", Mode: mode, TemplateID: "guard-template", Categories: []string{"private", "ai"}, ExpiresInDays: 7, CreateLink: true}
			created := controllerRequest(t, handler, "POST", "/api/subscription-generator", token, input)
			requireStatus(t, created, 200)
			data := responseMap(t, created)
			preview := text(data, "content")
			assertSubscriptionIPv6Protected(t, subscriptionIPv6Output(t, preview), "clash")
			if mode == "custom" && !strings.Contains(preview, "DOMAIN-SUFFIX,openai.com,ASWired") {
				t.Fatal("network protection discarded custom categories")
			}
			link := text(data, "url")
			download := controllerRequest(t, handler, "GET", link, "", nil)
			requireStatus(t, download, 200)
			assertSubscriptionIPv6Protected(t, subscriptionIPv6Output(t, download.Body.String()), "clash")
			if strings.Count(download.Body.String(), "IP-CIDR6,::/0,REJECT,no-resolve") != 1 {
				t.Fatal("final protection duplicated the generated rule")
			}
			// Existing links must respect the current global opt-out at download,
			// instead of permanently embedding the policy at link creation.
			if err := a.DB.SetSetting(ctx, "settings", map[string]any{"blockProxyIPv6": false}); err != nil {
				t.Fatal(err)
			}
			download = controllerRequest(t, handler, "GET", link, "", nil)
			requireStatus(t, download, 200)
			if strings.Contains(download.Body.String(), "IP-CIDR6,::/0,REJECT,no-resolve") {
				t.Fatal("generated link ignored the current IPv6 opt-out")
			}
		})
	}
}

func TestSubscriptionIPv6ProtectionIsStableAndRejectsInvalidShapes(t *testing.T) {
	for _, format := range []string{"clash", "stash", "singbox", "egern"} {
		input := map[string]any{"marker": "preserved"}
		first, err := protectSubscriptionIPv6(input, format)
		if err != nil {
			t.Fatal(format, err)
		}
		second, err := protectSubscriptionIPv6(first, format)
		if err != nil || !reflect.DeepEqual(first, second) || len(input) != 1 {
			t.Fatal("protection mutated its source or duplicated rules", format, second, err)
		}
		if _, err := protectSubscriptionIPv6(map[string]any{"dns": false}, format); err == nil {
			t.Fatal("invalid DNS object silently overwritten", format)
		}
		invalidRules := map[string]any{"rules": "MATCH,DIRECT"}
		if format == "singbox" {
			invalidRules = map[string]any{"route": map[string]any{"rules": "invalid"}}
		}
		if _, err := protectSubscriptionIPv6(invalidRules, format); err == nil {
			t.Fatal("invalid rules silently discarded", format)
		}
	}
}

// Set ASWIRED_TEST_SINGBOX to an official sing-box binary to additionally
// validate the generated document with the client's own schema parser.
func TestSubscriptionIPv6SingBoxClientCheck(t *testing.T) {
	binary := os.Getenv("ASWIRED_TEST_SINGBOX")
	if binary == "" {
		t.Skip("ASWIRED_TEST_SINGBOX is not configured")
	}
	a, sub := subscriptionFixture(t)
	nodes, err := a.eligibleNodes(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	output, _, _, err := a.renderSubscription(context.Background(), sub, nodes, "singbox")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte(output), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if result, err := exec.CommandContext(ctx, binary, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box rejected generated IPv6 protection: %s\n%v", result, err)
	}
}
