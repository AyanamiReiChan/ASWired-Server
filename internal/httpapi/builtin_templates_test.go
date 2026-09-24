package httpapi

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

func TestBuiltinClashTemplateOutput(t *testing.T) {
	a, sub := subscriptionFixture(t)
	defer a.Close()
	nodes := []clientNode{
		{Name: "Package A", Protocol: "trojan", Host: "a.example.test", Port: 443, Password: "member-a", Security: "tls", Network: "tcp"},
		{Name: "Package B", Protocol: "trojan", Host: "b.example.test", Port: 8443, Password: "member-b", Security: "tls", Network: "tcp"},
	}
	for _, format := range []string{"clash", "stash"} {
		t.Run(format, func(t *testing.T) {
			output, _, _, err := a.renderClientNodes(context.Background(), sub, nodes, nil, format)
			if err != nil {
				t.Fatal(err)
			}
			var cfg struct {
				MixedPort int `yaml:"mixed-port"`
				Proxies   []struct {
					Name, Server, Password string
					Port                   int
				} `yaml:"proxies"`
				Groups []struct {
					Name, Type, URL     string
					Proxies             []string
					Interval, Tolerance int
				} `yaml:"proxy-groups"`
				Rules []string
			}
			if err := yaml.Unmarshal([]byte(output), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.MixedPort != 7890 || len(cfg.Proxies) != len(nodes) || len(cfg.Groups) != 22 {
				t.Fatalf("unexpected ports/proxies/groups: %d/%d/%d", cfg.MixedPort, len(cfg.Proxies), len(cfg.Groups))
			}
			known := map[string]bool{"DIRECT": true, "REJECT": true}
			for i, proxy := range cfg.Proxies {
				node := nodes[i]
				if proxy.Name != node.Name || proxy.Server != node.Host || proxy.Port != node.Port || proxy.Password != node.Password {
					t.Fatalf("authorized node changed: %s", proxy.Name)
				}
				known[proxy.Name] = true
			}
			for _, group := range cfg.Groups {
				if known[group.Name] {
					t.Fatalf("duplicate group: %s", group.Name)
				}
				known[group.Name] = true
			}
			for _, group := range cfg.Groups {
				for _, member := range group.Proxies {
					if !known[member] {
						t.Fatalf("unknown group member %s in %s", member, group.Name)
					}
				}
				if group.Name == "♻️ 自动选择" || group.Name == "🚀 手动切换" {
					if !slices.Equal(group.Proxies, []string{"Package A", "Package B"}) {
						t.Fatalf("node selection includes unexpected routes: %v", group.Proxies)
					}
				}
				if group.Type == "url-test" && (group.Interval != 300 || group.Tolerance != 50 || group.URL != "https://cp.cloudflare.com/generate_204") {
					t.Fatalf("invalid automatic selection settings: %+v", group)
				}
			}
			if strings.Contains(output, "__PROXY_NODES__") || strings.Contains(output, "include-all-proxies:") || strings.Contains(output, "proxy-providers:") {
				t.Fatal("unexpanded or external proxy source in output")
			}
			seen := map[string]bool{}
			for _, rule := range cfg.Rules {
				if seen[rule] {
					t.Fatalf("duplicate rule: %s", rule)
				}
				seen[rule] = true
				parts := strings.Split(rule, ",")
				policy := parts[len(parts)-1]
				if policy == "no-resolve" {
					policy = parts[len(parts)-2]
				}
				if !known[policy] {
					t.Fatalf("rule references missing policy: %s", rule)
				}
				if parts[0] == "IP-CIDR" || parts[0] == "IP-CIDR6" {
					if _, err := netip.ParsePrefix(parts[1]); err != nil {
						t.Fatalf("invalid address rule %s: %v", rule, err)
					}
				}
			}
			if len(cfg.Rules) < 10000 || cfg.Rules[len(cfg.Rules)-1] != "MATCH,🐟 漏网之鱼" {
				t.Fatal("missing classification rules or final fallback")
			}
			for domain, want := range map[string]string{
				"chatgpt.com": "💬 Ai平台", "api.openai.com": "💬 Ai平台", "claude.ai": "💬 Ai平台",
				"t.me": "📲 电报消息", "youtube.com": "📹 油管视频", "netflix.com": "🎥 奈飞视频",
				"bilibili.com": "📺 哔哩哔哩", "bing.com": "Ⓜ️ 微软Bing", "localhost": "🎯 全球直连",
			} {
				if got := firstDomainPolicy(cfg.Rules, domain); got != want {
					t.Errorf("%s routes to %s, want %s", domain, got, want)
				}
			}
		})
	}
}

func firstDomainPolicy(rules []string, domain string) string {
	for _, rule := range rules {
		parts := strings.Split(rule, ",")
		if len(parts) < 3 {
			continue
		}
		switch parts[0] {
		case "DOMAIN":
			if domain == parts[1] {
				return parts[2]
			}
		case "DOMAIN-SUFFIX":
			if domain == parts[1] || strings.HasSuffix(domain, "."+parts[1]) {
				return parts[2]
			}
		case "DOMAIN-KEYWORD":
			if strings.Contains(domain, parts[1]) {
				return parts[2]
			}
		}
	}
	return ""
}

func TestBuiltinTemplateSelectionPrecedence(t *testing.T) {
	a, sub := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	check := func(want string) {
		t.Helper()
		for _, format := range []string{"clash", "stash"} {
			rec, err := a.selectedTemplate(ctx, sub, format)
			if err != nil || rec.ID != want {
				t.Fatalf("%s template = %s, want %s: %v", format, rec.ID, want, err)
			}
		}
	}
	check("builtin-clash-default")
	for _, id := range []string{"global", "package", "subscription"} {
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: id, Data: map[string]any{"type": "Clash", "content": blankTemplate("Clash"), "isDefault": id == "global"}}); err != nil {
			t.Fatal(err)
		}
	}
	check("global")
	plan, err := a.DB.GetRecord(ctx, "plans", "plan")
	if err != nil {
		t.Fatal(err)
	}
	plan.Data["templateIds"] = map[string]any{"clash": "package"}
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	check("package")
	sub.Data["templateId"] = "subscription"
	check("subscription")
	sub.Data["skipTemplates"] = true
	check("")
	for _, format := range []string{"singbox", "surge", "loon", "egern"} {
		if builtinSubscriptionTemplate(format).ID != "" {
			t.Fatalf("Clash template selected for %s", format)
		}
	}
}

func TestGeneratorDefaultTemplateLifecycle(t *testing.T) {
	a, sub := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	h := a.Handler()
	token, err := a.Signer.Issue("admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	input := generatorInput{Name: "Package default", NodeIDs: []string{"ss-node"}, SubscriptionID: sub.ID, Format: "clash", Mode: "default", ExpiresInDays: 7, CreateLink: true}
	created := controllerRequest(t, h, "POST", "/api/subscription-generator", token, input)
	requireStatus(t, created, 200)
	data := responseMap(t, created)
	link := text(data, "url")
	id := text(data["row"].(map[string]any), "id")
	assertClashPorts(t, text(data, "content"), 7890, 443)
	if !slices.Contains(configRules(t, text(data, "content")), "MATCH,🐟 漏网之鱼") {
		t.Fatal("generator did not use the built-in default")
	}
	rec, err := a.DB.GetRecord(ctx, generatedSubscriptionCollection, id)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/generated-subscriptions/"+id, token, map[string]any{"recordVersion": rec.Version, "name": "Renamed", "templateId": ""}), 200)
	download := controllerRequest(t, h, "GET", link, "", nil)
	requireStatus(t, download, 200)
	if !slices.Contains(configRules(t, download.Body.String()), "MATCH,🐟 漏网之鱼") {
		t.Fatal("editing the generated link lost default mode")
	}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: "new-default", Data: map[string]any{"type": "Clash", "content": "mixed-port: 9876\n" + blankTemplate("Clash"), "isDefault": true}}); err != nil {
		t.Fatal(err)
	}
	download = controllerRequest(t, h, "GET", link, "", nil)
	requireStatus(t, download, 200)
	assertClashPorts(t, download.Body.String(), 9876, 443)
	if !slices.Equal(configRules(t, download.Body.String()), []string{"IP-CIDR6,::/0,REJECT,no-resolve", "MATCH,PROXY"}) {
		t.Fatal("administrator default did not replace the built-in default")
	}
	input.Mode = "custom"
	input.CreateLink = false
	custom := controllerRequest(t, h, "POST", "/api/subscription-generator", token, input)
	requireStatus(t, custom, 200)
	assertClashPorts(t, text(responseMap(t, custom), "content"), 7890, 443)
	if !slices.Equal(configRules(t, text(responseMap(t, custom), "content")), []string{"IP-CIDR6,::/0,REJECT,no-resolve", "MATCH,ASWired"}) {
		t.Fatalf("custom rules no longer bypass defaults: %v", configRules(t, text(responseMap(t, custom), "content")))
	}
	sub.Data["token"] = "rotated-parent-token"
	if _, err := a.DB.SaveRecord(ctx, sub); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "GET", link, "", nil), 422)
}

func configRules(t *testing.T, output string) []string {
	t.Helper()
	var cfg struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(output), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Rules
}
