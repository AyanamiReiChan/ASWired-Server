package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
	"testing"
)

func TestTemplateSelectorsProvidersAndChains(t *testing.T) {
	cfg := map[string]any{"regionFilter": "(?i)hk|香港", "mode": "rule", "proxies": []any{map[string]any{"name": "HK VLESS", "type": "vless"}, map[string]any{"name": "HK test", "type": "vless"}, map[string]any{"name": "JP Trojan", "type": "trojan"}}, "proxy-providers": map[string]any{"provider": map[string]any{"type": "http"}}, "proxy-groups": []any{map[string]any{"name": "Japan", "type": "select", "include-all": true, "filter": "JP"}, map[string]any{"name": "HK", "type": "url-test", "include-all": true, "filter": "regionFilter", "exclude-filter": "test", "include-type": "vless", "dialer-proxy-group": "Japan"}, map[string]any{"name": "Empty", "type": "select", "include-all-proxies": true, "filter": "DOES_NOT_EXIST"}, map[string]any{"name": "All", "type": "select", "proxies": []string{"Empty", "HK", "DIRECT"}}}, "rules": []string{"DOMAIN,unused.test,Empty", "MATCH,All"}}
	expanded, e := expandTemplate(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := expanded["regionFilter"]; ok {
		t.Fatal("template variable leaked")
	}
	groups := mapList(expanded["proxy-groups"])
	if len(groups) != 3 {
		t.Fatalf("empty group not removed: %d", len(groups))
	}
	hk := groups[1]
	if names := stringList(hk["proxies"]); len(names) != 1 || names[0] != "HK VLESS · HK" {
		t.Fatalf("filter result %#v", names)
	}
	if len(stringList(hk["use"])) != 1 {
		t.Fatal("provider inclusion lost")
	}
	for _, key := range []string{"filter", "exclude-filter", "include-type", "include-all", "dialer-proxy-group"} {
		if _, ok := hk[key]; ok {
			t.Fatal("template-only field leaked")
		}
	}
	if len(stringList(expanded["rules"])) != 1 {
		t.Fatal("empty-group rule remained")
	}
	found := false
	for _, n := range mapList(expanded["proxies"]) {
		if text(n, "name") == "HK VLESS · HK" && text(n, "dialer-proxy") == "Japan" {
			found = true
		}
	}
	if !found {
		t.Fatal("chain did not create per-group dialer")
	}
}
func TestTemplateRejectsCyclesAndMalformedFilters(t *testing.T) {
	for _, cfg := range []map[string]any{{"a": "b", "b": "a", "proxy-groups": []any{map[string]any{"name": "loop", "filter": "a"}}}, {"proxy-groups": []any{map[string]any{"name": "a", "proxies": []string{"b"}}, map[string]any{"name": "b", "proxies": []string{"a"}}}}, {"proxy-groups": []any{map[string]any{"name": "bad", "filter": "["}}}} {
		if _, e := expandTemplate(cfg); e == nil {
			t.Fatal("unsafe template accepted")
		}
	}
}
func TestTemplateV2NormalizationAndRuleOrder(t *testing.T) {
	cfg, warnings, e := normalizeTemplate("[custom]\ncustom_proxy_group=Select`select`[]DIRECT`HK\nruleset=Select,[]FINAL", 2)
	if e != nil || len(warnings) > 0 {
		t.Fatalf("V2: %v %#v", e, warnings)
	}
	if !strings.Contains(text(mapList(cfg["proxy-groups"])[0], "filter"), "HK") {
		t.Fatal("V2 filter lost")
	}
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	a.DB.SaveRecord(ctx, store.Record{Collection: "rules", ID: "before", Data: map[string]any{"name": "first", "type": "rules", "mode": "前置", "content": "rules:\n  - DOMAIN,test.invalid,REJECT\n"}})
	out, e := a.applyRuleOverrides(ctx, store.Record{}, cfg, "clash")
	if e != nil {
		t.Fatal(e)
	}
	rules := stringList(out["rules"])
	if len(rules) != 2 || rules[0] != "DOMAIN,test.invalid,REJECT" || rules[1] != "MATCH,Select" {
		t.Fatalf("wrong override order: %#v", rules)
	}
}
