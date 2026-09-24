package httpapi

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestPolicySettingsDefaultsVisibleWithoutWritingMigration(t *testing.T) {
	a, handler, token := controllerFixture(t)
	ctx := context.Background()
	for _, saved := range []map[string]any{{}, {"behaviorLimits": nil, "blockProxyIPv6": nil}} {
		if err := a.DB.SetSetting(ctx, "settings", saved); err != nil {
			t.Fatal(err)
		}
		r := controllerRequest(t, handler, "GET", "/api/settings", token, nil)
		requireStatus(t, r, 200)
		settings := responseMap(t, r)["settings"].(map[string]any)
		cfg, err := behaviorConfiguration(settings["behaviorLimits"], "global")
		if err != nil || !cfg.Enabled || len(cfg.Rules) != 2 || settings["blockProxyIPv6"] != true {
			t.Fatalf("defaults not represented by settings: %+v, %v", settings, err)
		}
		var after map[string]any
		if err := a.DB.GetSetting(ctx, "settings", &after); err != nil || !reflect.DeepEqual(saved, after) {
			t.Fatalf("settings read unexpectedly persisted defaults: %+v, %v", after, err)
		}
	}
}

func TestPolicySettingsPreserveExplicitChoiceAndRejectWrongSwitchType(t *testing.T) {
	a, handler, token := controllerFixture(t)
	ctx := context.Background()
	for _, limits := range []map[string]any{{"enabled": false}, {}, {"enabled": true, "rules": []any{}}} {
		wanted := map[string]any{"blockProxyIPv6": false, "behaviorLimits": limits}
		r := controllerRequest(t, handler, "PUT", "/api/settings", token, map[string]any{"settings": wanted})
		requireStatus(t, r, 200)
		settings := responseMap(t, r)["settings"].(map[string]any)
		if settings["blockProxyIPv6"] != false || !reflect.DeepEqual(settings["behaviorLimits"], limits) {
			t.Fatalf("explicit configuration changed: %+v", settings)
		}
	}
	var before map[string]any
	if err := a.DB.GetSetting(ctx, "settings", &before); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(before)
	for _, value := range []any{"false", "true", 0, 1, []any{}, map[string]any{}} {
		r := controllerRequest(t, handler, "PUT", "/api/settings", token, map[string]any{"settings": map[string]any{"blockProxyIPv6": value}})
		requireStatus(t, r, 400)
		var after map[string]any
		if err := a.DB.GetSetting(ctx, "settings", &after); err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(after)
		if string(got) != string(want) {
			t.Fatal("invalid IPv6 switch overwrote persisted configuration")
		}
	}
}
