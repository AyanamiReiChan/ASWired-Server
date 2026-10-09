package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func firewallFixture(t *testing.T) (*App, http.Handler, string) {
	t.Helper()
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	for _, rec := range []store.Record{
		{Collection: "servers", ID: "server", Data: map[string]any{"name": "Server", "address": "127.0.0.1", "connection": "WebSocket", "agentPort": 23889}},
		{Collection: "inbounds", ID: "reality", Data: realityInboundFixtureData()},
		{Collection: "_agentCredentials", ID: "server", Data: map[string]any{"serverToken": "fixture-token"}},
	} {
		if _, err := a.DB.SaveRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	a.mu.Lock()
	a.peers["server"] = &peer{LastSeen: time.Now(), Capabilities: map[string]bool{"firewall_allowlist": true, "proxy_ipv6_guard": true}}
	a.mu.Unlock()
	return a, h, token
}

func firewallFixtureRules() []firewallRule {
	return []firewallRule{{ID: "home", Name: "Home", Protocol: "tcp", Port: 443, AllowedCIDRs: []string{"203.0.113.9/32", "2001:db8::1/128"}}}
}

func firewallSaveFixture(t *testing.T, h http.Handler, token string, revision int64, rules []firewallRule) map[string]any {
	t.Helper()
	r := controllerRequest(t, h, "PUT", "/api/servers/server/firewall", token, map[string]any{"revision": revision, "rules": rules})
	requireStatus(t, r, 202)
	return responseMap(t, r)
}

func firewallFinishFixture(t *testing.T, a *App, state map[string]any, status string, observed map[string]any) store.Task {
	t.Helper()
	ctx := context.Background()
	taskID := text(state["task"].(map[string]any), "id")
	task, err := a.DB.GetTask(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	task.Status = "running"
	task, err = a.DB.SaveTask(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	if !a.finishTask(ctx, "server", agentwire.Result{ID: taskID, Status: status, Data: observed, Error: map[string]string{"failed": "nft validation failed"}[status]}) {
		t.Fatal("receipt not saved")
	}
	return task
}

func firewallStatusFixture(state map[string]any) map[string]any {
	return map[string]any{"supported": true, "backend": "nftables", "revision": state["revision"], "rules": state["rules"], "applied": true, "checkedAt": time.Now().UTC().Format(time.RFC3339Nano)}
}

func TestFirewallAdminCapabilityAndDedicatedAPI(t *testing.T) {
	a, h, token := firewallFixture(t)
	ctx := context.Background()
	member := store.User{ID: "firewall-member", Username: "firewall-member", Role: "user", TokenVersion: 1, PasswordHash: "fixture"}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	for _, method := range []string{"GET", "PUT", "POST"} {
		path := "/api/servers/server/firewall"
		if method == "POST" {
			path += "/refresh"
		}
		requireStatus(t, controllerRequest(t, h, method, path, "", map[string]any{}), 401)
		requireStatus(t, controllerRequest(t, h, method, path, memberToken, map[string]any{}), 403)
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/servers/missing/firewall", token, nil), 404)
	for _, collection := range []string{"_firewallPolicies", "_firewallObserved"} {
		requireStatus(t, controllerRequest(t, h, "GET", "/api/collections/"+collection, token, nil), 404)
	}
	read := responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if number(read, "revision") != 0 || !boolean(read, "capable") || len(read["rules"].([]any)) != 0 || read["task"] != nil || read["observed"] != nil {
		t.Fatalf("initial state: %v", read)
	}
	a.mu.Lock()
	delete(a.peers, "server")
	a.mu.Unlock()
	read = responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if boolean(read, "capable") {
		t.Fatal("unknown capability treated as supported")
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/servers/server/firewall", token, map[string]any{"revision": 0, "rules": firewallFixtureRules()}), 409)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/servers/server/firewall/refresh", token, nil), 409)
	for _, action := range []string{"network.firewall.apply", "network.firewall.status"} {
		requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": action, "targetId": "server", "params": map[string]any{}}), 400)
		if _, err := a.queue(ctx, store.User{ID: "admin", Role: "admin"}, "server", action, nil); !errors.Is(err, errFirewallDedicatedAPI) {
			t.Fatal("generic queue bypassed firewall API", err)
		}
	}
}

func TestFirewallRulesValidateCanonicalTargets(t *testing.T) {
	targets := []firewallTarget{{ID: "reality", Protocol: "tcp", Port: 443}}
	valid := firewallFixtureRules()
	valid[0].AllowedCIDRs = []string{"203.0.113.9", "203.0.113.17/24", "2001:0db8::1/128", "203.0.113.9/32"}
	got, err := normalizeFirewallRules(valid, targets)
	if err != nil || !reflect.DeepEqual(got[0].AllowedCIDRs, []string{"2001:db8::1/128", "203.0.113.0/24", "203.0.113.9/32"}) {
		t.Fatalf("normalization: %v %v", got, err)
	}
	for _, cidr := range []string{"", "not-an-ip", "203.0.113.0/33", "fe80::1%eth0", "::ffff:203.0.113.9", "0.0.0.0/0", "::/0", "127.0.0.1", "::1", "224.0.0.1", "ff00::/8", "0.0.0.0", "::", "fe80::1", "203.0.113.9;drop"} {
		rules := firewallFixtureRules()
		rules[0].AllowedCIDRs = []string{cidr}
		if _, err := normalizeFirewallRules(rules, targets); err == nil {
			t.Errorf("accepted address %q", cidr)
		}
	}
	patches := []func(*firewallRule){
		func(r *firewallRule) { r.ID = "../escape" }, func(r *firewallRule) { r.ID = strings.Repeat("a", 65) }, func(r *firewallRule) { r.Name = strings.Repeat("字", 101) }, func(r *firewallRule) { r.Name = "x\ny" }, func(r *firewallRule) { r.Protocol = "udp" }, func(r *firewallRule) { r.Port = 22 }, func(r *firewallRule) { r.Port = 8443 }, func(r *firewallRule) { r.AllowedCIDRs = nil }, func(r *firewallRule) { r.AllowedCIDRs = make([]string, 129) },
	}
	for i, patch := range patches {
		rules := firewallFixtureRules()
		patch(&rules[0])
		if _, err := normalizeFirewallRules(rules, targets); err == nil {
			t.Errorf("accepted invalid rule %d", i)
		}
	}
	for _, rules := range [][]firewallRule{append(firewallFixtureRules(), firewallFixtureRules()...), make([]firewallRule, 65)} {
		if _, err := normalizeFirewallRules(rules, targets); err == nil {
			t.Fatal("accepted duplicate or excess rules")
		}
	}
	if rules, err := normalizeFirewallRules([]firewallRule{}, targets); err != nil || rules == nil || len(rules) != 0 {
		t.Fatal("explicit removal must be supported")
	}

	a, h, token := firewallFixture(t)
	ctx := context.Background()
	for _, candidate := range []struct {
		id       string
		port     int
		listen   string
		disabled bool
	}{
		{"ssh", 22, "0.0.0.0", false}, {"agent", 23889, "0.0.0.0", false}, {"local", 8443, "127.0.0.1", false}, {"specific", 8444, "203.0.113.1", false}, {"disabled", 8445, "0.0.0.0", true}, {"v6", 8446, "::", false},
	} {
		data := realityInboundFixtureData()
		data["port"], data["listen"] = candidate.port, candidate.listen
		if candidate.disabled {
			data["status"] = "停用"
		}
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: candidate.id, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	state := responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if len(state["targets"].([]any)) != 2 {
		t.Fatalf("unsafe targets exposed: %v", state["targets"])
	}
	duplicate := realityInboundFixtureData()
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "duplicate", Data: duplicate}); err != nil {
		t.Fatal(err)
	}
	state = responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if len(state["targets"].([]any)) != 1 || number(state["targets"].([]any)[0].(map[string]any), "port") != 8446 {
		t.Fatal("ambiguous port remained selectable")
	}
}

func TestFirewallSaveAtomicRevisionAndDispatch(t *testing.T) {
	a, h, token := firewallFixture(t)
	ctx := context.Background()
	for _, body := range []map[string]any{{"rules": []any{}}, {"revision": 0}, {"revision": 0, "rules": nil}, {"revision": -1, "rules": []any{}}, {"revision": 0.5, "rules": []any{}}, {"revision": firewallMaxRevision, "rules": []any{}}} {
		requireStatus(t, controllerRequest(t, h, "PUT", "/api/servers/server/firewall", token, body), 400)
	}
	if _, err := a.DB.DB().ExecContext(ctx, `CREATE TRIGGER reject_firewall_task BEFORE INSERT ON tasks WHEN NEW.kind='network.firewall.apply' BEGIN SELECT RAISE(ABORT,'fixture task failure'); END`); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/servers/server/firewall", token, map[string]any{"revision": 0, "rules": firewallFixtureRules()}), 409)
	if _, err := a.DB.GetRecord(ctx, "_firewallPolicies", "server"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("failed queue leaked policy")
	}
	if _, err := a.DB.DB().ExecContext(ctx, `DROP TRIGGER reject_firewall_task`); err != nil {
		t.Fatal(err)
	}
	first := firewallSaveFixture(t, h, token, 0, firewallFixtureRules())
	task, err := a.DB.GetTask(ctx, text(first["task"].(map[string]any), "id"))
	if err != nil {
		t.Fatal(err)
	}
	var command agentwire.Command
	_ = json.Unmarshal(task.Input, &command)
	if err := a.validateFirewallTask(ctx, task, command); err != nil {
		t.Fatal(err)
	}
	policy, err := a.DB.GetRecord(ctx, "_firewallPolicies", "server")
	if err != nil || text(policy.Data, "applyTaskId") != task.ID || firewallRevision(policy.Data) != 1 {
		t.Fatal("policy and queued task disagree")
	}
	if _, err := a.DB.DB().ExecContext(ctx, `CREATE TRIGGER reject_firewall_task BEFORE INSERT ON tasks WHEN NEW.kind LIKE 'network.firewall.%' BEGIN SELECT RAISE(ABORT,'fixture task failure'); END`); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/servers/server/firewall", token, map[string]any{"revision": 1, "rules": []any{}}), 409)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/servers/server/firewall/refresh", token, nil), 409)
	unchanged, err := a.DB.GetRecord(ctx, "_firewallPolicies", "server")
	if err != nil || unchanged.Version != policy.Version || !reflect.DeepEqual(unchanged.Data, policy.Data) {
		t.Fatal("failed task modified an existing policy")
	}
	if _, err := a.DB.DB().ExecContext(ctx, `DROP TRIGGER reject_firewall_task`); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/servers/server/firewall", token, map[string]any{"revision": 0, "rules": firewallFixtureRules()}), 409)
	second := firewallSaveFixture(t, h, token, 1, []firewallRule{})
	if a.permitDispatch(ctx, task) {
		t.Fatal("stale apply dispatched")
	}
	stale, _ := a.DB.GetTask(ctx, task.ID)
	if stale.Status != "failed" {
		t.Fatal("stale task failure not saved")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "task.retry", "targetId": task.ID}), 400)
	current, _ := a.DB.GetTask(ctx, text(second["task"].(map[string]any), "id"))
	a.mu.Lock()
	a.peers["server"].Capabilities["firewall_allowlist"] = false
	a.mu.Unlock()
	if a.permitDispatch(ctx, current) {
		t.Fatal("capability downgrade dispatched")
	}
	current, _ = a.DB.GetTask(ctx, current.ID)
	if current.Status != "failed" || !strings.Contains(current.Error, "升级") {
		t.Fatal("missing capability failure not visible")
	}
}

func TestFirewallReceiptsNeverConfirmStaleOrFailedPolicy(t *testing.T) {
	a, h, token := firewallFixture(t)
	ctx := context.Background()
	first := firewallSaveFixture(t, h, token, 0, firewallFixtureRules())
	task, _ := a.DB.GetTask(ctx, text(first["task"].(map[string]any), "id"))
	task.Status = "running"
	if _, err := a.DB.SaveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	second := firewallSaveFixture(t, h, token, 1, []firewallRule{})
	if !a.finishTask(ctx, "server", agentwire.Result{ID: task.ID, Status: "success", Data: firewallStatusFixture(first)}) {
		t.Fatal("old task receipt rejected")
	}
	state := responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if state["observed"] != nil {
		t.Fatal("old receipt overwrote new desired state")
	}
	firewallFinishFixture(t, a, second, "failed", firewallStatusFixture(second))
	// A cached heartbeat cannot turn a failed apply into a success.
	observed := firewallStatusFixture(second)
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_observations", ID: "server", Data: map[string]any{"network_firewall": observed}}); err != nil {
		t.Fatal(err)
	}
	state = responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if boolean(state["observed"].(map[string]any), "applied") {
		t.Fatal("failed task appeared applied through heartbeat")
	}
	third := firewallSaveFixture(t, h, token, 2, firewallFixtureRules())
	confirmed := firewallStatusFixture(third)
	firewallFinishFixture(t, a, third, "success", confirmed)
	state = responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if !boolean(state["observed"].(map[string]any), "applied") || text(state["observed"].(map[string]any), "checkedAt") != text(confirmed, "checkedAt") {
		t.Fatal("valid receipt lost its original observation time")
	}
	failedRefresh := controllerRequest(t, h, "POST", "/api/servers/server/firewall/refresh", token, nil)
	requireStatus(t, failedRefresh, 202)
	firewallFinishFixture(t, a, responseMap(t, failedRefresh), "failed", nil)
	state = responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if boolean(state["observed"].(map[string]any), "applied") || text(state["task"].(map[string]any), "error") == "" {
		t.Fatal("failed live verification reused an old success")
	}
	refresh := controllerRequest(t, h, "POST", "/api/servers/server/firewall/refresh", token, nil)
	requireStatus(t, refresh, 202)
	refreshState := responseMap(t, refresh)
	if number(refreshState, "revision") != 3 || refreshState["rules"] == nil || text(refreshState["task"].(map[string]any), "kind") != "network.firewall.status" {
		t.Fatal("refresh contract changed")
	}
	// A successful status task exposing a different revision stays unapplied.
	wrong := firewallStatusFixture(third)
	wrong["revision"] = 2
	firewallFinishFixture(t, a, refreshState, "success", wrong)
	state = responseMap(t, controllerRequest(t, h, "GET", "/api/servers/server/firewall", token, nil))
	if boolean(state["observed"].(map[string]any), "applied") {
		t.Fatal("stale kernel revision appeared applied")
	}
}

func TestFirewallProtectsInboundUntilRemovalConfirmed(t *testing.T) {
	a, h, token := firewallFixture(t)
	ctx := context.Background()
	first := firewallSaveFixture(t, h, token, 0, firewallFixtureRules())
	firewallFinishFixture(t, a, first, "success", firewallStatusFixture(first))
	row, _ := a.DB.GetRecord(ctx, "inbounds", "reality")
	renamed := clone(row.Data)
	renamed["name"] = "Renamed guarded inbound"
	renamed["network"], renamed["security"], renamed["listen"] = "tcp", "reality", "0.0.0.0"
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/inbounds/reality", token, map[string]any{"row": renamed}), 200)
	for _, patch := range []map[string]any{{"port": 8443}, {"status": "停用"}, {"tag": "new-tag"}, {"listen": "127.0.0.1"}} {
		changed := clone(row.Data)
		for k, v := range patch {
			changed[k] = v
		}
		requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/inbounds/reality", token, map[string]any{"row": changed}), 409)
	}
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/inbounds/reality", token, nil), 409)
	removal := firewallSaveFixture(t, h, token, 1, []firewallRule{})
	if err := a.firewallInboundChange(ctx, row, nil); err == nil {
		t.Fatal("queued removal released protected port early")
	}
	firewallFinishFixture(t, a, removal, "success", firewallStatusFixture(removal))
	if err := a.firewallInboundChange(ctx, row, nil); err != nil {
		t.Fatal("confirmed removal did not release port", err)
	}
}

func TestFirewallDispatchRevalidatesChangedListenersAndMissingEvidence(t *testing.T) {
	a, h, token := firewallFixture(t)
	ctx := context.Background()
	state := firewallSaveFixture(t, h, token, 0, firewallFixtureRules())
	task, _ := a.DB.GetTask(ctx, text(state["task"].(map[string]any), "id"))
	row, _ := a.DB.GetRecord(ctx, "inbounds", "reality")
	row.Data["port"] = 8443
	if _, err := a.DB.SaveRecord(ctx, row); err != nil {
		t.Fatal(err)
	}
	if a.permitDispatch(ctx, task) {
		t.Fatal("changed listener dispatched old guard")
	}
	failed, _ := a.DB.GetTask(ctx, task.ID)
	if failed.Status != "failed" {
		t.Fatal("port change did not persist visible failure")
	}
	if sameFirewallRules(nil, []firewallRule{}) || sameFirewallRules([]firewallRule{}, nil) {
		t.Fatal("absent evidence was treated as an empty installed ruleset")
	}
}

func TestFirewallObservationSurvivesManagementFilter(t *testing.T) {
	a, _, _ := firewallFixture(t)
	ctx := context.Background()
	status := map[string]any{"supported": true, "backend": "nftables", "revision": 0, "rules": []any{}, "applied": true, "checkedAt": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)}
	_, err := a.acceptReport(ctx, agentwire.Report{ServerID: "server", Token: "fixture-token", Mode: "embedded", Timestamp: time.Now().Unix(), Capabilities: map[string]bool{"firewall_allowlist": true}, Observation: map[string]any{"network_firewall": status, "cpu_percent": 90}, Busy: true}, "Pull")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := a.DB.GetRecord(ctx, "_observations", "server")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Data["network_firewall"] == nil || rec.Data["cpu_percent"] != nil {
		t.Fatal("filter lost firewall or retained host metrics")
	}
	if got := a.firewallObserved(ctx, "server"); text(got, "checkedAt") != text(status, "checkedAt") {
		t.Fatal("heartbeat fabricated fresh verification timestamp")
	}
}
