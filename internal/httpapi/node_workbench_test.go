package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestNodeWorkbenchImportIsAtomicAndCredentialAware(t *testing.T) {
	a, h, token := controllerFixture(t)
	first := realityClientFixtureURI("proxy.example.test", "First")
	invalid := controllerRequest(t, h, "POST", "/api/nodes/import", token, map[string]any{"lines": []string{first, "invalid"}})
	requireStatus(t, invalid, 400)
	rows, _ := a.DB.ListRecords(context.Background(), "nodes", "")
	if len(rows) != 0 {
		t.Fatal("partial import persisted")
	}
	parsed, _ := parseImportedURI(first)
	second := strings.Replace(first, text(parsed, "uuid"), "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", 1)
	result := controllerRequest(t, h, "POST", "/api/nodes/import", token, map[string]any{"lines": []string{first, first, second}})
	requireStatus(t, result, 201)
	if number(responseMap(t, result), "count") != 2 {
		t.Fatal("deduplication merged independent credentials or kept duplicates")
	}
	result = controllerRequest(t, h, "POST", "/api/nodes/import", token, map[string]any{"lines": []string{first, second}})
	requireStatus(t, result, 201)
	if number(responseMap(t, result), "count") != 0 {
		t.Fatal("repeat import created duplicates")
	}
	member := store.User{ID: "member", Username: "member", Role: "user", TokenVersion: 1, PasswordHash: "fixture"}
	if err := a.DB.CreateUser(context.Background(), member); err != nil {
		t.Fatal(err)
	}
	memberToken, err := a.Signer.Issue(member.ID, member.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/nodes/import", memberToken, map[string]any{"lines": []string{first}}), http.StatusForbidden)
}

func TestNodeWorkbenchMetadataConflictDoesNotPartiallySave(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	node, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "one", Data: realityClientFixtureData()})
	if err != nil {
		t.Fatal(err)
	}
	change := map[string]any{"rows": []any{map[string]any{"id": node.ID, "recordVersion": node.Version, "patch": map[string]any{"name": "changed"}}, map[string]any{"id": "missing", "recordVersion": 1, "patch": map[string]any{"name": "bad"}}}}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/nodes/metadata", token, change), 409)
	unchanged, _ := a.DB.GetRecord(ctx, "nodes", node.ID)
	if text(unchanged.Data, "name") == "changed" {
		t.Fatal("partial metadata saved")
	}
	change["rows"] = []any{map[string]any{"id": node.ID, "recordVersion": node.Version, "patch": map[string]any{"uuid": "forged"}}}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/nodes/metadata", token, change), 400)
}

func TestNodeWorkbenchConnectionHonorsOwnerAndEligibility(t *testing.T) {
	a, sub := subscriptionFixture(t)
	h := a.Handler()
	ctx := context.Background()
	member, _ := a.DB.UserByID(ctx, "member")
	token, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	admin, _ := a.DB.UserByID(ctx, "admin")
	adminToken, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	path := "/api/nodes/ss-node/connection?subscriptionId=" + sub.ID
	requireStatus(t, controllerRequest(t, h, "GET", path, token, nil), 200)
	requireStatus(t, controllerRequest(t, h, "GET", path, adminToken, nil), 403)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/nodes/missing/connection?subscriptionId="+sub.ID, token, nil), 403)
	sub.Data["status"] = "停用"
	if _, err := a.DB.SaveRecord(ctx, sub); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "GET", path, token, nil), 403)
}
