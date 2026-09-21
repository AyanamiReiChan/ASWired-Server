package httpapi

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestIPDatabaseRejectsCorruptionAndUsesActivatedVersion(t *testing.T) {
	a, h, token := controllerFixture(t)
	raw, e := os.ReadFile("testdata/GeoIP2-City-Test.mmdb")
	if e != nil {
		t.Fatal(e)
	}
	upload := func(data []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/ip-databases?name=official-fixture", bytes.NewReader(data))
		r.Header.Set("MM-Authorization", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	requireStatus(t, upload([]byte("not a database")), 400)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/ip-lookup?ip=81.2.69.160", token, nil), 409)
	result := upload(raw)
	requireStatus(t, result, 200)
	id := text(responseMap(t, result)["row"].(map[string]any), "id")
	if strings.Contains(result.Body.String(), "body") {
		t.Fatal("upload response returned raw database")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/ip-databases/"+id+"/activate", token, nil), 200)
	lookup := controllerRequest(t, h, "GET", "/api/ip-lookup?ip=81.2.69.160", token, nil)
	requireStatus(t, lookup, 200)
	if responseMap(t, lookup)["found"] != true || !strings.Contains(lookup.Body.String(), "London") {
		t.Fatalf("wrong fixture lookup %s", lookup.Body)
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/ip-lookup?ip=2001:218::", token, nil), 200)
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/ip-databases/"+id, token, nil), 409)
	record, _ := a.DB.GetRecord(context.Background(), "_ipDatabases", id)
	record.Data["body"] = "YmFk"
	if _, e = a.DB.SaveRecord(context.Background(), record); e != nil {
		t.Fatal(e)
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/ip-lookup?ip=81.2.69.160", token, nil), 503)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/ip-databases", "", nil), 401)
}
