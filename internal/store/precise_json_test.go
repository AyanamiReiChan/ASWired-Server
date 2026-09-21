package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEncryptedJSONPreservesLargeCounters(t *testing.T) {
	s := &Store{}
	if err := s.SetEncryptionKey([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatal(err)
	}
	const exact = "9007199254740993"
	raw, err := s.encodeJSON(map[string]any{"counter": json.Number(exact)})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := s.decodeJSON(raw, &out); err != nil {
		t.Fatal(err)
	}
	n, ok := out["counter"].(json.Number)
	if !ok || n.String() != exact {
		t.Fatalf("large counter rounded: %T %v", out["counter"], out["counter"])
	}
	if err := s.decodeJSON([]byte(`{"counter":1} {"counter":2}`), &out); err == nil {
		t.Fatal("trailing stored JSON accepted")
	}
}
