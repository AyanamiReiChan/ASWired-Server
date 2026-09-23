package sitecert

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebsiteDeploymentQueueAndStatusNeverExposeMaterial(t *testing.T) {
	c := &Client{DataDir: t.TempDir(), StateDir: t.TempDir(), Ready: func(context.Context) error { return nil }}
	r := Request{ID: "fixture-request-12345", Operation: "deploy", Sites: []string{"panel", "komari"}, CertificateID: "fixture", Certificate: "public-material", PrivateKey: "private-material-never-returned"}
	if err := c.Enqueue(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := c.Enqueue(context.Background(), r); err == nil {
		t.Fatal("overwrote pending request")
	}
	raw, err := os.ReadFile(filepath.Join(c.DataDir, "site-certificate-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored Request
	if err = json.Unmarshal(raw, &stored); err != nil || stored.PrivateKey != r.PrivateKey || stored.CreatedAt == "" {
		t.Fatal("incomplete request", err)
	}
	status := c.Status(context.Background())
	encoded, _ := json.Marshal(status)
	if status.Phase != "queued" || strings.Contains(string(encoded), "private-material") {
		t.Fatal("unsafe status")
	}
	if err := os.Remove(filepath.Join(c.DataDir, "site-certificate-request.json")); err != nil {
		t.Fatal(err)
	}
	r.Sites = []string{"../../etc"}
	if err := c.Enqueue(context.Background(), r); err == nil {
		t.Fatal("accepted arbitrary target")
	}
}
