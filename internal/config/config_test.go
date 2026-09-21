package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestSecretPersistenceAndConcurrentInitialization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwt.key")
	const n = 16
	keys := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) { defer wg.Done(); keys[i], errs[i] = LoadOrCreateSecret(path) }(i)
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if len(keys[i]) != 32 || !bytes.Equal(keys[0], keys[i]) {
			t.Fatal("concurrent callers observed different keys")
		}
	}
	again, err := LoadOrCreateSecret(path)
	if err != nil || !bytes.Equal(keys[0], again) {
		t.Fatal("restart changed JWT secret")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("key permissions %o", info.Mode().Perm())
		}
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSecret(path); err == nil {
		t.Fatal("corrupt key was silently replaced")
	}
}

func TestLoadRejectsUnsafeSettings(t *testing.T) {
	t.Setenv("ASWIRED_DATA_DIR", t.TempDir())
	t.Setenv("ASWIRED_JWT_SECRET", "short")
	if _, err := Load(); err == nil {
		t.Fatal("short configured key accepted")
	}
	t.Setenv("ASWIRED_JWT_SECRET", "abcdefghijklmnopqrstuvwxyz0123456789")
	t.Setenv("ASWIRED_ALLOWED_ORIGINS", "https://example.com/path")
	if _, err := Load(); err == nil {
		t.Fatal("non-origin URL accepted")
	}
	t.Setenv("ASWIRED_ALLOWED_ORIGINS", "https://example.com")
	t.Setenv("ASWIRED_PUBLIC_URL", "http://example.com")
	if _, err := Load(); err == nil {
		t.Fatal("public HTTP URL accepted outside loopback")
	}
	t.Setenv("ASWIRED_PUBLIC_URL", "http://localhost:12889")
	if _, err := Load(); err != nil {
		t.Fatalf("localhost HTTP development URL rejected: %v", err)
	}
}
