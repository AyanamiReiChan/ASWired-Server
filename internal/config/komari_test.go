package config

import (
	"strings"
	"testing"
)

func TestKomariFirstRunDoesNotRequireAdminUsername(t *testing.T) {
	t.Setenv("ASWIRED_KOMARI_PUBLIC_URL", "https://probe.example.com")
	t.Setenv("ASWIRED_KOMARI_BRIDGE_SECRET", strings.Repeat("a", 32))
	t.Setenv("ASWIRED_ADMIN_USERNAMES", "")
	var cfg Config
	if err := loadKomari(&cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.AdminUsernames) != 0 {
		t.Fatal("first-run account must be chosen in setup")
	}
}

func TestKomariExplicitAdminRestrictionAndSecret(t *testing.T) {
	t.Setenv("ASWIRED_KOMARI_PUBLIC_URL", "https://probe.example.com")
	t.Setenv("ASWIRED_KOMARI_BRIDGE_SECRET", strings.Repeat("b", 32))
	t.Setenv("ASWIRED_ADMIN_USERNAMES", " Alice,BOB ")
	var cfg Config
	if err := loadKomari(&cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.AdminUsernames, ",") != "alice,bob" {
		t.Fatal(cfg.AdminUsernames)
	}
	t.Setenv("ASWIRED_KOMARI_BRIDGE_SECRET", "weak")
	if err := loadKomari(&Config{}); err == nil {
		t.Fatal("accepted weak bridge secret")
	}
}
