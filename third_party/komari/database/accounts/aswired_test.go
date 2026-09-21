package accounts

import (
	"errors"
	"testing"

	"github.com/komari-monitor/komari/pkg/aswired"
)

// No local database is initialized: managed operations must return before
// touching a second account store, even with incomplete bridge configuration.
func TestManagedAccountsRejectLocalIdentityChanges(t *testing.T) {
	t.Setenv("ASWIRED_IDENTITY_URL", "http://127.0.0.1:12889")
	checks := []struct {
		name string
		run func() error
	}{
		{"create", func() error { _, err := CreateAccount("duplicate", "password"); return err }},
		{"default admin", func() error { _, _, err := CreateDefaultAdminAccount(); return err }},
		{"reset", func() error { return ForceResetPassword("duplicate", "password") }},
		{"delete", func() error { return DeleteAccountByUsername("duplicate") }},
		{"update", func() error { return UpdateUser("id", nil, nil, nil) }},
		{"bind SSO", func() error { return BindingExternalAccount("id", "sso") }},
		{"unbind SSO", func() error { return UnbindExternalAccount("id") }},
		{"generate 2FA", func() error { _, _, err := Generate2Fa(); return err }},
		{"enable 2FA", func() error { return Enable2Fa("id", "secret") }},
		{"disable 2FA", func() error { return Disable2Fa("id") }},
		{"verify local 2FA", func() error { _, err := Verify2Fa("id", "123456"); return err }},
		{"create session", func() error { _, err := CreateSession("id", 60, "", "", "password"); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); !errors.Is(err, aswired.ErrManaged) {
				t.Fatalf("expected central account management, got %v", err)
			}
		})
	}
	if _, ok := CheckPassword("duplicate", "password"); ok {
		t.Fatal("local password accepted in integrated mode")
	}
}
