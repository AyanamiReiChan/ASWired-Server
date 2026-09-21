package config

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
)

func loadKomari(cfg *Config) error {
	cfg.KomariPublicURL = strings.TrimRight(strings.TrimSpace(os.Getenv("ASWIRED_KOMARI_PUBLIC_URL")), "/")
	cfg.KomariBridgeSecret = strings.TrimSpace(os.Getenv("ASWIRED_KOMARI_BRIDGE_SECRET"))
	for _, name := range strings.Split(os.Getenv("ASWIRED_ADMIN_USERNAMES"), ",") {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			cfg.AdminUsernames = append(cfg.AdminUsernames, name)
		}
	}
	if cfg.KomariPublicURL == "" && cfg.KomariBridgeSecret == "" {
		return nil
	}
	u, err := url.Parse(cfg.KomariPublicURL)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("ASWIRED_KOMARI_PUBLIC_URL must be an origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return errors.New("Komari origin requires HTTPS outside loopback")
	}
	if len(cfg.KomariBridgeSecret) < 32 {
		return errors.New("Komari integration requires a 32-byte bridge secret")
	}
	return nil
}
