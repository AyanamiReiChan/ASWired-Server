package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	ListenAddr         string
	DataDir            string
	DatabaseDriver     string
	DatabaseDSN        string
	DatabaseMaxOpen    int
	DatabaseMaxIdle    int
	JWTSecret          []byte
	JWTTTL             time.Duration
	PublicURL          string
	AllowedOrigins     []string
	FrontendDir        string
	KomariPublicURL    string
	KomariBridgeSecret string
	AdminUsernames     []string
}

func value(key, defaultValue string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return defaultValue
}

func Load() (Config, error) {
	cfg := Config{ListenAddr: value("ASWIRED_LISTEN", "127.0.0.1:12889"), DatabaseDriver: value("ASWIRED_DATABASE_DRIVER", "sqlite"), DatabaseDSN: os.Getenv("ASWIRED_DATABASE_DSN"), PublicURL: strings.TrimRight(value("ASWIRED_PUBLIC_URL", "http://127.0.0.1:12889"), "/"), FrontendDir: os.Getenv("ASWIRED_FRONTEND_DIR"), JWTTTL: 8 * time.Hour}
	var err error
	cfg.DataDir, err = filepath.Abs(value("ASWIRED_DATA_DIR", "data"))
	if err != nil {
		return Config{}, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return Config{}, err
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		return Config{}, fmt.Errorf("ASWIRED_LISTEN: %w", err)
	}
	parsed, err := url.Parse(cfg.PublicURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Config{}, errors.New("ASWIRED_PUBLIC_URL must be an HTTP(S) URL without credentials, query or fragment")
	}
	if parsed.Scheme == "http" {
		host := strings.ToLower(parsed.Hostname())
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return Config{}, errors.New("ASWIRED_PUBLIC_URL must use HTTPS outside localhost or loopback development")
		}
	}
	if err := cfg.loadManagedDatabase(); err != nil {
		return Config{}, err
	}
	if cfg.DatabaseDSN == "" {
		if cfg.DatabaseDriver != "sqlite" {
			return Config{}, errors.New("ASWIRED_DATABASE_DSN is required for PostgreSQL")
		}
		cfg.DatabaseDSN = filepath.Join(cfg.DataDir, "aswired.db")
	}
	if raw := os.Getenv("ASWIRED_JWT_TTL"); raw != "" {
		cfg.JWTTTL, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("ASWIRED_JWT_TTL: %w", err)
		}
	}
	if cfg.JWTTTL <= 0 || cfg.JWTTTL > 30*24*time.Hour {
		return Config{}, errors.New("JWT lifetime must be positive and at most 30 days")
	}
	secret := os.Getenv("ASWIRED_JWT_SECRET")
	if secret == "" {
		secret = os.Getenv("JWT_SECRET")
	}
	if secret != "" {
		cfg.JWTSecret = []byte(secret)
		if len(cfg.JWTSecret) < 32 {
			return Config{}, errors.New("JWT_SECRET must contain at least 32 bytes")
		}
	} else {
		cfg.JWTSecret, err = LoadOrCreateSecret(filepath.Join(cfg.DataDir, "jwt.key"))
		if err != nil {
			return Config{}, err
		}
	}
	for _, raw := range strings.Split(value("ASWIRED_ALLOWED_ORIGINS", "http://localhost:5174,http://127.0.0.1:5174"), ",") {
		origin := strings.TrimRight(strings.TrimSpace(raw), "/")
		if origin == "" {
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return Config{}, fmt.Errorf("invalid allowed origin %q", origin)
		}
		cfg.AllowedOrigins = append(cfg.AllowedOrigins, origin)
	}
	if err := loadKomari(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadOrCreateSecret(path string) ([]byte, error) {
	read := func() ([]byte, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		secret, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(secret) != 32 {
			return nil, fmt.Errorf("invalid persisted key at %s", path)
		}
		if err := os.Chmod(path, 0600); err != nil {
			return nil, err
		}
		return secret, nil
	}
	if secret, err := read(); err == nil {
		return secret, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.WriteString(base64.RawStdEncoding.EncodeToString(secret) + "\n")
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if existing, readErr := read(); readErr == nil {
			return existing, nil
		}
		return nil, fmt.Errorf("publish controller key: %w", err)
	}
	return secret, nil
}
