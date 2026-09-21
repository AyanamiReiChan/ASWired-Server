package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DatabaseActiveFile = "database-active.enc"
const DatabasePendingFile = "database-pending.enc"

// PostgreSQL is never included in public settings: Password is only persisted
// inside the authenticated, encrypted database configuration envelope.
type PostgreSQL struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	SSLMode  string `json:"sslMode"`
	MaxOpen  int    `json:"maxOpen"`
	MaxIdle  int    `json:"maxIdle"`
}

func (p *PostgreSQL) Validate() error {
	p.Host = strings.TrimSpace(p.Host)
	p.Database = strings.TrimSpace(p.Database)
	p.Username = strings.TrimSpace(p.Username)
	if p.Host == "" || p.Database == "" || p.Username == "" {
		return errors.New("请填写主机、数据库名和用户名")
	}
	if len(p.Host) > 253 || len(p.Database) > 63 || len(p.Username) > 63 || len(p.Password) > 4096 || strings.ContainsAny(p.Host, "/\\\r\n\t ?#@\x00") || strings.ContainsAny(p.Database+p.Username+p.Password, "\x00\r\n") {
		return errors.New("数据库连接参数无效")
	}
	if strings.Contains(p.Host, ":") && net.ParseIP(strings.Trim(p.Host, "[]")) == nil {
		return errors.New("主机中不要包含端口或 URL")
	}
	p.Host = strings.Trim(p.Host, "[]")
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("端口须为 1 至 65535")
	}
	switch p.SSLMode {
	case "disable", "prefer", "require", "verify-ca", "verify-full":
	default:
		return errors.New("SSL 模式无效")
	}
	if p.MaxOpen < 1 || p.MaxOpen > 1000 || p.MaxIdle < 0 || p.MaxIdle > p.MaxOpen {
		return errors.New("最大连接数须为 1 至 1000，空闲连接须为 0 至最大连接数")
	}
	return nil
}

func (p PostgreSQL) DSN() string {
	u := url.URL{Scheme: "postgres", Host: net.JoinHostPort(p.Host, strconv.Itoa(p.Port)), Path: "/" + p.Database, User: url.UserPassword(p.Username, p.Password)}
	u.RawQuery = url.Values{"sslmode": {p.SSLMode}, "connect_timeout": {"8"}}.Encode()
	return u.String()
}

func (p PostgreSQL) Public() map[string]any {
	return map[string]any{"host": p.Host, "port": p.Port, "database": p.Database, "username": p.Username, "sslMode": p.SSLMode, "maxOpen": p.MaxOpen, "maxIdle": p.MaxIdle}
}

type DatabaseChange struct {
	ID        string     `json:"id"`
	Target    PostgreSQL `json:"target"`
	Source    string     `json:"source"`
	State     string     `json:"state"`
	Message   string     `json:"message,omitempty"`
	BackupID  string     `json:"backupId,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

func DatabaseSource(driver, dsn string) string {
	sum := sha256.Sum256([]byte(driver + "\x00" + dsn))
	return hex.EncodeToString(sum[:])
}

func databaseCipher(dir string) (cipher.AEAD, error) {
	key, err := LoadOrCreateSecret(filepath.Join(dir, "database-config.key"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func ReadDatabaseChange(dir, name string) (*DatabaseChange, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	aead, err := databaseCipher(dir)
	if err != nil {
		return nil, errors.New("无法读取数据库配置密钥")
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("数据库配置损坏")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(name))
	if err != nil {
		return nil, errors.New("数据库配置解密失败")
	}
	var change DatabaseChange
	if json.Unmarshal(plain, &change) != nil || change.ID == "" {
		return nil, errors.New("数据库配置无效")
	}
	if err = change.Target.Validate(); err != nil {
		return nil, err
	}
	return &change, nil
}

func WriteDatabaseChange(dir, name string, change DatabaseChange) error {
	aead, err := databaseCipher(dir)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(change)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nonce, nonce, raw, []byte(name))
	file, err := os.CreateTemp(dir, ".database-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(sealed)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), filepath.Join(dir, name))
}

func (cfg *Config) loadManagedDatabase() error {
	active, err := ReadDatabaseChange(cfg.DataDir, DatabaseActiveFile)
	if err != nil {
		return err
	}
	if active == nil {
		return nil
	}
	cfg.DatabaseDriver = "postgres"
	cfg.DatabaseDSN = active.Target.DSN()
	cfg.DatabaseMaxOpen = active.Target.MaxOpen
	cfg.DatabaseMaxIdle = active.Target.MaxIdle
	return nil
}
