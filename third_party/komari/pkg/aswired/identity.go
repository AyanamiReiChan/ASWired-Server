// Package aswired delegates identity to ASWired's single account database.
package aswired

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Identity struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	TwoFactor bool      `json:"twoFactor"`
	Session   string    `json:"session"`
	ExpiresAt time.Time `json:"expiresAt"`
}

var ErrManaged = errors.New("账户由 ASWired 统一管理，请联系 ASWired 管理员修改账户")
var ErrInvalidSession = errors.New("登录已失效，请重新登录")

func Enabled() bool {
	return os.Getenv("ASWIRED_IDENTITY_URL") != "" || os.Getenv("ASWIRED_BRIDGE_SECRET") != "" || os.Getenv("ASWIRED_LOGIN_URL") != ""
}
func LoginURL() string { return os.Getenv("ASWIRED_LOGIN_URL") }
func Origin() string {
	u, err := url.Parse(LoginURL())
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
func Secure() bool { return strings.HasPrefix(os.Getenv("KOMARI_PUBLIC_URL"), "https://") }
func Validate() error {
	if !Enabled() {
		return nil
	}
	if len(os.Getenv("ASWIRED_BRIDGE_SECRET")) < 32 {
		return errors.New("ASWIRED_BRIDGE_SECRET must contain at least 32 bytes")
	}
	for _, name := range []string{"ASWIRED_IDENTITY_URL", "ASWIRED_LOGIN_URL", "KOMARI_PUBLIC_URL"} {
		u, err := url.Parse(os.Getenv(name))
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("invalid " + name)
		}
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
			return errors.New(name + " must use HTTPS outside loopback")
		}
		if name != "ASWIRED_LOGIN_URL" && u.Path != "" && u.Path != "/" {
			return errors.New(name + " must be an origin")
		}
	}
	return nil
}
func Call(ctx context.Context, endpoint string, input any) (Identity, error) {
	if !Enabled() {
		return Identity{}, ErrManaged
	}
	if err := Validate(); err != nil {
		return Identity{}, err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return Identity{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(os.Getenv("ASWIRED_IDENTITY_URL"), "/")+"/api/internal/komari/"+endpoint, bytes.NewReader(body))
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("ASWIRED_BRIDGE_SECRET"))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return Identity{}, errors.New("统一账户服务暂不可用")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		return Identity{}, ErrInvalidSession
	}
	if res.StatusCode != 200 {
		return Identity{}, errors.New("登录已失效或身份验证失败，请重新登录")
	}
	var out Identity
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return out, errors.New("invalid identity response")
	}
	return out, nil
}
func Session(token string) (Identity, error) {
	if !strings.HasPrefix(token, "kprobe_") || len(token) > 256 {
		return Identity{}, errors.New("invalid session")
	}
	out, err := Call(context.Background(), "introspect", map[string]any{"session": token})
	if err == nil && (out.ID == "" || out.Username == "" || !out.ExpiresAt.After(time.Now())) {
		err = errors.New("invalid identity")
	}
	return out, err
}
