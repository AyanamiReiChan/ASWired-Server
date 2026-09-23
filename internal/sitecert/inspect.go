// Package sitecert inspects the HTTPS certificates served by the local reverse
// proxy. It never reads certificate private keys or sends a mutating Caddy request.
package sitecert

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Target struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Certificate struct {
	Target
	Host           string   `json:"host,omitempty"`
	Port           string   `json:"port,omitempty"`
	CheckedAt      string   `json:"checkedAt"`
	Status         string   `json:"status"`
	Error          string   `json:"error,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	Domains        []string `json:"domains,omitempty"`
	IssuedAt       string   `json:"issuedAt,omitempty"`
	Expires        string   `json:"expires,omitempty"`
	Serial         string   `json:"serial,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	Verified       bool     `json:"verified"`
	Manager        string   `json:"manager"`
	Renewal        string   `json:"renewal"`
	ManagementNote string   `json:"managementNote"`
}

type Inspector struct {
	mu       sync.Mutex
	cache    []Certificate
	cacheKey string
	checked  time.Time
	dial     func(context.Context, string, string) (net.Conn, error)
	roots    *x509.CertPool
	client   *http.Client
	caddyURL string
}

func NewInspector() *Inspector {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &Inspector{dial: dialer.DialContext, caddyURL: "http://127.0.0.1:2019/config/", client: &http.Client{
		Timeout:       3 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DialContext: dialer.DialContext, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Check only accepts deployment configuration supplied by the controller, never
// a browser-provided URL. TLS always connects to loopback using the site's SNI.
func (i *Inspector) Check(ctx context.Context, targets []Target) []Certificate {
	i.mu.Lock()
	defer i.mu.Unlock()
	key, _ := json.Marshal(targets)
	if string(key) == i.cacheKey && time.Since(i.checked) < 2*time.Second {
		return append([]Certificate(nil), i.cache...)
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var caddy map[string]any
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, i.caddyURL, nil)
	if response, err := i.client.Do(request); err == nil {
		if response.StatusCode == http.StatusOK {
			body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
			if err == nil && len(body) <= 2<<20 {
				_ = json.Unmarshal(body, &caddy)
			}
		}
		response.Body.Close()
	}
	rows := make([]Certificate, len(targets))
	var wg sync.WaitGroup
	for n, target := range targets {
		wg.Add(1)
		go func(n int, target Target) { defer wg.Done(); rows[n] = i.inspect(ctx, target, caddy) }(n, target)
	}
	wg.Wait()
	i.cache, i.cacheKey, i.checked = rows, string(key), time.Now()
	return append([]Certificate(nil), rows...)
}

func (i *Inspector) inspect(ctx context.Context, target Target, caddy map[string]any) Certificate {
	row := Certificate{Target: target, CheckedAt: time.Now().UTC().Format(time.RFC3339), Status: "unavailable", Manager: "external", Renewal: "unknown", ManagementNote: "由外部 HTTPS 服务管理，尚未确认自动续期方式"}
	u, err := url.Parse(target.URL)
	if err != nil || u.Hostname() == "" || u.User != nil {
		row.Status = "unconfigured"
		row.Error = "未配置网站公网地址"
		return row
	}
	if u.Scheme != "https" {
		row.Status = "http"
		row.Error = "网站地址未启用 HTTPS"
		return row
	}
	row.Host, row.Port = u.Hostname(), u.Port()
	if row.Port == "" {
		row.Port = "443"
	}
	row.Manager, row.Renewal, row.ManagementNote = caddyManagement(caddy, row.Host, row.Port)
	var conn net.Conn
	for _, address := range []string{"127.0.0.1", "::1"} {
		conn, err = i.dial(ctx, "tcp", net.JoinHostPort(address, row.Port))
		if err == nil {
			break
		}
	}
	if err != nil {
		row.Error = "无法连接本机 HTTPS 端口；请检查反代监听，远端反代的证书需在其所在主机管理"
		return row
	}
	defer conn.Close()
	// Collect the public leaf even if expired or mismatched; validation is performed
	// explicitly below and the result is never represented as trusted on failure.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: row.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) // #nosec G402 -- explicit x509.Verify below
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		row.Error = "本机 HTTPS 握手失败"
		return row
	}
	chain := tlsConn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		row.Error = "HTTPS 服务未返回证书"
		return row
	}
	leaf := chain[0]
	fingerprint := sha256.Sum256(leaf.Raw)
	row.Issuer = leaf.Issuer.String()
	row.Domains = append([]string(nil), leaf.DNSNames...)
	row.IssuedAt = leaf.NotBefore.UTC().Format(time.RFC3339)
	row.Expires = leaf.NotAfter.UTC().Format(time.RFC3339)
	row.Serial = leaf.SerialNumber.String()
	row.Fingerprint = hex.EncodeToString(fingerprint[:])
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: row.Host, Roots: i.roots, Intermediates: intermediates})
	if err != nil {
		row.Status = "invalid"
		var invalid x509.CertificateInvalidError
		var hostname x509.HostnameError
		switch {
		case errors.As(err, &hostname):
			row.Error = "证书不覆盖网站域名"
		case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
			row.Error = "证书已过期或尚未生效"
		default:
			row.Error = "证书链未通过系统信任验证"
		}
		return row
	}
	row.Verified = true
	row.Status = "valid"
	if time.Until(leaf.NotAfter) <= 30*24*time.Hour {
		row.Status = "expiring"
	}
	return row
}

func object(value any) map[string]any { row, _ := value.(map[string]any); return row }
func array(value any) []any           { rows, _ := value.([]any); return rows }
func matches(pattern, host string) bool {
	pattern, host = strings.ToLower(pattern), strings.ToLower(host)
	return pattern == host || strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) && strings.Count(pattern, ".") == strings.Count(host, ".")
}
func containsHost(value any, host string) bool {
	for _, entry := range array(value) {
		if pattern, ok := entry.(string); ok && matches(pattern, host) {
			return true
		}
	}
	return false
}
func routeHost(routes any, host string) bool {
	for _, value := range array(routes) {
		route := object(value)
		for _, match := range array(route["match"]) {
			if containsHost(object(match)["host"], host) {
				return true
			}
		}
		for _, handler := range array(route["handle"]) {
			if routeHost(object(handler)["routes"], host) {
				return true
			}
		}
	}
	return false
}

func caddyManagement(cfg map[string]any, host, port string) (string, string, string) {
	unknown := func() (string, string, string) {
		return "external", "unknown", "由外部 HTTPS 服务管理，尚未确认自动续期方式"
	}
	apps := object(cfg["apps"])
	servers := object(object(apps["http"])["servers"])
	for _, raw := range servers {
		server := object(raw)
		listens := false
		for _, entry := range array(server["listen"]) {
			address, _ := entry.(string)
			_, p, err := net.SplitHostPort(address)
			if err == nil && p == port {
				listens = true
			}
		}
		if !listens || !routeHost(server["routes"], host) {
			continue
		}
		for _, rawPolicy := range array(server["tls_connection_policies"]) {
			policy := object(rawPolicy)
			if !containsHost(object(policy["match"])["sni"], host) {
				continue
			}
			for _, serial := range array(object(policy["certificate_selection"])["serial_number"]) {
				s, ok := serial.(string)
				if !ok {
					continue
				}
				for _, rawLoader := range array(object(object(apps["tls"])["certificates"])["load_files"]) {
					tags := array(object(rawLoader)["tags"])
					owned, matchesSerial := false, false
					for _, tag := range tags {
						owned = owned || tag == "aswired-site-panel" || tag == "aswired-site-komari"
						matchesSerial = matchesSerial || tag == "aswired-serial-"+s
					}
					if owned && matchesSerial {
						return "aswired", "managed", "由主控证书记录续期并部署到 Caddy；以证书记录的自动续期与自动部署设置为准"
					}
				}
			}
			for _, tag := range array(object(policy["certificate_selection"])["any_tag"]) {
				s, _ := tag.(string)
				if s == "aswired-site-panel" || s == "aswired-site-komari" {
					return "aswired", "managed", "由主控证书记录续期并部署到 Caddy；以证书记录的自动续期与自动部署设置为准"
				}
			}
		}
		auto := object(server["automatic_https"])
		if auto["disable"] == true || auto["disable_certificates"] == true || containsHost(auto["skip"], host) || containsHost(auto["skip_certificates"], host) {
			return "caddy", "disabled", "Caddy 已关闭此域名的自动证书管理"
		}
		tlsConfig := object(apps["tls"])
		for loader, values := range object(tlsConfig["certificates"]) {
			if loader != "automate" && len(array(values)) > 0 && auto["ignore_loaded_certificates"] != true {
				return "caddy", "unknown", "Caddy 存在手动加载的证书，不能确认此域名由其自动续期"
			}
		}
		for _, value := range array(object(tlsConfig["automation"])["policies"]) {
			p := object(value)
			if len(array(p["subjects"])) > 0 && !containsHost(p["subjects"], host) {
				continue
			}
			if len(array(p["managers"])) > 0 {
				return "caddy", "unknown", "Caddy 使用外部证书管理器，请确认其续期配置"
			}
			break
		}
		return "caddy", "automatic", "Caddy 自动签发与续期；当前无需向节点 Agent 部署"
	}
	return unknown()
}
