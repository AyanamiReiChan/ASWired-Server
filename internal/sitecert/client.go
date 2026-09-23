package sitecert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Deployment struct {
	Supported     bool     `json:"supported"`
	Reason        string   `json:"reason,omitempty"`
	Phase         string   `json:"phase"`
	Message       string   `json:"message,omitempty"`
	CertificateID string   `json:"certificateId,omitempty"`
	Serial        string   `json:"serial,omitempty"`
	Sites         []string `json:"sites,omitempty"`
	RequestID     string   `json:"requestId,omitempty"`
	UpdatedAt     string   `json:"updatedAt,omitempty"`
}
type Binding struct {
	CertificateID string `json:"certificateId"`
	Serial        string `json:"serial"`
}
type Client struct {
	DataDir, StateDir string
	Ready             func(context.Context) error
}
type Request struct {
	ID            string   `json:"id"`
	Operation     string   `json:"operation"`
	CertificateID string   `json:"certificateId"`
	Sites         []string `json:"sites"`
	Certificate   string   `json:"certificate"`
	PrivateKey    string   `json:"privateKey"`
	CreatedAt     string   `json:"createdAt"`
}

func NewClient(dataDir string) *Client {
	c := &Client{DataDir: dataDir, StateDir: "/var/lib/aswired-certificates"}
	c.Ready = func(ctx context.Context) error {
		if runtime.GOOS != "linux" || filepath.Clean(dataDir) != "/var/lib/aswired" {
			return errors.New("网站部署需要正式 Linux 组合安装")
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "systemctl", "is-active", "aswired-certificates.path", "caddy").Output()
		if err != nil || strings.TrimSpace(string(out)) != "active\nactive" {
			return errors.New("网站部署需要运行中的 Caddy 和证书部署服务；其他反代请使用外部 HTTPS 模式")
		}
		return nil
	}
	return c
}
func readSummary(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return err
	}
	if len(raw) > 16384 {
		return errors.New("certificate status too large")
	}
	return json.Unmarshal(raw, dst)
}
func (c *Client) Bindings() map[string]Binding {
	rows := map[string]Binding{}
	_ = readSummary(filepath.Join(c.StateDir, "bindings.json"), &rows)
	return rows
}
func (c *Client) Status(ctx context.Context) Deployment {
	s := Deployment{Phase: "idle"}
	_ = readSummary(filepath.Join(c.StateDir, "status.json"), &s)
	s.Supported = false
	if c.Ready == nil {
		s.Reason = "网站部署服务未配置"
	} else if err := c.Ready(ctx); err != nil {
		s.Reason = err.Error()
	} else {
		s.Supported = true
		s.Reason = ""
	}
	if _, err := os.Lstat(filepath.Join(c.DataDir, "site-certificate-request.json")); err == nil && s.Phase != "applying" {
		s.Phase = "queued"
		s.Message = "等待证书部署服务处理"
	}
	return s
}
func (c *Client) Enqueue(ctx context.Context, request Request) error {
	s := c.Status(ctx)
	if !s.Supported {
		return errors.New(s.Reason)
	}
	if s.Phase == "queued" || s.Phase == "applying" {
		return errors.New("已有网站证书操作正在处理")
	}
	if request.Operation != "deploy" && request.Operation != "external" {
		return errors.New("不支持的网站证书操作")
	}
	if len(request.Sites) == 0 || len(request.Sites) > 2 {
		return errors.New("请选择主控或 Komari 网站")
	}
	seen := map[string]bool{}
	for _, id := range request.Sites {
		if (id != "panel" && id != "komari") || seen[id] {
			return errors.New("网站目标无效")
		}
		seen[id] = true
	}
	request.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(raw) > 2<<20 {
		return errors.New("证书材料过大")
	}
	f, err := os.CreateTemp(c.DataDir, ".site-certificate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(f.Name(), filepath.Join(c.DataDir, "site-certificate-request.json")); os.IsExist(err) {
		return errors.New("已有网站证书操作正在处理")
	}
	return err
}
