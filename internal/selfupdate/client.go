// Package selfupdate queues a version-only request for a separately privileged updater.
package selfupdate

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

	"golang.org/x/mod/semver"
)

type Status struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Phase     string `json:"phase"`
	Version   string `json:"version,omitempty"`
	Message   string `json:"message,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
	Backup    string `json:"backup,omitempty"`
}

type Client struct {
	DataDir  string
	StateDir string
	Ready    func(context.Context) error
}

func New(dataDir, driver string) *Client {
	c := &Client{DataDir: dataDir, StateDir: "/var/lib/aswired-updater"}
	c.Ready = func(ctx context.Context) error {
		if runtime.GOOS != "linux" || filepath.Clean(dataDir) != "/var/lib/aswired" {
			return errors.New("此安装方式不支持网页升级，请使用正式组合部署包")
		}
		if driver != "sqlite" {
			return errors.New("PostgreSQL 部署请先验证数据库备份，再按升级文档执行 update.sh")
		}
		if _, err := os.Lstat(filepath.Join(dataDir, "database-pending.enc")); !os.IsNotExist(err) {
			return errors.New("数据库迁移尚未完成，暂不能升级")
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "systemctl", "is-active", "aswired-update.path").Output()
		if err != nil || strings.TrimSpace(string(out)) != "active" {
			return errors.New("更新服务未安装或未启动；旧安装需先用 update.sh 升级一次")
		}
		return nil
	}
	return c
}

func active(phase string) bool { return phase == "queued" || phase == "updating" }

func readJSON(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return err
	}
	if len(raw) > 8192 {
		return errors.New("update state is too large")
	}
	return json.Unmarshal(raw, target)
}

func (c *Client) Status(ctx context.Context) Status {
	s := Status{Phase: "idle"}
	// Only a typed, non-secret summary crosses into the API.
	_ = readJSON(filepath.Join(c.StateDir, "status.json"), &s)
	s.Supported = false
	if c.Ready == nil {
		s.Reason = "更新服务未配置"
	} else if err := c.Ready(ctx); err != nil {
		s.Reason = err.Error()
	} else {
		s.Supported = true
		s.Reason = ""
	}
	if _, err := os.Lstat(filepath.Join(c.DataDir, "update-request.json")); err == nil && !active(s.Phase) {
		s.Phase = "queued"
		s.Message = "等待更新服务处理"
	}
	return s
}

func (c *Client) Request(ctx context.Context, version string) error {
	if !semver.IsValid(version) || semver.Canonical(version) != version {
		return errors.New("目标版本无效")
	}
	status := c.Status(ctx)
	if !status.Supported {
		return errors.New(status.Reason)
	}
	if active(status.Phase) {
		return errors.New("已有升级请求正在处理")
	}
	data, _ := json.Marshal(map[string]string{"version": version, "createdAt": time.Now().UTC().Format(time.RFC3339Nano)})
	f, err := os.CreateTemp(c.DataDir, ".update-request-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = os.Link(f.Name(), filepath.Join(c.DataDir, "update-request.json")); os.IsExist(err) {
		return errors.New("已有升级请求正在处理")
	}
	return err
}
