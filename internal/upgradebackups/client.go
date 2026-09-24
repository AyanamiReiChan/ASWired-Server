// Package upgradebackups reads a non-secret summary and queues fixed operations
// for a separately privileged worker. It never opens the backup directories.
package upgradebackups

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
)

const (
	RequestFile    = "upgrade-backup-request.json"
	StatusFile     = "upgrade-backups.json"
	MaxStatusBytes = 2 << 20
	MaxItems       = 1000
)

var (
	ErrInvalid       = errors.New("升级备份请求无效")
	ErrUnsupported   = errors.New("此安装不支持管理升级备份")
	ErrBusy          = errors.New("已有升级或备份管理任务正在处理")
	ErrState         = errors.New("升级备份状态无法读取，请检查维护服务")
	ErrNotFound      = errors.New("备份不在当前列表中，请刷新列表")
	ErrProtected     = errors.New("该备份暂不可删除，请刷新列表查看原因")
	backupIDPattern  = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)
	requestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	fileNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type File struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"sizeBytes"`
}

type Item struct {
	ID              string `json:"id"`
	CreatedAt       string `json:"createdAt"`
	PreviousVersion string `json:"previousVersion"`
	SizeBytes       int64  `json:"sizeBytes"`
	Files           []File `json:"files"`
	Deletable       bool   `json:"deletable"`
	Reason          string `json:"reason,omitempty"`
}

type Status struct {
	Supported      bool   `json:"supported"`
	Reason         string `json:"reason,omitempty"`
	Phase          string `json:"phase"`
	RequestID      string `json:"requestId,omitempty"`
	Operation      string `json:"operation,omitempty"`
	BackupID       string `json:"backupId,omitempty"`
	Message        string `json:"message,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
	Items          []Item `json:"items"`
	TotalSizeBytes int64  `json:"totalSizeBytes"`
	Truncated      bool   `json:"truncated,omitempty"`
	RemainingCount int    `json:"remainingCount,omitempty"`
}

type Request struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	BackupID  string `json:"backupId"`
	CreatedAt string `json:"createdAt"`
}

type Client struct {
	DataDir  string
	StateDir string
	Ready    func(context.Context) error
}

func New(dataDir string) *Client {
	c := &Client{DataDir: dataDir, StateDir: "/var/lib/aswired-updater"}
	c.Ready = func(ctx context.Context) error {
		if runtime.GOOS != "linux" || filepath.Clean(dataDir) != "/var/lib/aswired" {
			return errors.New("此安装方式不支持网页管理升级备份，请使用正式组合部署包")
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, "systemctl", "is-active", "aswired-upgrade-backups.path").Output()
		if err != nil || strings.TrimSpace(string(output)) != "active" {
			return errors.New("升级备份维护服务未安装或未启动；旧安装需先按升级文档更新")
		}
		return nil
	}
	return c
}

func ValidBackupID(id string) bool {
	if !backupIDPattern.MatchString(id) {
		return false
	}
	stamp, err := time.Parse("20060102T150405Z", id)
	return err == nil && stamp.Format("20060102T150405Z") == id
}

func safeText(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

func validTimestamp(value string) bool {
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func readJSON(path string, limit int64, target any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return ErrState
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return ErrState
	}
	return json.Unmarshal(raw, target)
}

func validRequest(request Request) bool {
	return requestIDPattern.MatchString(request.ID) && validTimestamp(request.CreatedAt) &&
		(request.Operation == "list" && request.BackupID == "" || request.Operation == "delete" && ValidBackupID(request.BackupID))
}

func validateStatus(status Status) error {
	switch status.Phase {
	case "idle", "scanning", "deleting", "completed", "failed":
	default:
		return ErrState
	}
	if status.RequestID != "" && !requestIDPattern.MatchString(status.RequestID) || status.BackupID != "" && !ValidBackupID(status.BackupID) || status.UpdatedAt != "" && !validTimestamp(status.UpdatedAt) {
		return ErrState
	}
	if status.Operation != "" && status.Operation != "list" && status.Operation != "delete" || !safeText(status.Message, 2048) || len(status.Items) > MaxItems || status.TotalSizeBytes < 0 || status.RemainingCount < 0 || !status.Truncated && status.RemainingCount != 0 {
		return ErrState
	}
	seen := map[string]bool{}
	var total int64
	for _, item := range status.Items {
		if !ValidBackupID(item.ID) || seen[item.ID] || !validTimestamp(item.CreatedAt) || !safeText(item.PreviousVersion, 128) || !safeText(item.Reason, 2048) || item.SizeBytes < 0 || len(item.Files) > 32 || math.MaxInt64-total < item.SizeBytes {
			return ErrState
		}
		seen[item.ID] = true
		total += item.SizeBytes
		files := map[string]bool{}
		for _, file := range item.Files {
			if !fileNamePattern.MatchString(file.Name) || files[file.Name] || file.SizeBytes < 0 {
				return ErrState
			}
			files[file.Name] = true
		}
	}
	if total != status.TotalSizeBytes {
		return ErrState
	}
	return nil
}

func (c *Client) readStatus() (Status, error) {
	status := Status{Phase: "idle", Items: []Item{}}
	err := readJSON(filepath.Join(c.StateDir, StatusFile), MaxStatusBytes, &status)
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil || validateStatus(status) != nil {
		return Status{Phase: "failed", Message: ErrState.Error(), Items: []Item{}}, ErrState
	}
	if status.Items == nil {
		status.Items = []Item{}
	}
	for i := range status.Items {
		if status.Items[i].Files == nil {
			status.Items[i].Files = []File{}
		}
	}
	// The worker cannot claim support or provide a public reason via its JSON.
	status.Supported, status.Reason = false, ""
	return status, nil
}

func (c *Client) Status(ctx context.Context) Status {
	status, _ := c.readStatus()
	if c.Ready == nil {
		status.Reason = "升级备份维护服务未配置"
	} else if err := c.Ready(ctx); err != nil {
		status.Reason = err.Error()
	} else {
		status.Supported = true
	}
	var request Request
	err := readJSON(filepath.Join(c.DataDir, RequestFile), 4096, &request)
	if errors.Is(err, os.ErrNotExist) {
		return status
	}
	if err != nil || !validRequest(request) {
		status.Phase, status.Message = "failed", "待处理的升级备份请求无效，请检查维护服务"
		return status
	}
	if status.RequestID != request.ID || status.Phase == "idle" {
		status.Phase, status.Message = "queued", "等待升级备份维护服务处理"
		status.RequestID, status.Operation, status.BackupID, status.UpdatedAt = request.ID, request.Operation, request.BackupID, request.CreatedAt
	}
	return status
}

func filePresent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (c *Client) Request(ctx context.Context, operation, backupID string) (Request, error) {
	if operation != "list" && operation != "delete" || operation == "list" && backupID != "" || operation == "delete" && !ValidBackupID(backupID) {
		return Request{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	if c.Ready == nil {
		return Request{}, ErrUnsupported
	}
	if err := c.Ready(ctx); err != nil {
		return Request{}, fmt.Errorf("%w: %s", ErrUnsupported, err)
	}
	status, err := c.readStatus()
	if err != nil {
		return Request{}, ErrState
	}
	if status.Phase == "scanning" || status.Phase == "deleting" {
		return Request{}, ErrBusy
	}
	for _, name := range []string{RequestFile, "update-request.json"} {
		present, err := filePresent(filepath.Join(c.DataDir, name))
		if err != nil {
			return Request{}, ErrState
		}
		if present {
			return Request{}, ErrBusy
		}
	}
	var upgrade struct {
		Phase string `json:"phase"`
	}
	if err := readJSON(filepath.Join(c.StateDir, "status.json"), 8192, &upgrade); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Request{}, ErrState
	}
	if upgrade.Phase == "queued" || upgrade.Phase == "updating" {
		return Request{}, ErrBusy
	}
	if operation == "delete" {
		found := false
		for _, item := range status.Items {
			if item.ID == backupID {
				found = true
				if !item.Deletable {
					return Request{}, ErrProtected
				}
			}
		}
		if !found {
			return Request{}, ErrNotFound
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Request{}, ErrState
	}
	request := Request{ID: hex.EncodeToString(nonce[:]), Operation: operation, BackupID: backupID, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	data, err := json.Marshal(request)
	if err != nil {
		return Request{}, ErrState
	}
	f, err := os.CreateTemp(c.DataDir, ".upgrade-backup-request-*")
	if err != nil {
		return Request{}, ErrState
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return Request{}, ErrState
	}
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	if err = os.Link(f.Name(), filepath.Join(c.DataDir, RequestFile)); errors.Is(err, os.ErrExist) {
		return Request{}, ErrBusy
	}
	if err != nil {
		return Request{}, ErrState
	}
	return request, nil
}
