package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func backupDestination(cfg map[string]any) string {
	values := []string{}
	for _, key := range []string{"provider", "url", "bucket", "prefix", "region", "username", "accessKeyId", "clientId", "folderId", "apiBaseURL", "refreshToken"} {
		values = append(values, text(cfg, key))
	}
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (a *App) backupRemoteRequest(ctx context.Context, cfg map[string]any, method string, record *store.Record) (*http.Request, error) {
	provider := strings.ToLower(text(cfg, "provider"))
	base := strings.TrimRight(text(cfg, "url"), "/")
	if provider == "gdrive" {
		base = defaultText(cfg, "apiBaseURL", "https://www.googleapis.com")
		if _, err := secureOrigin(base); err != nil {
			return nil, err
		}
		token, err := a.driveToken(ctx, cfg)
		if err != nil {
			return nil, err
		}
		id := defaultText(cfg, "folderId", "root")
		if record != nil {
			id = text(record.Data, "fileId")
			if id == "" {
				return nil, errors.New("缺少 Drive 文件 ID")
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, base+"/drive/v3/files/"+url.PathEscape(id), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}
	if _, err := secureOrigin(base); err != nil {
		return nil, err
	}
	address := base
	if provider == "s3" {
		bucket := text(cfg, "bucket")
		if bucket == "" || strings.ContainsAny(bucket, "/\\?# ") {
			return nil, errors.New("S3 Bucket无效")
		}
		address += "/" + url.PathEscape(bucket)
		if record != nil {
			for _, part := range strings.Split(strings.Trim(text(cfg, "prefix"), "/"), "/") {
				if part == ".." || part == "." {
					return nil, errors.New("S3 Prefix无效")
				}
				if part != "" {
					address += "/" + url.PathEscape(part)
				}
			}
		}
	} else if provider != "webdav" {
		return nil, errors.New("远程备份服务无效")
	}
	if record != nil {
		object := text(record.Data, "object")
		if object != record.ID+".aswb" || strings.ContainsAny(record.ID, "/\\. ") {
			return nil, errors.New("备份对象标识无效")
		}
		address += "/" + url.PathEscape(object)
	} else if provider == "s3" {
		address += "?list-type=2&max-keys=1"
	}
	req, err := http.NewRequestWithContext(ctx, method, address, nil)
	if err != nil {
		return nil, err
	}
	if provider == "webdav" {
		req.SetBasicAuth(text(cfg, "username"), text(cfg, "password"))
		req.Header.Set("Depth", "0")
	} else if err = signS3(req, nil, cfg, time.Now()); err != nil {
		return nil, err
	}
	return req, nil
}

func (a *App) testRemoteBackup(ctx context.Context, cfg map[string]any) (map[string]any, error) {
	method := "GET"
	if strings.EqualFold(text(cfg, "provider"), "webdav") {
		method = "PROPFIND"
	}
	req, err := a.backupRemoteRequest(ctx, cfg, method, nil)
	if err != nil {
		return nil, err
	}
	response, err := a.backupHTTP(req)
	if err != nil {
		return nil, err
	}
	response.Body.Close()
	return map[string]any{"success": true, "message": "远程存储认证与读取成功；写入权限将在实际上传时验证"}, nil
}

// Only delete objects created by this controller at the identical configured
// destination. Unknown historical objects and other accounts are never swept.
func (a *App) pruneRemoteBackups(ctx context.Context, u store.User, cfg map[string]any) (int, error) {
	if err := validateBackupRetention(cfg); err != nil {
		return 0, err
	}
	keep := int(number(cfg, "keepLast"))
	if keep == 0 {
		return 0, nil
	}
	if keep < 1 || keep > 10000 {
		return 0, errors.New("远程保留份数须为 1 至 10000；0 表示不自动清理")
	}
	rows, err := a.DB.ListRecords(ctx, "_remoteBackups", "")
	if err != nil {
		return 0, err
	}
	eligible := []store.Record{}
	destination := backupDestination(cfg)
	for _, row := range rows {
		if text(row.Data, "destination") == destination {
			eligible = append(eligible, row)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].CreatedAt.Equal(eligible[j].CreatedAt) {
			return eligible[i].ID > eligible[j].ID
		}
		return eligible[i].CreatedAt.After(eligible[j].CreatedAt)
	})
	if len(eligible) <= keep {
		return 0, nil
	}
	removed := 0
	for _, row := range eligible[keep:] {
		request, err := a.backupRemoteRequest(ctx, cfg, "DELETE", &row)
		if err != nil {
			return removed, err
		}
		response, err := a.backupHTTP(request)
		if err != nil {
			return removed, err
		}
		response.Body.Close()
		if err = a.DB.DeleteRecord(ctx, "_remoteBackups", row.ID); err != nil {
			return removed, err
		}
		removed++
		a.audit(ctx, u, "backup.remote.prune", row.ID, map[string]any{"provider": text(cfg, "provider")})
	}
	return removed, nil
}

func validateBackupRetention(cfg map[string]any) error {
	value := number(cfg, "keepLast")
	if value < 0 || value > 10000 || math.Trunc(value) != value {
		return errors.New("远程保留份数须为 0 至 10000 的整数；0 表示不自动清理")
	}
	return nil
}
