package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"golang.org/x/crypto/scrypt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func backupSeal(raw []byte, password string) ([]byte, error) {
	if len(password) < 16 {
		return nil, errors.New("远程备份加密口令至少16字节")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	key, e := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	header := append([]byte("ASWBACK1"), salt...)
	header = append(header, nonce...)
	return append(header, gcm.Seal(nil, nonce, raw, header)...), nil
}
func backupOpen(raw []byte, password string) ([]byte, error) {
	if len(raw) < 52 || string(raw[:8]) != "ASWBACK1" {
		return nil, errors.New("远程备份格式无效")
	}
	key, e := scrypt.Key([]byte(password), raw[8:24], 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	out, e := gcm.Open(nil, raw[24:36], raw[36:], raw[:36])
	if e != nil {
		return nil, errors.New("备份口令错误或文件已损坏")
	}
	return out, nil
}
func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
func awsPath(path string) string {
	const digits = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~/", rune(c)) {
			out.WriteByte(c)
		} else {
			out.WriteByte('%')
			out.WriteByte(digits[c>>4])
			out.WriteByte(digits[c&15])
		}
	}
	return out.String()
}
func signS3(req *http.Request, body []byte, cfg map[string]any, now time.Time) error {
	access, secret := text(cfg, "accessKeyId"), text(cfg, "secretAccessKey")
	if access == "" || secret == "" {
		return errors.New("缺少S3访问凭据")
	}
	region := defaultText(cfg, "region", "us-east-1")
	hash := sha256.Sum256(body)
	payload := hex.EncodeToString(hash[:])
	date := now.UTC().Format("20060102T150405Z")
	day := now.UTC().Format("20060102")
	req.Header.Set("X-Amz-Date", date)
	req.Header.Set("X-Amz-Content-Sha256", payload)
	names := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	values := map[string]string{"host": req.URL.Host, "x-amz-content-sha256": payload, "x-amz-date": date}
	if session := text(cfg, "sessionToken"); session != "" {
		req.Header.Set("X-Amz-Security-Token", session)
		names = append(names, "x-amz-security-token")
		values["x-amz-security-token"] = session
	}
	if value := req.Header.Get("Range"); value != "" {
		names = append(names, "range")
		values["range"] = value
	}
	sort.Strings(names)
	canonicalHeaders := ""
	for _, name := range names {
		canonicalHeaders += name + ":" + strings.TrimSpace(values[name]) + "\n"
	}
	signed := strings.Join(names, ";")
	path := awsPath(req.URL.Path)
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{req.Method, path, strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20"), canonicalHeaders, signed, payload}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	scope := day + "/" + region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	key := hmacSHA256([]byte("AWS4"+secret), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+access+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)
	return nil
}
func (a *App) remoteBackup(ctx context.Context, u store.User, operation string, params map[string]any) (map[string]any, error) {
	var settings map[string]any
	if e := a.DB.GetSetting(ctx, "settings", &settings); e != nil {
		return nil, e
	}
	cfg, ok := settings["remoteBackup"].(map[string]any)
	if !ok {
		return nil, errors.New("尚未配置远程备份")
	}
	if operation == "backup.remote.test" {
		return a.testRemoteBackup(ctx, cfg)
	}
	if operation == "backup.remote.prune" {
		count, err := a.pruneRemoteBackups(ctx, u, cfg)
		return map[string]any{"removed": count, "success": err == nil}, err
	}
	password := text(cfg, "encryptionPassword")
	if password == "" {
		password = text(settings, "backupSecret")
	}
	if len(password) < 16 {
		return nil, errors.New("请配置至少16字节独立备份加密口令")
	}
	upload := operation == "backup.remote.upload"
	id := text(params, "id")
	var data []byte
	var e error
	if upload {
		result, e := a.createBackup(ctx, u)
		if e != nil {
			return nil, e
		}
		id = text(result, "id")
		raw, e := os.ReadFile(filepath.Join(a.Config.DataDir, "backups", id+".zip"))
		if e != nil {
			return nil, e
		}
		data, e = backupSeal(raw, password)
		if e != nil {
			return nil, e
		}
	} else {
		if id == "" || strings.ContainsAny(id, "/\\. ") {
			return nil, errors.New("请输入有效远程备份标识")
		}
	}
	provider := strings.ToLower(text(cfg, "provider"))
	object := id + ".aswb"
	method := "GET"
	if upload {
		method = "PUT"
	}
	base := strings.TrimRight(text(cfg, "url"), "/")
	var req *http.Request
	var driveID string
	switch provider {
	case "webdav", "s3":
		if _, e = secureOrigin(base); e != nil {
			return nil, e
		}
		address := base + "/" + url.PathEscape(object)
		if provider == "s3" {
			bucket := text(cfg, "bucket")
			if bucket == "" || strings.ContainsAny(bucket, "/\\?# ") {
				return nil, errors.New("S3 Bucket无效")
			}
			prefix := strings.Trim(text(cfg, "prefix"), "/")
			path := "/" + url.PathEscape(bucket)
			if prefix != "" {
				for _, part := range strings.Split(prefix, "/") {
					if part == ".." || part == "." {
						return nil, errors.New("S3 Prefix无效")
					}
					path += "/" + url.PathEscape(part)
				}
			}
			address = base + path + "/" + url.PathEscape(object)
		}
		req, e = http.NewRequestWithContext(ctx, method, address, bytes.NewReader(data))
		if e != nil {
			return nil, e
		}
		if provider == "webdav" {
			req.SetBasicAuth(text(cfg, "username"), text(cfg, "password"))
		} else if e = signS3(req, data, cfg, time.Now()); e != nil {
			return nil, e
		}
	case "gdrive":
		token, e := a.driveToken(ctx, cfg)
		if e != nil {
			return nil, e
		}
		apiBase := defaultText(cfg, "apiBaseURL", "https://www.googleapis.com")
		if _, e = secureOrigin(apiBase); e != nil {
			return nil, e
		}
		if upload {
			metadata := map[string]any{"name": object}
			if folder := text(cfg, "folderId"); folder != "" {
				metadata["parents"] = []string{folder}
			}
			raw, _ := json.Marshal(metadata)
			init, e := http.NewRequestWithContext(ctx, "POST", apiBase+"/upload/drive/v3/files?uploadType=resumable", bytes.NewReader(raw))
			if e != nil {
				return nil, e
			}
			init.Header.Set("Authorization", "Bearer "+token)
			init.Header.Set("Content-Type", "application/json")
			init.Header.Set("X-Upload-Content-Type", "application/octet-stream")
			init.Header.Set("X-Upload-Content-Length", fmt.Sprint(len(data)))
			res, e := a.backupHTTP(init)
			if e != nil {
				return nil, e
			}
			res.Body.Close()
			location := res.Header.Get("Location")
			target, e := url.Parse(location)
			origin, _ := url.Parse(apiBase)
			if e != nil || target.Host != origin.Host || target.Scheme != origin.Scheme {
				return nil, errors.New("Google Drive上传会话来源不匹配")
			}
			req, e = http.NewRequestWithContext(ctx, "PUT", location, bytes.NewReader(data))
			if e != nil {
				return nil, e
			}
			req.Header.Set("Authorization", "Bearer "+token)
		} else {
			record, e := a.DB.GetRecord(ctx, "_remoteBackups", id)
			if e != nil {
				return nil, e
			}
			driveID = text(record.Data, "fileId")
			if driveID == "" {
				return nil, errors.New("缺少Google Drive文件ID")
			}
			req, e = http.NewRequestWithContext(ctx, "GET", apiBase+"/drive/v3/files/"+url.PathEscape(driveID)+"?alt=media", nil)
			if e != nil {
				return nil, e
			}
			req.Header.Set("Authorization", "Bearer "+token)
		}
	default:
		return nil, errors.New("远程备份支持WebDAV、S3或Google Drive")
	}
	if upload {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	res, e := a.backupHTTP(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if upload {
		if provider == "gdrive" {
			var result map[string]any
			if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&result) != nil || text(result, "id") == "" {
				return nil, errors.New("Google Drive未确认文件ID")
			}
			driveID = text(result, "id")
		}
		_, e = a.DB.SaveRecord(ctx, store.Record{Collection: "_remoteBackups", ID: id, Data: map[string]any{"provider": provider, "object": object, "fileId": driveID, "size": len(data), "uploadedAt": time.Now().UTC(), "destination": backupDestination(cfg)}})
		if e != nil {
			return nil, e
		}
		a.audit(ctx, u, operation, id, map[string]any{"provider": provider})
		removed, pruneErr := a.pruneRemoteBackups(ctx, u, cfg)
		result := map[string]any{"success": true, "id": id, "provider": provider, "encrypted": true, "removed": removed}
		if pruneErr != nil {
			result["retentionError"] = pruneErr.Error()
			result["message"] = "备份已上传，但旧备份清理失败：" + pruneErr.Error()
		}
		return result, nil
	}
	encrypted, e := io.ReadAll(io.LimitReader(res.Body, maxBackupArchiveBytes+4097))
	if e != nil || len(encrypted) > maxBackupArchiveBytes+4096 {
		return nil, errors.New("远程备份超过大小限制")
	}
	raw, e := backupOpen(encrypted, password)
	if e != nil {
		return nil, e
	}
	newID := newID()
	path := filepath.Join(a.Config.DataDir, "backups", newID+".zip")
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	if e = atomicSecret(path, raw); e != nil {
		return nil, e
	}
	return map[string]any{"success": true, "id": newID, "url": "/api/backups/" + newID, "message": "备份已取回并验证解密，可下载后通过恢复界面检查与恢复"}, nil
}
func (a *App) backupHTTP(req *http.Request) (*http.Response, error) {
	client := *a.client
	client.Timeout = 2 * time.Minute
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, e := client.Do(req)
	if e != nil {
		return nil, errors.New("远程备份服务连接失败")
	}
	if (res.StatusCode < 200 || res.StatusCode >= 300) && !(req.Method == http.MethodDelete && res.StatusCode == http.StatusNotFound) {
		res.Body.Close()
		return nil, fmt.Errorf("远程备份服务返回HTTP %d", res.StatusCode)
	}
	return res, nil
}
func (a *App) driveToken(ctx context.Context, cfg map[string]any) (string, error) {
	endpoint := defaultText(cfg, "tokenURL", "https://oauth2.googleapis.com/token")
	if _, e := secureOrigin(endpoint); e != nil {
		return "", e
	}
	values := url.Values{"client_id": {text(cfg, "clientId")}, "client_secret": {text(cfg, "clientSecret")}, "refresh_token": {text(cfg, "refreshToken")}, "grant_type": {"refresh_token"}}
	if values.Get("refresh_token") == "" {
		return "", errors.New("缺少Google Drive刷新令牌")
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(values.Encode()))
	if e != nil {
		return "", e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, e := a.backupHTTP(req)
	if e != nil {
		return "", e
	}
	defer res.Body.Close()
	var out map[string]any
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out) != nil || text(out, "access_token") == "" {
		return "", errors.New("Google Drive令牌刷新失败")
	}
	return text(out, "access_token"), nil
}
