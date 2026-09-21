package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"github.com/coder/websocket"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxBackupArchiveBytes = 256 << 20
const maxBackupManifestBytes = 384 << 20

type backupBoundedWriter struct {
	Writer    io.Writer
	Remaining int64
}

func (w *backupBoundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.Remaining {
		return 0, errors.New("备份数据超过当前导出上限")
	}
	n, e := w.Writer.Write(data)
	w.Remaining -= int64(n)
	return n, e
}

var backupTables = []string{"users", "settings", "records", "subscription_bindings", "audit_events", "metrics", "tasks", "traffic_cursors", "traffic_ledger"}

type restoreJournal struct {
	ID       string
	Old, New map[string]string
}

func atomicSecret(path string, raw []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".activate-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func recoverRestore(dir string, db *store.Store) error {
	path := filepath.Join(dir, "restore-journal.json")
	raw, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var journal restoreJournal
	if e = json.Unmarshal(raw, &journal); e != nil {
		return e
	}
	var marker string
	e = db.DB().QueryRow(db.Bind("SELECT value FROM settings WHERE key=?"), "_internal.restore_marker").Scan(&marker)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	keys := journal.Old
	if marker == journal.ID {
		keys = journal.New
	}
	for _, name := range []string{"master-identity.key", "data-encryption.key"} {
		if keys[name] == "" {
			return errors.New("restore journal missing key")
		}
		if e = atomicSecret(filepath.Join(dir, name), []byte(keys[name])); e != nil {
			return e
		}
	}
	return os.Remove(path)
}

type backupTable struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}
type backupManifest struct {
	Format        string                 `json:"format"`
	Version       int                    `json:"version"`
	CreatedAt     time.Time              `json:"createdAt"`
	ServerVersion string                 `json:"serverVersion"`
	Tables        map[string]backupTable `json:"tables"`
}

func (a *App) createBackup(ctx context.Context, u store.User) (map[string]any, error) {
	options := &sql.TxOptions{ReadOnly: true}
	if a.DB.Driver() == "postgres" {
		options.Isolation = sql.LevelRepeatableRead
	}
	tx, e := a.DB.DB().BeginTx(ctx, options)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	manifest := backupManifest{Format: "ASWired-logical-backup", Version: 1, CreatedAt: time.Now().UTC(), ServerVersion: Version, Tables: map[string]backupTable{}}
	for _, name := range backupTables {
		rows, e := tx.QueryContext(ctx, "SELECT * FROM "+name)
		if e != nil {
			return nil, e
		}
		columns, e := rows.Columns()
		if e != nil {
			rows.Close()
			return nil, e
		}
		table := backupTable{Columns: columns, Rows: [][]any{}}
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if e = rows.Scan(dest...); e != nil {
				rows.Close()
				return nil, e
			}
			for i, v := range values {
				if b, ok := v.([]byte); ok {
					values[i] = string(b)
				}
			}
			table.Rows = append(table.Rows, values)
		}
		err := rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		manifest.Tables[name] = table
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	f, e := writer.Create("manifest.json")
	if e != nil {
		return nil, e
	}
	if e = json.NewEncoder(&backupBoundedWriter{Writer: f, Remaining: maxBackupManifestBytes}).Encode(manifest); e != nil {
		return nil, e
	}
	for _, name := range []string{"master-identity.key", "data-encryption.key"} {
		raw, e := os.ReadFile(filepath.Join(a.Config.DataDir, name))
		if e != nil {
			return nil, e
		}
		f, e := writer.Create("identity/" + name)
		if e != nil {
			return nil, e
		}
		if _, e = f.Write(raw); e != nil {
			return nil, e
		}
	}
	if e = writer.Close(); e != nil {
		return nil, e
	}
	if data.Len() > maxBackupArchiveBytes {
		return nil, errors.New("备份超过256MiB导出上限")
	}
	id := newID()
	dir := filepath.Join(a.Config.DataDir, "backups")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	path := filepath.Join(dir, id+".zip")
	if e = os.WriteFile(path, data.Bytes(), 0600); e != nil {
		return nil, e
	}
	a.audit(ctx, u, "backup.create", id, map[string]any{"size": data.Len(), "format": manifest.Format})
	return map[string]any{"success": true, "id": id, "url": "/api/backups/" + id, "format": manifest.Format, "size": data.Len(), "containsSecrets": true}, nil
}
func (a *App) backupDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || strings.ContainsAny(id, "/\\.") {
		fail(w, 400, "invalid_id", "备份标识无效")
		return
	}
	path := filepath.Join(a.Config.DataDir, "backups", id+".zip")
	if _, e := os.Stat(path); e != nil {
		fail(w, 404, "not_found", "备份不存在")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="aswired-backup-`+id+`.zip"`)
	w.Header().Set("Content-Type", "application/zip")
	http.ServeFile(w, r, path)
}
func readZipFile(archive *zip.Reader, name string, limit int64) ([]byte, error) {
	var selected *zip.File
	for _, f := range archive.File {
		if f.Name != name {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("duplicate backup entry %s", name)
		}
		selected = f
	}
	if selected == nil {
		return nil, fmt.Errorf("backup missing %s", name)
	}
	if selected.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("backup entry exceeds size limit")
	}
	reader, e := selected.Open()
	if e != nil {
		return nil, e
	}
	defer reader.Close()
	data, e := io.ReadAll(io.LimitReader(reader, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(data)) > limit {
		return nil, errors.New("backup entry exceeds size limit")
	}
	return data, nil
}
func (a *App) backupRestore(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("confirm") != "restore" {
		fail(w, 400, "confirmation_required", "恢复会替换主控数据，确认后使用confirm=restore")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBackupArchiveBytes))
	if e != nil {
		fail(w, 400, "invalid_backup", "备份超过大小限制")
		return
	}
	archive, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		fail(w, 400, "invalid_backup", "备份不是有效ZIP")
		return
	}
	manifestRaw, e := readZipFile(archive, "manifest.json", maxBackupManifestBytes)
	if e != nil {
		fail(w, 400, "invalid_backup", e.Error())
		return
	}
	var manifest backupManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.UseNumber()
	if decoder.Decode(&manifest) != nil || manifest.Format != "ASWired-logical-backup" || manifest.Version != 1 {
		fail(w, 400, "unsupported_backup", "此版本只恢复ASWired v1备份，不能将上游私有格式当作兼容备份")
		return
	}
	dataKeyRaw, e := readZipFile(archive, "identity/data-encryption.key", 4096)
	if e != nil {
		fail(w, 400, "invalid_backup", e.Error())
		return
	}
	dataKey, e := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(dataKeyRaw)))
	if e != nil || len(dataKey) != 32 {
		fail(w, 400, "invalid_backup", "数据恢复密钥无效")
		return
	}
	masterRaw, e := readZipFile(archive, "identity/master-identity.key", 4096)
	if e != nil {
		fail(w, 400, "invalid_backup", e.Error())
		return
	}
	master := strings.TrimSpace(string(masterRaw))
	pub, e := agentwire.PublicKey(master)
	if e != nil {
		fail(w, 400, "invalid_backup", "节点身份密钥无效")
		return
	}
	for _, table := range manifest.Tables {
		for _, row := range table.Rows {
			for i, v := range row {
				if n, ok := v.(json.Number); ok {
					if integer, err := n.Int64(); err == nil {
						row[i] = integer
					} else {
						decimal, err := n.Float64()
						if err != nil {
							fail(w, 400, "invalid_backup", "备份数值无效")
							return
						}
						row[i] = decimal
					}
				}
			}
		}
	}
	if len(manifest.Tables) != len(backupTables) {
		fail(w, 400, "invalid_backup", "备份表集合不完整")
		return
	}
	tx, e := a.DB.DB().BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 500, "storage_error", "无法开始恢复")
		return
	}
	defer tx.Rollback()
	for _, name := range backupTables {
		table, ok := manifest.Tables[name]
		if !ok {
			fail(w, 400, "invalid_backup", "备份缺少数据表")
			return
		}
		rows, e := tx.QueryContext(r.Context(), "SELECT * FROM "+name+" WHERE 1=0")
		if e != nil {
			fail(w, 500, "storage_error", "无法验证表结构")
			return
		}
		columns, e := rows.Columns()
		rows.Close()
		if e != nil || strings.Join(columns, "|") != strings.Join(table.Columns, "|") {
			fail(w, 400, "schema_mismatch", "备份表结构与当前版本不匹配")
			return
		}
		for _, row := range table.Rows {
			if len(row) != len(columns) {
				fail(w, 400, "invalid_backup", "备份行结构不完整")
				return
			}
		}
	}

	for name, table := range manifest.Tables {
		for _, row := range table.Rows {
			for i, c := range table.Columns {
				payload := name == "records" && c == "data" || name == "metrics" && c == "data" || name == "audit_events" && c == "details" || name == "tasks" && (c == "input" || c == "result") || name == "settings" && c == "value"
				if name == "settings" && fmt.Sprint(row[0]) == "_internal.restore_marker" {
					continue
				}
				if payload {
					if value, ok := row[i].(string); ok && value != "" {
						if e = store.ValidateEncryptedJSON(dataKey, []byte(value)); e != nil {
							fail(w, 400, "invalid_backup", "备份数据或解密密钥验证失败")
							return
						}
					}
				}
			}
		}
	}
	users := manifest.Tables["users"]
	adminFound := false
	for _, row := range users.Rows {
		record := map[string]any{}
		for i, c := range users.Columns {
			record[c] = row[i]
			if c == "token_version" {
				var b [8]byte
				if _, e = rand.Read(b[:]); e != nil {
					fail(w, 500, "restore_failed", "会话重置失败")
					return
				}
				row[i] = int64(binary.BigEndian.Uint64(b[:])&((1<<52)-1)) + 1
			}
		}
		if record["role"] == "admin" && (record["disabled"] == int64(0) || record["disabled"] == false) {
			adminFound = true
		}
	}
	if !adminFound {
		fail(w, 400, "invalid_backup", "备份没有可用管理员")
		return
	}
	for i := len(backupTables) - 1; i >= 0; i-- {
		if _, e = tx.ExecContext(r.Context(), "DELETE FROM "+backupTables[i]); e != nil {
			fail(w, 500, "restore_failed", "恢复事务失败，原数据保留")
			return
		}
	}
	for _, name := range backupTables {
		table := manifest.Tables[name]
		placeholders := strings.TrimRight(strings.Repeat("?,", len(table.Columns)), ",")
		q := a.DB.Bind("INSERT INTO " + name + " (" + strings.Join(table.Columns, ",") + ") VALUES (" + placeholders + ")")
		for _, row := range table.Rows {
			if _, e = tx.ExecContext(r.Context(), q, row...); e != nil {
				fail(w, 400, "restore_failed", "备份数据验证失败，原数据保留")
				return
			}
		}
	}
	journal := restoreJournal{ID: newID(), Old: map[string]string{}, New: map[string]string{"master-identity.key": string(masterRaw), "data-encryption.key": string(dataKeyRaw)}}
	for _, name := range []string{"master-identity.key", "data-encryption.key"} {
		old, err := os.ReadFile(filepath.Join(a.Config.DataDir, name))
		if err != nil {
			fail(w, 500, "restore_failed", "无法保留恢复材料")
			return
		}
		journal.Old[name] = string(old)
	}
	journalRaw, _ := json.Marshal(journal)
	if e = atomicSecret(filepath.Join(a.Config.DataDir, "restore-journal.json"), journalRaw); e != nil {
		fail(w, 500, "restore_failed", "无法保存恢复日志")
		return
	}
	if _, e = tx.ExecContext(r.Context(), a.DB.Bind("INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at"), "_internal.restore_marker", journal.ID, time.Now().UTC().Format(time.RFC3339Nano)); e != nil {
		fail(w, 500, "restore_failed", "无法保存恢复事务标记")
		return
	}
	if e = tx.Commit(); e != nil {
		_ = recoverRestore(a.Config.DataDir, a.DB)
		fail(w, 500, "restore_failed", "恢复事务提交失败")
		return
	}
	if e = recoverRestore(a.Config.DataDir, a.DB); e != nil {
		a.mu.Lock()
		a.recoveryRequired = true
		sockets := make([]*websocket.Conn, 0, len(a.sockets))
		for socket := range a.sockets {
			sockets = append(sockets, socket)
		}
		a.mu.Unlock()
		for _, socket := range sockets {
			_ = socket.CloseNow()
		}
		fail(w, 503, "restart_required", "数据已恢复，密钥激活未完成，请重启主控继续恢复")
		return
	}
	_ = a.DB.SetEncryptionKey(dataKey)
	a.MasterPrivate = master
	a.MasterPublic = pub
	a.mu.Lock()
	a.peers = map[string]*peer{}
	a.handshakes = map[string]time.Time{}
	a.identity = nil
	a.mu.Unlock()
	respond(w, 200, map[string]any{"success": true, "requiresLogin": true, "requiresAgentReconnect": true, "createdAt": manifest.CreatedAt})
}
