package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

// ApplyDatabaseMigration must run before HTTP listeners or background jobs start.
// It preserves SQLite and the data directory keys; only an empty PostgreSQL
// schema is initialized. A committed target is recoverable after a process crash.
func (a *App) ApplyDatabaseMigration(ctx context.Context) (bool, error) {
	change, err := config.ReadDatabaseChange(a.Config.DataDir, config.DatabasePendingFile)
	if err != nil || change == nil {
		return false, err
	}
	active, err := config.ReadDatabaseChange(a.Config.DataDir, config.DatabaseActiveFile)
	if err != nil {
		return false, err
	}
	if active != nil && active.ID == change.ID {
		return false, os.Remove(filepath.Join(a.Config.DataDir, config.DatabasePendingFile))
	}
	if change.State == "failed" {
		return false, nil
	}
	failure := func(message string) (bool, error) {
		change.State = "failed"
		change.Message = message
		if err := config.WriteDatabaseChange(a.Config.DataDir, config.DatabasePendingFile, *change); err != nil {
			return false, errors.New("无法保存迁移失败状态，已停止启动以保护数据")
		}
		return false, nil
	}
	if a.DB.Driver() != "sqlite" || change.Source != config.DatabaseSource(a.Config.DatabaseDriver, a.Config.DatabaseDSN) {
		return failure("源数据库配置已变化，迁移未执行")
	}
	if change.State == "pending" {
		backup, err := a.createBackup(ctx, store.User{})
		if err != nil {
			return failure("SQLite 备份失败，继续使用原数据库")
		}
		change.BackupID = text(backup, "id")
		change.State = "copying"
		if err = config.WriteDatabaseChange(a.Config.DataDir, config.DatabasePendingFile, *change); err != nil {
			return false, errors.New("迁移备份状态保存失败")
		}
	}
	if change.State != "copying" || change.BackupID == "" || strings.ContainsAny(change.BackupID, "/\\.") {
		return failure("迁移记录无效，未切换数据库")
	}
	raw, err := os.ReadFile(filepath.Join(a.Config.DataDir, "backups", change.BackupID+".zip"))
	if err != nil {
		return failure("读取迁移备份失败，未切换数据库")
	}
	manifest, err := migrationManifest(raw)
	if err != nil {
		return failure("迁移备份校验失败，未切换数据库")
	}
	target, err := sql.Open("pgx", change.Target.DSN())
	if err != nil {
		return failure("连接 PostgreSQL 失败，未切换数据库")
	}
	defer target.Close()
	target.SetMaxOpenConns(change.Target.MaxOpen)
	target.SetMaxIdleConns(change.Target.MaxIdle)
	committed, err := copyDatabaseManifest(ctx, target, *change, manifest)
	if err != nil {
		// Commit/network or activation errors can be ambiguous. Keep the snapshot and
		// retry the same migration ID on next start, rather than serving stale SQLite.
		if committed {
			return false, errors.New("目标数据库提交状态待确认；原数据库保留，请重新启动以继续校验")
		}
		return failure("迁移失败：目标须为空且允许建表和写入，原 SQLite 保留并继续使用")
	}
	change.State = "completed"
	change.Message = "数据备份、复制和校验完成，已切换 PostgreSQL"
	if err = config.WriteDatabaseChange(a.Config.DataDir, config.DatabaseActiveFile, *change); err != nil {
		return false, errors.New("数据已复制，切换配置保存失败；请重启以继续激活，勿修改原数据库")
	}
	// Active config is the durable commit point. A leftover pending file is
	// removed on the next start only if its ID matches the active config.
	_ = os.Remove(filepath.Join(a.Config.DataDir, config.DatabasePendingFile))
	return true, nil
}

func migrationManifest(raw []byte) (backupManifest, error) {
	var manifest backupManifest
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return manifest, err
	}
	data, err := readZipFile(archive, "manifest.json", maxBackupManifestBytes)
	if err != nil {
		return manifest, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&manifest) != nil || manifest.Format != "ASWired-logical-backup" || manifest.Version != 1 || len(manifest.Tables) != len(backupTables) {
		return manifest, errors.New("invalid migration backup")
	}
	for _, name := range backupTables {
		if _, ok := manifest.Tables[name]; !ok {
			return manifest, errors.New("missing backup table")
		}
	}
	for _, table := range manifest.Tables {
		for _, row := range table.Rows {
			if len(row) != len(table.Columns) {
				return manifest, errors.New("invalid backup row")
			}
			for i, v := range row {
				if n, ok := v.(json.Number); ok {
					if integer, err := n.Int64(); err == nil {
						row[i] = integer
					} else {
						decimal, err := n.Float64()
						if err != nil {
							return manifest, err
						}
						row[i] = decimal
					}
				}
			}
		}
	}
	return manifest, nil
}

func tableDigest(table backupTable) string {
	rows := make([]string, 0, len(table.Rows))
	for _, row := range table.Rows {
		raw, _ := json.Marshal(row)
		rows = append(rows, string(raw))
	}
	sort.Strings(rows)
	raw, _ := json.Marshal(struct {
		Columns []string
		Rows    []string
	}{table.Columns, rows})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func manifestDigest(manifest backupManifest) string {
	var body strings.Builder
	for _, name := range backupTables {
		body.WriteString(name + ":" + tableDigest(manifest.Tables[name]) + "\n")
	}
	hash := sha256.Sum256([]byte(body.String()))
	return hex.EncodeToString(hash[:])
}

func readMigrationTable(ctx context.Context, tx *sql.Tx, name string) (backupTable, error) {
	table := backupTable{Rows: [][]any{}}
	rows, err := tx.QueryContext(ctx, "SELECT * FROM "+name)
	if err != nil {
		return table, err
	}
	defer rows.Close()
	table.Columns, err = rows.Columns()
	if err != nil {
		return table, err
	}
	for rows.Next() {
		values := make([]any, len(table.Columns))
		dest := make([]any, len(values))
		for i := range values {
			dest[i] = &values[i]
		}
		if err = rows.Scan(dest...); err != nil {
			return table, err
		}
		for i, v := range values {
			if b, ok := v.([]byte); ok {
				values[i] = string(b)
			}
		}
		table.Rows = append(table.Rows, values)
	}
	return table, rows.Err()
}

func copyDatabaseManifest(ctx context.Context, db *sql.DB, change config.DatabaseChange, manifest backupManifest) (bool, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(1095976786)").Scan(&locked); err != nil || !locked {
		return false, errors.New("migration target is busy")
	}
	var tableCount int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE'").Scan(&tableCount); err != nil {
		return false, err
	}
	markerJSON, _ := json.Marshal(change.ID + ":" + manifestDigest(manifest))
	marker := string(markerJSON)
	if tableCount != 0 {
		var existing string
		if err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='_internal.database_migration'").Scan(&existing); err != nil || existing != marker {
			return false, errors.New("target database is not empty")
		}
		// The transaction committed previously. Compare the actual contents again.
		if err = verifyMigration(ctx, tx, manifest, true); err != nil {
			return true, err
		}
		return true, tx.Commit()
	}
	if err = store.CreateSchema(ctx, tx, "pgx"); err != nil {
		return false, err
	}
	// Schema migration metadata is created by CreateSchema. All application rows,
	// including encrypted credentials, token versions and traffic, are copied raw.
	for _, name := range backupTables {
		table := manifest.Tables[name]
		actual, err := readMigrationTable(ctx, tx, name)
		if err != nil {
			return false, err
		}
		if strings.Join(actual.Columns, "\x00") != strings.Join(table.Columns, "\x00") {
			return false, errors.New("backup schema mismatch")
		}
		placeholders := make([]string, len(table.Columns))
		for i := range placeholders {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}
		stmt, err := tx.PrepareContext(ctx, "INSERT INTO "+name+" ("+strings.Join(table.Columns, ",")+") VALUES ("+strings.Join(placeholders, ",")+")")
		if err != nil {
			return false, err
		}
		for _, row := range table.Rows {
			if _, err = stmt.ExecContext(ctx, row...); err != nil {
				stmt.Close()
				return false, err
			}
		}
		if err = stmt.Close(); err != nil {
			return false, err
		}
	}
	if err = verifyMigration(ctx, tx, manifest, false); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO settings(key,value,updated_at) VALUES('_internal.database_migration',$1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", marker, change.CreatedAt.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func verifyMigration(ctx context.Context, tx *sql.Tx, manifest backupManifest, ignoreMarker bool) error {
	for _, name := range backupTables {
		actual, err := readMigrationTable(ctx, tx, name)
		if err != nil {
			return err
		}
		expected := manifest.Tables[name]
		if ignoreMarker && name == "settings" {
			actual = withoutMigrationMarker(actual)
			expected = withoutMigrationMarker(expected)
		}
		if len(actual.Rows) != len(expected.Rows) || tableDigest(actual) != tableDigest(expected) {
			return fmt.Errorf("migration verification failed: %s", name)
		}
	}
	return nil
}

func withoutMigrationMarker(table backupTable) backupTable {
	rows := make([][]any, 0, len(table.Rows))
	for _, row := range table.Rows {
		if len(row) > 0 && row[0] != "_internal.database_migration" {
			rows = append(rows, row)
		}
	}
	table.Rows = rows
	return table
}
