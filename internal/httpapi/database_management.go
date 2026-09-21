package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
)

var databaseManagementMu sync.Mutex

func (a *App) databaseStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	stats := a.DB.DB().Stats()
	driver := a.DB.Driver()
	if driver == "pgx" {
		driver = "postgres"
	}
	result := map[string]any{"driver": driver, "databaseType": map[string]string{"sqlite": "SQLite", "postgres": "PostgreSQL"}[driver], "openConnections": stats.OpenConnections, "inUse": stats.InUse, "idle": stats.Idle, "maxOpen": stats.MaxOpenConnections, "waitCount": stats.WaitCount, "sizeBytes": nil, "walSizeBytes": nil}
	if driver == "sqlite" {
		rows, err := a.DB.DB().QueryContext(ctx, "PRAGMA database_list")
		if err != nil {
			fail(w, 503, "database_status_failed", "读取数据库状态失败")
			return
		}
		path := ""
		for rows.Next() {
			var seq int
			var name, file string
			if err = rows.Scan(&seq, &name, &file); err != nil {
				break
			}
			if name == "main" {
				path = file
			}
		}
		rowErr := rows.Err()
		rows.Close()
		if err != nil || rowErr != nil {
			fail(w, 503, "database_status_failed", "读取数据库状态失败")
			return
		}
		if path != "" {
			result["sizeBytes"] = databaseFileSize(path)
			result["walSizeBytes"] = databaseFileSize(path + "-wal")
		}
	} else {
		var size int64
		if err := a.DB.DB().QueryRowContext(ctx, "SELECT pg_database_size(current_database())").Scan(&size); err == nil {
			result["sizeBytes"] = size
		}
	}
	databaseManagementMu.Lock()
	defer databaseManagementMu.Unlock()
	pending, err := config.ReadDatabaseChange(a.Config.DataDir, config.DatabasePendingFile)
	if err != nil {
		fail(w, 503, "database_config_failed", "读取迁移状态失败")
		return
	}
	active, err := config.ReadDatabaseChange(a.Config.DataDir, config.DatabaseActiveFile)
	if err != nil {
		fail(w, 503, "database_config_failed", "读取数据库配置失败")
		return
	}
	if active != nil {
		result["connection"] = active.Target.Public()
		result["maxIdle"] = active.Target.MaxIdle
		result["lastMigration"] = map[string]any{"state": active.State, "message": active.Message, "backupId": active.BackupID}
	}
	if pending != nil {
		result["migration"] = map[string]any{"state": pending.State, "message": pending.Message, "createdAt": pending.CreatedAt, "target": pending.Target.Public(), "backupId": pending.BackupID}
	}
	result["canMigrate"] = driver == "sqlite" && (pending == nil || pending.State == "failed")
	respond(w, 200, result)
}

func databaseFileSize(path string) any {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return int64(0)
	}
	if err != nil {
		return nil
	}
	return info.Size()
}

func checkDatabase(ctx context.Context, p config.PostgreSQL, empty bool) error {
	db, err := sql.Open("pgx", p.DSN())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(p.MaxOpen)
	db.SetMaxIdleConns(p.MaxIdle)
	if err = db.PingContext(ctx); err != nil {
		return err
	}
	if empty {
		var count int
		// A dedicated empty schema prevents altering an existing application's tables.
		err = db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE'").Scan(&count)
		if err != nil {
			return err
		}
		if count != 0 {
			return errors.New("target_not_empty")
		}
	}
	return nil
}

func (a *App) databaseTest(w http.ResponseWriter, r *http.Request) {
	var in config.PostgreSQL
	if !decode(w, r, &in) {
		return
	}
	if err := in.Validate(); err != nil {
		fail(w, 400, "invalid_database", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	started := time.Now()
	if err := checkDatabase(ctx, in, false); err != nil {
		fail(w, 400, "database_connection_failed", "无法连接 PostgreSQL，请检查地址、凭据和 SSL 模式")
		return
	}
	respond(w, 200, map[string]any{"success": true, "latencyMs": time.Since(started).Milliseconds(), "message": "PostgreSQL 连接成功"})
}

func (a *App) databaseMigrate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirm string            `json:"confirm"`
		Target  config.PostgreSQL `json:"target"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Confirm != "迁移到 PostgreSQL" {
		fail(w, 400, "confirmation_required", "请输入「迁移到 PostgreSQL」确认")
		return
	}
	if a.DB.Driver() != "sqlite" {
		fail(w, 409, "unsupported_source", "只有 SQLite 支持迁移到 PostgreSQL")
		return
	}
	if err := in.Target.Validate(); err != nil {
		fail(w, 400, "invalid_database", err.Error())
		return
	}
	databaseManagementMu.Lock()
	defer databaseManagementMu.Unlock()
	old, err := config.ReadDatabaseChange(a.Config.DataDir, config.DatabasePendingFile)
	if err != nil {
		fail(w, 503, "database_config_failed", "读取迁移状态失败")
		return
	}
	if old != nil && old.State != "failed" {
		fail(w, 409, "migration_pending", "已有迁移等待执行，请刷新状态")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if err = checkDatabase(ctx, in.Target, true); err != nil {
		if err.Error() == "target_not_empty" {
			fail(w, 409, "target_not_empty", "目标数据库必须使用空的 schema，不能覆盖已有数据")
		} else {
			fail(w, 400, "database_connection_failed", "目标 PostgreSQL 连接失败，未开始迁移")
		}
		return
	}
	change := config.DatabaseChange{ID: newID(), Target: in.Target, Source: config.DatabaseSource(a.Config.DatabaseDriver, a.Config.DatabaseDSN), State: "pending", CreatedAt: time.Now().UTC()}
	if err = config.WriteDatabaseChange(a.Config.DataDir, config.DatabasePendingFile, change); err != nil {
		fail(w, 500, "database_config_failed", "无法保存加密迁移配置，未开始迁移")
		return
	}
	respond(w, 202, map[string]any{"accepted": true, "state": "pending", "message": "迁移已安排，主控将短暂重启并备份、复制和校验数据。请稍后刷新数据库状态。"})
	select {
	case a.restart <- struct{}{}:
	default:
	}
}

func (a *App) databaseCancel(w http.ResponseWriter, r *http.Request) {
	databaseManagementMu.Lock()
	defer databaseManagementMu.Unlock()
	old, err := config.ReadDatabaseChange(a.Config.DataDir, config.DatabasePendingFile)
	if err != nil {
		fail(w, 503, "database_config_failed", "读取迁移状态失败")
		return
	}
	if old != nil && old.State != "failed" {
		fail(w, 409, "migration_running", "迁移已开始，请等待完成")
		return
	}
	if err = os.Remove(filepath.Join(a.Config.DataDir, config.DatabasePendingFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		fail(w, 500, "database_config_failed", "清除迁移记录失败")
		return
	}
	respond(w, 200, map[string]bool{"success": true})
}

func (a *App) RestartRequested() <-chan struct{} { return a.restart }
