package httpapi

import (
	"errors"
	"net/http"

	"github.com/AyanamiReiChan/ASWired-Server/internal/upgradebackups"
)

func (a *App) upgradeBackups() *upgradebackups.Client {
	if a.upgradeBackupClient != nil {
		return a.upgradeBackupClient
	}
	return upgradebackups.New(a.Config.DataDir)
}

func (a *App) upgradeBackupStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	respond(w, http.StatusOK, a.upgradeBackups().Status(r.Context()))
}

func (a *App) upgradeBackupRefresh(w http.ResponseWriter, r *http.Request) {
	a.queueUpgradeBackup(w, r, "list", "")
}

func (a *App) upgradeBackupDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !upgradebackups.ValidBackupID(id) {
		fail(w, 400, "invalid_backup_id", "升级备份标识无效")
		return
	}
	var input struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Confirm != id {
		fail(w, 400, "confirmation_required", "请输入完整备份标识以确认删除")
		return
	}
	a.queueUpgradeBackup(w, r, "delete", id)
}

func (a *App) queueUpgradeBackup(w http.ResponseWriter, r *http.Request, operation, id string) {
	client := a.upgradeBackups()
	request, err := client.Request(r.Context(), operation, id)
	if err != nil {
		status, code := http.StatusServiceUnavailable, "upgrade_backups_unavailable"
		switch {
		case errors.Is(err, upgradebackups.ErrInvalid):
			status, code = http.StatusBadRequest, "invalid_backup_request"
		case errors.Is(err, upgradebackups.ErrBusy):
			status, code = http.StatusConflict, "upgrade_backups_busy"
		case errors.Is(err, upgradebackups.ErrProtected):
			status, code = http.StatusConflict, "backup_not_deletable"
		case errors.Is(err, upgradebackups.ErrNotFound):
			status, code = http.StatusNotFound, "backup_not_found"
		}
		fail(w, status, code, err.Error())
		return
	}
	a.audit(r.Context(), current(r), "upgrade.backups."+operation+".queued", id, map[string]any{"requestId": request.ID, "operation": operation, "backupId": id})
	w.Header().Set("Cache-Control", "private, no-store")
	respond(w, http.StatusAccepted, client.Status(r.Context()))
}
