package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

type logDateSelection struct {
	StartDate   string `json:"startDate"`
	EndDate     string `json:"endDate"`
	Fingerprint string `json:"fingerprint"`
}

func logDateRange(start, end string) (time.Time, time.Time, error) {
	zone := time.FixedZone("Asia/Shanghai", 8*60*60)
	from, err := time.ParseInLocation("2006-01-02", start, zone)
	if err != nil || len(start) != 10 || from.Year() < 1 || from.Format("2006-01-02") != start {
		return time.Time{}, time.Time{}, store.ErrInvalid
	}
	through, err := time.ParseInLocation("2006-01-02", end, zone)
	if err != nil || len(end) != 10 || through.Year() < 1 || through.Year() >= 9999 || through.Format("2006-01-02") != end || through.Before(from) {
		return time.Time{}, time.Time{}, store.ErrInvalid
	}
	return from, through.AddDate(0, 0, 1), nil
}

func (a *App) previewLogs(w http.ResponseWriter, r *http.Request)      { a.logsByDate(w, r, false) }
func (a *App) deleteLogsByDate(w http.ResponseWriter, r *http.Request) { a.logsByDate(w, r, true) }

func (a *App) logsByDate(w http.ResponseWriter, r *http.Request, deleting bool) {
	collection := r.PathValue("collection")
	if collection != "tasks" && collection != "audit" {
		fail(w, http.StatusNotFound, "unknown_collection", "仅支持任务与审计日志")
		return
	}
	var input logDateSelection
	if !decode(w, r, &input) {
		return
	}
	from, to, err := logDateRange(input.StartDate, input.EndDate)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid_date_range", "请选择有效的开始和结束日期，结束日期不能早于开始日期")
		return
	}
	if deleting {
		fingerprint, err := hex.DecodeString(input.Fingerprint)
		if err != nil || len(fingerprint) != 32 {
			fail(w, http.StatusBadRequest, "preview_required", "请先预览本次删除范围")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var selected store.LogSelection
	if deleting {
		selected, err = a.DB.DeleteLogSelection(ctx, collection, from, to, time.Now(), input.Fingerprint, taskLogRetirementReason)
	} else {
		selected, err = a.DB.PreviewLogSelection(ctx, collection, from, to, time.Now())
	}
	if err != nil {
		switch {
		case errors.Is(err, store.ErrLogSelectionTooLarge):
			fail(w, http.StatusUnprocessableEntity, "range_too_large", "选定日期超过 10000 条日志，请缩小日期范围")
		case errors.Is(err, store.ErrLogPreviewChanged):
			fail(w, http.StatusConflict, "preview_changed", "日志或可删除状态已变化，请重新预览后确认")
		default:
			fail(w, http.StatusInternalServerError, "storage_error", "日志操作失败，请重试")
		}
		return
	}
	result := map[string]any{"startDate": input.StartDate, "endDate": input.EndDate, "timeZone": "Asia/Shanghai", "total": selected.Total, "protected": selected.Protected}
	if deleting {
		result["deleted"] = selected.Deletable
		if selected.Deletable > 0 {
			a.audit(r.Context(), current(r), "log.delete.batch", collection, map[string]any{"startDate": input.StartDate, "endDate": input.EndDate, "timeZone": "Asia/Shanghai", "deleted": selected.Deletable, "protected": selected.Protected})
		}
	} else {
		result["deletable"] = selected.Deletable
		result["fingerprint"] = selected.Fingerprint
	}
	respond(w, http.StatusOK, result)
}
