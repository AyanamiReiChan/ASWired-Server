package httpapi

import (
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/logfiles"
	"net/http"
	"os"
)

func (a *App) listLogFiles(w http.ResponseWriter, r *http.Request) {
	logs := a.logStream(r.URL.Query().Get("stream"))
	if logs == nil {
		fail(w, 503, "unavailable", "主控文件日志未启用")
		return
	}
	result, err := logs.List()
	if err != nil {
		fail(w, 500, "storage_error", "读取日志文件失败")
		return
	}
	respond(w, 200, result)
}
func (a *App) removeLogFiles(w http.ResponseWriter, r *http.Request) {
	logs := a.logStream(r.URL.Query().Get("stream"))
	if logs == nil {
		fail(w, 503, "unavailable", "主控文件日志未启用")
		return
	}
	var input struct {
		Name    string `json:"name"`
		All     bool   `json:"all"`
		Confirm bool   `json:"confirm"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !input.Confirm || (input.All && input.Name != "") || (!input.All && input.Name == "") {
		fail(w, 400, "invalid_request", "请确认明确的日志清理范围")
		return
	}
	var err error
	if input.All {
		err = logs.Clear()
	} else {
		err = logs.Delete(input.Name)
	}
	if err != nil {
		switch {
		case errors.Is(err, logfiles.ErrName):
			fail(w, 400, "invalid_name", "无效的日志文件名")
		case errors.Is(err, os.ErrNotExist):
			fail(w, 404, "not_found", "日志文件已轮转或删除，请刷新")
		default:
			fail(w, 500, "storage_error", "日志清理未完成，请刷新文件列表后重试")
		}
		return
	}
	respond(w, 200, map[string]bool{"success": true})
}
