package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

const trafficInternalCollection = "_trafficInternalTransfers"

// A server/email pair is explicit operator configuration, never inferred from
// email prefixes. The deterministic ID also prevents duplicate concurrent adds.
func trafficPairID(serverID, email string) string {
	digest := sha256.Sum256([]byte(serverID + "\x00" + email))
	return hex.EncodeToString(digest[:])
}

func trafficInternalRow(record store.Record) map[string]any {
	row := map[string]any{"id": record.ID, "serverId": text(record.Data, "serverId"), "email": text(record.Data, "email"), "name": text(record.Data, "name")}
	if source := text(record.Data, "sourceServerId"); source != "" {
		row["sourceServerId"] = source
	}
	return row
}

func (a *App) trafficInternalIndex(ctx context.Context) (map[string]store.Record, error) {
	records, err := a.DB.ListRecords(ctx, trafficInternalCollection, "")
	if err != nil {
		return nil, err
	}
	index := make(map[string]store.Record, len(records))
	for _, record := range records {
		index[trafficPairID(text(record.Data, "serverId"), text(record.Data, "email"))] = record
	}
	return index, nil
}

func (a *App) trafficInternalTransfers(w http.ResponseWriter, r *http.Request) {
	records, err := a.DB.ListRecords(r.Context(), trafficInternalCollection, "")
	if err != nil {
		fail(w, 503, "storage_error", "内部中转分类读取失败")
		return
	}
	items := make([]any, 0, len(records))
	for _, record := range records {
		items = append(items, trafficInternalRow(record))
	}
	respond(w, 200, map[string]any{"items": items})
}

func validTrafficLabel(value string, max int) bool {
	return value != "" && utf8.RuneCountInString(value) <= max && !strings.ContainsFunc(value, unicode.IsControl)
}

func (a *App) saveTrafficInternalTransfer(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ServerID       string `json:"serverId"`
		Email          string `json:"email"`
		Name           string `json:"name"`
		SourceServerID string `json:"sourceServerId"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.ServerID = strings.TrimSpace(input.ServerID)
	input.Email = strings.TrimSpace(input.Email)
	input.Name = strings.TrimSpace(input.Name)
	input.SourceServerID = strings.TrimSpace(input.SourceServerID)
	if !validTrafficLabel(input.ServerID, 256) || !validTrafficLabel(input.Email, 320) || strings.Contains(input.Email, ">>>") || !validTrafficLabel(input.Name, 120) {
		fail(w, 400, "invalid_internal_transfer", "请填写有效的服务器、Xray用户标识和线路名称")
		return
	}
	ctx := r.Context()
	for _, id := range []string{input.ServerID, input.SourceServerID} {
		if id == "" {
			continue
		}
		server, err := a.DB.GetRecord(ctx, "servers", id)
		if errors.Is(err, store.ErrNotFound) || err == nil && !nativeServer(server) {
			fail(w, 400, "invalid_server", "请选择有效的原生服务器")
			return
		}
		if err != nil {
			fail(w, 503, "storage_error", "服务器读取失败")
			return
		}
	}
	trafficMu.Lock()
	defer trafficMu.Unlock()
	owned, err := a.trafficEmailOwned(ctx, input.ServerID, input.Email)
	if err != nil {
		fail(w, 503, "storage_error", "流量归属检查失败")
		return
	}
	if owned {
		fail(w, 409, "assigned_email", "该用户标识已归属成员订阅，不能标记为内部中转")
		return
	}
	id := trafficPairID(input.ServerID, input.Email)
	record, err := a.DB.GetRecord(ctx, trafficInternalCollection, id)
	if errors.Is(err, store.ErrNotFound) {
		record = store.Record{Collection: trafficInternalCollection, ID: id}
	} else if err != nil {
		fail(w, 503, "storage_error", "内部中转分类读取失败")
		return
	}
	record.Data = map[string]any{"serverId": input.ServerID, "email": input.Email, "name": input.Name}
	if input.SourceServerID != "" {
		record.Data["sourceServerId"] = input.SourceServerID
	}
	record, err = a.DB.SaveRecord(ctx, record)
	if err != nil {
		fail(w, 503, "storage_error", "内部中转分类保存失败")
		return
	}
	a.audit(ctx, current(r), "traffic.internal-transfer.save", record.ID, record.Data)
	respond(w, 200, trafficInternalRow(record))
}

func (a *App) trafficEmailOwned(ctx context.Context, serverID, email string) (bool, error) {
	subscriptions, err := a.DB.ListRecords(ctx, "subscriptions", "")
	if err != nil {
		return false, err
	}
	inbounds, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return false, err
	}
	for _, sub := range subscriptions {
		base := text(sub.Data, "credentialEmail")
		if base == "" {
			continue
		}
		if email == base {
			return true, nil
		}
		for _, inbound := range inbounds {
			if text(inbound.Data, "serverId") == serverID && email == base+"."+inbound.ID {
				return true, nil
			}
		}
	}
	var assigned bool
	err = a.DB.DB().QueryRowContext(ctx, a.DB.Bind(`SELECT EXISTS(SELECT 1 FROM traffic_ledger WHERE server_id=? AND email=? AND (owner_id<>'' OR subscription_id<>''))`), serverID, email).Scan(&assigned)
	return assigned, err
}

func (a *App) deleteTrafficInternalTransfer(w http.ResponseWriter, r *http.Request) {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	id := r.PathValue("id")
	err := a.DB.DeleteRecord(r.Context(), trafficInternalCollection, id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, 404, "not_found", "内部中转分类不存在")
		return
	}
	if err != nil {
		fail(w, 503, "storage_error", "内部中转分类删除失败")
		return
	}
	a.audit(r.Context(), current(r), "traffic.internal-transfer.delete", id, nil)
	respond(w, 200, map[string]any{"ok": true})
}
