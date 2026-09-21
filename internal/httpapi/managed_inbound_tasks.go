package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

var errManagedInboundReplay = errors.New("旧管理入站配置不再支持下发或重试，请从当前入站重新发布 VLESS TCP REALITY 配置")

func (a *App) validateManagedInboundTask(ctx context.Context, task store.Task) error {
	var command agentwire.Command
	if err := json.Unmarshal(task.Input, &command); err != nil {
		return err
	}
	if command.Action == "core.users.sync" {
		rows, err := a.DB.ListRecords(ctx, "inbounds", "")
		if err != nil {
			return err
		}
		for _, row := range rows {
			if text(row.Data, "serverId") != task.ServerID || text(row.Data, "tag") != text(command.Params, "inbound") {
				continue
			}
			users, err := a.usersForInbound(ctx, row)
			if err != nil {
				users = []map[string]any{}
			}
			want, _ := json.Marshal(users)
			got, _ := json.Marshal(command.Params["users"])
			if string(want) != string(got) {
				return errors.New("入站用户已改变，请重新同步，不能重试旧凭据")
			}
			return nil
		}
		deleted, err := a.DB.ListRecords(ctx, "_deletedManagedInbounds", "")
		if err != nil {
			return err
		}
		for _, row := range deleted {
			if text(row.Data, "serverId") == task.ServerID && text(row.Data, "tag") == text(command.Params, "inbound") {
				return errManagedInboundReplay
			}
		}
		return nil
	}
	if command.Action != "core.config.apply" && command.Action != "mihomo.config.apply" {
		return nil
	}
	params := command.Params
	if number(params, "managedProfileVersion") == 2 && command.Action == "core.config.apply" {
		return a.validateCurrentManagedConfig(ctx, task.ServerID, params)
	}
	if auxiliary, ok := params["auxiliary"].(map[string]any); ok && nonemptyManagedListeners(auxiliary) {
		return errManagedInboundReplay
	}
	rows, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return err
	}
	tags := map[string]bool{}
	for _, row := range rows {
		if text(row.Data, "serverId") != task.ServerID {
			continue
		}
		if tag := text(row.Data, "tag"); tag != "" {
			tags[tag] = true
		}
		tags["aswired-bridge-"+row.ID] = true
	}
	history, err := a.DB.ListRecords(ctx, "_managedInboundTags", "")
	if err != nil {
		return err
	}
	for _, record := range history {
		if text(record.Data, "serverId") == task.ServerID {
			for _, tag := range stringList(record.Data["tags"]) {
				tags[tag] = true
			}
		}
	}
	if command.Action == "mihomo.config.apply" {
		if !nonemptyManagedListeners(params) {
			return nil
		}
		state, err := a.DB.GetRecord(ctx, "_auxiliarySync", task.ServerID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if boolean(params, "managedInbounds") || task.ID == text(state.Data, "taskId") || task.ID == text(state.Data, "bridgeTaskId") {
			return errManagedInboundReplay
		}
		if listeners, ok := params["listeners"].([]any); ok {
			for _, raw := range listeners {
				if listener, ok := raw.(map[string]any); ok && tags[text(listener, "name")] {
					return errManagedInboundReplay
				}
			}
		}
		return nil
	}
	marked := boolean(params, "managedInbounds")
	config, ok := params["config"].(map[string]any)
	if !ok {
		if marked {
			return errManagedInboundReplay
		}
		return nil
	}
	if err := a.validateManagedOutboundTask(ctx, task.ServerID, config, marked); err != nil {
		return err
	}
	if err := a.rejectDeletedInboundReplay(ctx, task.ServerID, config); err != nil {
		return err
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok {
		if marked {
			return errManagedInboundReplay
		}
		return nil
	}
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			if marked {
				return errManagedInboundReplay
			}
			continue
		}
		if !marked && !tags[text(inbound, "tag")] {
			continue
		}
		stream, _ := inbound["streamSettings"].(map[string]any)
		if !strings.EqualFold(text(inbound, "protocol"), "vless") || !strings.EqualFold(defaultText(stream, "network", "tcp"), "tcp") || !strings.EqualFold(text(stream, "security"), "reality") {
			return errManagedInboundReplay
		}
	}
	return nil
}

// New managed tasks must still match current records, including user credentials.
// This also prevents delayed retries from restoring revoked users or old listeners.
func (a *App) validateCurrentManagedConfig(ctx context.Context, serverID string, params map[string]any) error {
	if !boolean(params, "managedInbounds") {
		return errManagedInboundReplay
	}
	cfg, ok := params["config"].(map[string]any)
	if !ok {
		return errManagedInboundReplay
	}
	if err := a.rejectDeletedInboundReplay(ctx, serverID, cfg); err != nil {
		return err
	}
	if err := a.validateManagedOutboundTask(ctx, serverID, cfg, true); err != nil {
		return err
	}
	expected, err := a.compile(ctx, serverID)
	if err != nil {
		return err
	}
	canonical := func(value any) string {
		raw, _ := json.Marshal(value)
		var rows []map[string]any
		_ = json.Unmarshal(raw, &rows)
		for _, row := range rows {
			settings, _ := row["settings"].(map[string]any)
			accounts, _ := settings["accounts"].([]any)
			if len(accounts) == 1 {
				account, _ := accounts[0].(map[string]any)
				if text(account, "user") == "aswired-disabled" {
					account["pass"] = "disabled"
				}
			}
		}
		raw, _ = json.Marshal(rows)
		return string(raw)
	}
	if canonical(cfg["inbounds"]) != canonical(expected["inbounds"]) {
		return errors.New("入站或用户已改变，请重新发布当前配置")
	}
	aux, err := a.compileAuxiliary(ctx, serverID)
	if err != nil {
		return err
	}
	actual, _ := params["auxiliary"].(map[string]any)
	if nonemptyManagedListeners(aux) || nonemptyManagedListeners(actual) {
		want, _ := json.Marshal(aux)
		got, _ := json.Marshal(actual)
		if string(want) != string(got) {
			return errors.New("辅助入站已改变，请重新发布")
		}
	}
	return a.checkInboundCapabilities(ctx, serverID)
}

func nonemptyManagedListeners(params map[string]any) bool {
	raw, exists := params["listeners"]
	if !exists || raw == nil {
		return false
	}
	listeners, ok := raw.([]any)
	return !ok || len(listeners) > 0
}

func (a *App) rememberManagedInboundTags(ctx context.Context, inbound store.Record) error {
	serverID, tag := text(inbound.Data, "serverId"), text(inbound.Data, "tag")
	if serverID == "" || inbound.ID == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(serverID + "\x00" + inbound.ID + "\x00" + tag))
	id := hex.EncodeToString(digest[:])
	if _, err := a.DB.GetRecord(ctx, "_managedInboundTags", id); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	tags := []string{"aswired-bridge-" + inbound.ID}
	if tag != "" {
		tags = append(tags, tag)
	}
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_managedInboundTags", ID: id, Data: map[string]any{"serverId": serverID, "tags": tags}})
	if errors.Is(err, store.ErrConflict) {
		if _, readErr := a.DB.GetRecord(ctx, "_managedInboundTags", id); readErr == nil {
			return nil
		}
	}
	return err
}

func (a *App) validateManagedOutboundTask(ctx context.Context, serverID string, config map[string]any, marked bool) error {
	raw, present := config["outbounds"]
	if !present {
		return nil
	}
	outbounds, ok := raw.([]any)
	if !ok {
		if marked {
			return errors.New("管理出站配置无效，请重新发布 VLESS TCP REALITY 配置")
		}
		return nil
	}
	tags := map[string]bool{}
	if !marked {
		rows, err := a.DB.ListRecords(ctx, "outbounds", "")
		if err != nil {
			return err
		}
		for _, row := range rows {
			if text(row.Data, "serverId") == serverID {
				tags[text(row.Data, "tag")] = true
			}
		}
	}
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok {
			if marked {
				return errors.New("管理出站配置无效，请重新发布 VLESS TCP REALITY 配置")
			}
			continue
		}
		if !marked && !tags[text(outbound, "tag")] {
			continue
		}
		if err := validateRealityOutbound(outbound); err != nil {
			return errors.New("旧管理出站配置不再支持下发或重试，请重新发布 VLESS TCP REALITY 配置：" + err.Error())
		}
	}
	return nil
}
