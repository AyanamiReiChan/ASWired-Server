package httpapi

import (
	_ "embed"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

//go:embed builtin_templates/clash-default.yaml
var defaultClashTemplate string

func builtinSubscriptionTemplate(format string) store.Record {
	if format != "clash" && format != "stash" {
		return store.Record{}
	}
	return store.Record{Collection: "policies", ID: "builtin-clash-default", Data: map[string]any{
		"name": "ASWired 默认分流", "type": "Clash", "content": defaultClashTemplate,
	}}
}
