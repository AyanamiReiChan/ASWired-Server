package httpapi

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var errUnsupportedServerConnection = errors.New("请选择自动、WebSocket、HTTP 或轮询连接的内嵌 Xray Agent")

func nativeServerConnection(connection string) bool {
	switch strings.ToLower(strings.TrimSpace(connection)) {
	case "websocket", "http", "pull", "auto", "自动", "轮询":
		return true
	default:
		return false
	}
}

func serverConnectionMode(server store.Record) string {
	mode := strings.ToLower(strings.TrimSpace(text(server.Data, "connection")))
	switch mode {
	case "自动", "auto":
		return "auto"
	case "轮询", "pull":
		return "pull"
	case "http":
		return "http"
	default:
		return "websocket"
	}
}

func serverConnectionLabel(mode string) string {
	switch mode {
	case "auto":
		return "自动"
	case "http":
		return "HTTP"
	case "pull":
		return "轮询"
	default:
		return "WebSocket"
	}
}

func agentListenAddress(server store.Record) string {
	port := int(number(server.Data, "agentPort"))
	if port == 0 {
		port = 23889
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
}

func nativeServer(server store.Record) bool {
	if mode := text(server.Data, "xray_mode"); mode != "" && mode != "embedded" {
		return false
	}
	connection := text(server.Data, "connection")
	if nativeServerConnection(connection) {
		return true
	}
	if strings.TrimSpace(connection) != "" {
		return false
	}
	if mode := text(server.Data, "managementMode"); mode != "" && !strings.EqualFold(mode, "agent") {
		return false
	}
	for key, value := range server.Data {
		if strings.HasPrefix(strings.ToLower(key), "xui") && value != nil && value != "" {
			return false
		}
	}
	return true
}

func retiredAgentAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	return action == "core.mode.migrate" || strings.HasPrefix(action, "xui.")
}
