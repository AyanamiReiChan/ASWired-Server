package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

type mcpTool struct {
	Name, Description, Collection, Operation, Action string
	Write, Destructive                               bool
}

func mcpCatalog() []mcpTool {
	tools := []mcpTool{{Name: "workspace_list", Description: "列出有权访问的资源", Operation: "list"}, {Name: "workspace_get", Description: "读取有权访问的单个资源", Operation: "get"}, {Name: "workspace_save", Description: "保存资源", Operation: "save", Write: true}, {Name: "run_action", Description: "执行主控业务操作并返回实际结果或任务标识", Operation: "action", Write: true}}
	for _, collection := range collections {
		for _, op := range []string{"list", "get", "create", "update", "delete"} {
			operation := op
			if op == "create" || op == "update" {
				operation = "save"
			}
			tools = append(tools, mcpTool{Name: collection + "_" + op, Description: collection + " · " + op, Collection: collection, Operation: operation, Write: op != "list" && op != "get", Destructive: op == "delete"})
		}
	}
	for _, action := range []string{"mihomo.config.apply", "mihomo.users.sync", "mihomo.status", "mihomo.start", "mihomo.stop", "mihomo.restart", "mihomo.config.get", "telegram.webhook.set", "telegram.webhook.delete", "telegram.webhook.status", "telegram.commands.set", "forward.chain.status", "network.forward.apply", "network.forward.status", "network.wireguard.apply", "network.wireguard.remove", "network.wireguard.status", "network.warp.apply", "network.warp.remove", "network.warp.status", "network.quality", "forward.apply", "forward.disable", "forward.chain.apply", "forward.ledger", "core.status", "core.config.get", "core.config.apply", "core.config.history", "core.config.restore", "core.start", "core.stop", "core.restart", "core.stats", "core.users.sync", "core.policy.apply", "core.connections", "server.config.apply", "server.global.update", "server.scan", "server.ports.check", "server.credentials.rotate", "inbound.config.apply", "outbound.config.apply", "routing.apply", "member.credentials.sync", "node.health.check", "source.sync", "speedtest.run", "task.retry", "certificate.issue", "certificate.renew", "certificate.upload", "certificate.deploy", "ddns.sync", "site.apply", "network.latency", "backup.create", "backup.remote.upload", "backup.remote.download", "template.preview", "template.import", "template.history", "template.restore", "script.validate", "federation.publish", "federation.connect", "federation.sync", "federation.revoke", "federation.disconnect", "federation.agent.publish", "federation.agent.connect", "federation.agent.execute", "federation.agent.result", "federation.agent.revoke", "membership.code.create", "membership.code.revoke", "membership.redeem", "membership.request", "membership.request.confirm", "membership.request.reject", "subscription.renewal.declare", "subscription.renewal.confirm", "subscription.renewal.reject", "subscription.traffic.reset", "komari.test", "komari.sync", "notification.test", "token.create", "token.revoke"} {
		tools = append(tools, mcpTool{Name: strings.ReplaceAll(action, ".", "_"), Description: action, Operation: "action", Action: action, Write: true, Destructive: destructiveAction(action)})
	}
	return tools
}
func destructiveAction(action string) bool {
	return strings.HasSuffix(action, ".remove") || strings.HasSuffix(action, ".disable") || strings.HasSuffix(action, ".revoke") || strings.HasSuffix(action, ".reset") || strings.HasSuffix(action, ".stop") || strings.HasSuffix(action, ".restore") || action == "server.credentials.rotate"
}
func (a *App) mcp(w http.ResponseWriter, r *http.Request) {
	var call struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if !decode(w, r, &call) {
		return
	}
	reply := func(result any) { respond(w, 200, map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result}) }
	rpcErr := func(code int, message string) {
		respond(w, 200, map[string]any{"jsonrpc": "2.0", "id": call.ID, "error": map[string]any{"code": code, "message": message}})
	}
	u, scopes, e := a.authenticateAPIToken(r)
	if e != nil {
		fail(w, 401, "unauthorized", "MCP需要有效API Token")
		return
	}
	if call.JSONRPC != "2.0" {
		rpcErr(-32600, "Invalid JSON-RPC version")
		return
	}
	switch call.Method {
	case "initialize":
		reply(map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "ASWired", "version": Version}})
	case "notifications/initialized":
		w.WriteHeader(202)
	case "ping":
		reply(map[string]any{})
	case "tools/list":
		tools := []any{}
		for _, spec := range mcpCatalog() {
			if u.Role != "admin" && (adminOnlyCollection(spec.Collection) || spec.Action == "source.sync" || spec.Collection == "nodes" && spec.Operation != "list") {
				continue
			}
			if spec.Write && !hasScope(scopes, "write") {
				continue
			}
			tools = append(tools, map[string]any{"name": spec.Name, "description": spec.Description, "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"collection": map[string]string{"type": "string"}, "id": map[string]string{"type": "string"}, "row": map[string]string{"type": "object"}, "action": map[string]string{"type": "string"}, "targetId": map[string]string{"type": "string"}, "params": map[string]string{"type": "object"}, "confirm": map[string]string{"type": "boolean"}}}, "annotations": map[string]bool{"readOnlyHint": !spec.Write, "destructiveHint": spec.Destructive}})
		}
		reply(map[string]any{"tools": tools})
	case "tools/call":
		args := call.Params.Arguments
		if args == nil {
			args = map[string]any{}
		}
		var spec *mcpTool
		for _, candidate := range mcpCatalog() {
			if candidate.Name == call.Params.Name {
				copy := candidate
				spec = &copy
				break
			}
		}
		if spec == nil {
			rpcErr(-32601, "Tool not found")
			return
		}
		if !hasScope(scopes, "read") || spec.Write && !hasScope(scopes, "write") {
			rpcErr(-32602, "Token scope denied")
			return
		}
		if spec.Collection != "" {
			args["collection"] = spec.Collection
		}
		if spec.Action != "" {
			args["action"] = spec.Action
		}
		if (spec.Destructive || destructiveAction(text(args, "action"))) && !boolean(args, "confirm") {
			rpcErr(-32602, "该操作需要confirm=true")
			return
		}
		ctx := context.WithValue(r.Context(), userKey{}, u)
		rec := httptest.NewRecorder()
		request := r.Clone(ctx)
		request.SetPathValue("collection", text(args, "collection"))
		request.SetPathValue("id", text(args, "id"))
		var handler http.HandlerFunc
		switch spec.Operation {
		case "list":
			handler = a.list
			request.Method = "GET"
		case "get":
			handler = a.get
			request.Method = "GET"
		case "save":
			handler = a.save
			if text(args, "id") == "" {
				request.Method = "POST"
			} else {
				request.Method = "PUT"
			}
		case "delete":
			handler = a.delete
			request.Method = "DELETE"
		case "action":
			handler = a.action
			request.Method = "POST"
		default:
			rpcErr(-32601, "Tool not found")
			return
		}
		body, _ := json.Marshal(args)
		request.Body = http.NoBody
		if spec.Write {
			request.Body = ioBody(body)
		}
		handler(rec, request)
		reply(map[string]any{"content": []any{map[string]string{"type": "text", "text": rec.Body.String()}}, "isError": rec.Code >= 400})
	default:
		rpcErr(-32601, "Method not found")
	}
}

type bytesBody struct{ *bytes.Reader }

func (bytesBody) Close() error  { return nil }
func ioBody(b []byte) bytesBody { return bytesBody{bytes.NewReader(b)} }
