package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func managedProtocolFixture(protocol string) map[string]any {
	row := map[string]any{"name": protocol, "serverId": "server", "tag": "managed-test", "protocol": protocol, "port": 8443, "listen": "127.0.0.1", "network": "tcp", "security": "none", "transport": "TCP / NONE", "flow": "无", "status": "启用", "method": "aes-128-gcm", "snellVersion": 4}
	if protocol == "Trojan" || protocol == "Hysteria2" || protocol == "AnyTLS" {
		row["security"] = "tls"
		row["transport"] = "TCP / TLS"
		row["sni"] = "example.test"
		row["certificateFile"] = "/cert.pem"
		row["keyFile"] = "/key.pem"
	}
	if protocol == "Hysteria2" {
		row["network"] = "hysteria"
		row["transport"] = "HYSTERIA / TLS"
		row["alpn"] = "h3"
	}
	return row
}

func TestManagedProtocolsCreatePublishSubscribeAndRevoke(t *testing.T) {
	for _, protocol := range []string{"VLESS", "VMess", "Trojan", "Shadowsocks", "Hysteria2", "SOCKS5", "HTTP", "AnyTLS", "Snell"} {
		t.Run(protocol, func(t *testing.T) {
			a, sub := subscriptionFixture(t)
			ctx := context.Background()
			a.peers["server"] = &peer{LastSeen: time.Now(), Capabilities: map[string]bool{"managed_protocols_v2": true, "managed_account_reload": true, "anytls": true, "snell": true}}
			enableProxyIPv6GuardFixture(a, "server")
			actor, _ := a.DB.UserByID(ctx, "admin")
			token, _ := a.Signer.Issue(actor.ID, actor.TokenVersion)
			response := controllerRequest(t, a.Handler(), "POST", "/api/collections/inbounds", token, map[string]any{"row": managedProtocolFixture(protocol)})
			requireStatus(t, response, http.StatusOK)
			saved := responseMap(t, response)["row"].(map[string]any)
			id := text(saved, "id")
			inbound, err := a.DB.GetRecord(ctx, "inbounds", id)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.refreshInboundNodes(ctx); err != nil {
				t.Fatal(err)
			}
			node, err := a.DB.GetRecord(ctx, "nodes", "inbound-"+id)
			if err != nil {
				t.Fatal(err)
			}
			users, err := a.usersForInbound(ctx, inbound)
			if err != nil || len(users) != 1 {
				t.Fatalf("users: %v %v", users, err)
			}
			syncRaw, _ := json.Marshal(agentwire.Command{Action: "core.users.sync", Params: map[string]any{"inbound": text(inbound.Data, "tag"), "users": users}})
			syncTask := store.Task{ServerID: "server", Input: syncRaw}
			client, err := a.realitySubscriptionNode(ctx, node, sub)
			if err != nil {
				t.Fatal(err)
			}
			if client.Protocol == "socks5" || client.Protocol == "http" {
				if client.Username != text(users[0], "email") {
					t.Fatal("account identity mismatch")
				}
			}
			output, _, skipped, err := a.renderSubscription(ctx, sub, []store.Record{node}, "clash")
			if err != nil || skipped != 0 || !strings.Contains(output, protocol) {
				t.Fatalf("subscription: %s %d %v", output, skipped, err)
			}
			task, err := a.queueCompile(ctx, actor, "server")
			if err != nil {
				t.Fatal(err)
			}
			if err = a.validateManagedInboundTask(ctx, task); err != nil {
				t.Fatal(err)
			}
			var command agentwire.Command
			_ = json.Unmarshal(task.Input, &command)
			if dir := os.Getenv("ASWIRED_PROTOCOL_FIXTURES"); dir != "" && !auxiliaryProtocol(inbound.Data) {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(map[string]any{"config": command.Params["config"], "client": client, "users": users})
				if err := os.WriteFile(filepath.Join(dir, protocol+".json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				if protocol == "VLESS" || protocol == "VMess" || protocol == "Trojan" {
					for _, network := range []string{"ws", "grpc"} {
						row := clone(inbound.Data)
						row["network"] = network
						row["security"] = "tls"
						row["transport"] = strings.ToUpper(network) + " / TLS"
						row["certificateFile"] = "/cert.pem"
						row["keyFile"] = "/key.pem"
						row["sni"] = "example.test"
						row["path"] = "/contract"
						row["serviceName"] = "contract"
						compiled, e := compileInbound(row, users)
						if e != nil {
							t.Fatal(e)
						}
						config := clone(command.Params["config"].(map[string]any))
						config["inbounds"] = []any{compiled}
						raw, _ = json.Marshal(map[string]any{"config": config, "client": client, "users": users})
						if err := os.WriteFile(filepath.Join(dir, protocol+"-"+network+".json"), raw, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if auxiliaryProtocol(inbound.Data) {
				if !nonemptyManagedListeners(command.Params["auxiliary"].(map[string]any)) {
					t.Fatal("missing auxiliary listener")
				}
			}
			sub.Data["status"] = "禁用"
			_, err = a.DB.SaveRecord(ctx, sub)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.validateManagedInboundTask(ctx, task); err == nil {
				t.Fatal("stale credentials can replay")
			}
			if err = a.validateManagedInboundTask(ctx, syncTask); err == nil {
				t.Fatal("stale user synchronization can replay")
			}
			users, err = a.usersForInbound(ctx, inbound)
			if err != nil || len(users) != 0 {
				t.Fatal("users were not revoked", err)
			}
			replacement, err := a.queueCompile(ctx, actor, "server")
			if err != nil {
				t.Fatal(err)
			}
			if err = a.validateManagedInboundTask(ctx, replacement); err != nil {
				t.Fatal(err)
			}
			deleted := controllerRequest(t, a.Handler(), "DELETE", "/api/collections/inbounds/"+id, token, nil)
			requireStatus(t, deleted, http.StatusOK)
			deletionTask, err := a.DB.GetTask(ctx, text(responseMap(t, deleted)["task"].(map[string]any), "id"))
			if err != nil {
				t.Fatal(err)
			}
			if err = a.validateManagedInboundTask(ctx, deletionTask); err != nil {
				t.Fatal("deletion cannot dispatch", err)
			}
			if auxiliaryProtocol(inbound.Data) {
				var command agentwire.Command
				_ = json.Unmarshal(deletionTask.Input, &command)
				aux, ok := command.Params["auxiliary"].(map[string]any)
				if !ok || nonemptyManagedListeners(aux) {
					t.Fatal("deleted auxiliary listener not cleared")
				}
			}
			if _, err = a.DB.GetRecord(ctx, "nodes", node.ID); err == nil {
				t.Fatal("node projection survived deletion")
			}
		})
	}
}

func TestManagedTransportAndCapabilityValidation(t *testing.T) {
	for _, protocol := range []string{"VLESS", "VMess", "Trojan"} {
		for _, network := range []string{"tcp", "ws", "grpc"} {
			row := managedProtocolFixture(protocol)
			row["network"] = network
			row["transport"] = strings.ToUpper(network) + " / " + strings.ToUpper(text(row, "security"))
			row["path"] = "/test"
			row["serviceName"] = "test"
			compiled, err := compileInbound(row, nil)
			if err != nil {
				t.Fatal(protocol, network, err)
			}
			stream := compiled["streamSettings"].(map[string]any)
			if text(stream, "network") != network {
				t.Fatal("transport lost")
			}
		}
	}
	for _, protocol := range []string{"TUIC", "Hysteria", "WireGuard"} {
		if err := validateManagedInboundProfile(managedProtocolFixture(protocol)); err == nil {
			t.Fatal("unsupported protocol accepted", protocol)
		}
	}
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "http", Data: managedProtocolFixture("HTTP")})
	if err != nil {
		t.Fatal(err)
	}
	actor, _ := a.DB.UserByID(ctx, "admin")
	if _, err = a.queueCompile(ctx, actor, "server"); err == nil {
		t.Fatal("old Agent accepted reload protocol")
	}
}
