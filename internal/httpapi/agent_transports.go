package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (a *App) agentPull(w http.ResponseWriter, r *http.Request) {
	var hello agentwire.Hello
	r.Body = http.MaxBytesReader(w, r.Body, agentwire.MaxPacket*2)
	if json.NewDecoder(r.Body).Decode(&hello) != nil {
		fail(w, 400, "invalid_packet", "无效加密数据包")
		return
	}
	channel, e := agentwire.NewServer(a.MasterPrivate, hello.PublicKey)
	if e != nil {
		fail(w, 401, "agent_auth_failed", "节点认证失败")
		return
	}
	var report agentwire.Report
	if channel.Open(hello.Packet, &report) != nil {
		fail(w, 401, "agent_auth_failed", "节点认证失败")
		return
	}
	a.mu.Lock()
	_, seen := a.handshakes[hello.PublicKey]
	if !seen {
		a.handshakes[hello.PublicKey] = time.Now()
	}
	a.mu.Unlock()
	if seen {
		fail(w, 409, "replayed_handshake", "连接请求已使用")
		return
	}
	reply, e := a.acceptReport(r.Context(), report, "Pull")
	if e != nil {
		reply = agentwire.Reply{Error: e.Error()}
	}
	packet, e := channel.Seal(reply)
	if e != nil {
		fail(w, 500, "channel_error", "加密响应失败")
		return
	}
	respond(w, 200, packet)
}
func (a *App) direct(ctx context.Context, server store.Record, cmd agentwire.Command) (agentwire.Result, error) {
	if !nativeServer(server) {
		return agentwire.Result{}, errUnsupportedServerConnection
	}
	if retiredAgentAction(cmd.Action) {
		return agentwire.Result{}, errors.New("此动作已不受支持")
	}
	address := text(server.Data, "agentUrl")
	if address == "" {
		host := text(server.Data, "address")
		if strings.ContainsAny(host, "/\\?#@") {
			return agentwire.Result{}, errors.New("invalid server address")
		}
		port := int(number(server.Data, "agentPort"))
		if port == 0 {
			port = 23889
		}
		address = "http://" + net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
	}
	u, e := url.Parse(address)
	if e != nil || validateAgentURL(address) != nil || u == nil {
		return agentwire.Result{}, errors.New("invalid Agent URL")
	}
	credentials, e := a.DB.GetRecord(ctx, "_agentCredentials", server.ID)
	if e != nil {
		return agentwire.Result{}, e
	}
	nonceBytes := make([]byte, 32)
	if _, e = rand.Read(nonceBytes); e != nil {
		return agentwire.Result{}, e
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(address, "/")+"/v1/hello?nonce="+url.QueryEscape(nonce), nil)
	client := *a.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, e := client.Do(req)
	if e != nil {
		return agentwire.Result{}, e
	}
	defer res.Body.Close()
	var hello agentwire.DirectHello
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&hello) != nil {
		return agentwire.Result{}, errors.New("Agent handshake failed")
	}
	now := time.Now()
	if hello.Nonce != nonce || hello.ServerID != server.ID || hello.MasterPublicKey != a.MasterPublic || hello.Timestamp < now.Add(-90*time.Second).Unix() || hello.Timestamp > now.Add(90*time.Second).Unix() {
		return agentwire.Result{}, errors.New("Agent handshake identity or freshness mismatch")
	}
	if e = agentwire.VerifyDirectHello(text(credentials.Data, "agentToken"), hello); e != nil {
		return agentwire.Result{}, errors.New("Agent handshake identity proof rejected")
	}
	ch, e := agentwire.NewServer(a.MasterPrivate, hello.PublicKey)
	if e != nil {
		return agentwire.Result{}, e
	}
	packet, e := ch.Seal(agentwire.DirectRequest{Token: text(credentials.Data, "agentToken"), Command: cmd, Timestamp: time.Now().Unix()})
	if e != nil {
		return agentwire.Result{}, e
	}
	body, _ := json.Marshal(agentwire.Hello{PublicKey: hello.PublicKey, Packet: packet})
	req, _ = http.NewRequestWithContext(ctx, "POST", strings.TrimRight(address, "/")+"/v1/rpc", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, e = client.Do(req)
	if e != nil {
		return agentwire.Result{}, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return agentwire.Result{}, fmt.Errorf("Agent HTTP status %d", res.StatusCode)
	}
	var response agentwire.Packet
	if e = json.NewDecoder(io.LimitReader(res.Body, agentwire.MaxPacket*2)).Decode(&response); e != nil {
		return agentwire.Result{}, e
	}
	var result agentwire.Result
	if e = ch.Open(response, &result); e != nil {
		return result, e
	}
	if result.ID != cmd.ID {
		return result, errors.New("Agent result ID mismatch")
	}
	return result, nil
}

func validateAgentURL(address string) error {
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("Agent URL 须为不含凭据、查询参数或片段的 HTTP(S) 地址")
	}
	return nil
}
