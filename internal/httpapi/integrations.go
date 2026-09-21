package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (a *App) externalJSON(ctx context.Context, method, address string, headers map[string]string, body any, out any) error {
	u, e := url.Parse(address)
	if e != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("外部地址须为HTTP(S)链接")
	}
	var raw []byte
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := *a.client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return errors.New("外部服务重定向未获允许")
	}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("外部服务连接失败")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("外部服务返回HTTP %d", res.StatusCode)
	}
	if out == nil {
		_, e = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		return e
	}
	return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out)
}

func (a *App) notificationTest(ctx context.Context, u store.User, id string, params map[string]any) (map[string]any, error) {
	var settings map[string]any
	if e := a.DB.GetSetting(ctx, "settings", &settings); e != nil && !errors.Is(e, store.ErrNotFound) {
		return nil, e
	}
	channel := text(params, "channel")
	if id != "" {
		if rec, e := a.DB.GetRecord(ctx, "notifications", id); e == nil {
			for k, v := range rec.Data {
				if settings == nil {
					settings = map[string]any{}
				}
				settings[k] = v
			}
			channel = defaultText(rec.Data, "channel", channel)
		}
	}
	message := defaultText(params, "message", "ASWired 通知渠道测试 "+time.Now().UTC().Format(time.RFC3339))
	if len(message) > 4000 {
		return nil, errors.New("通知内容过长")
	}
	if channel == "" {
		switch {
		case text(settings, "webhook") != "":
			channel = "webhook"
		case text(settings, "telegramToken") != "":
			channel = "telegram"
		case text(settings, "smtpHost") != "":
			channel = "email"
		}
	}
	switch strings.ToLower(channel) {
	case "webhook":
		payload := map[string]any{"event": defaultText(params, "event", "aswired.notification.test"), "message": message, "time": time.Now().UTC()}
		headers := map[string]string{}
		if key := text(settings, "webhookSecret"); key != "" {
			raw, _ := json.Marshal(payload)
			mac := hmac.New(sha256.New, []byte(key))
			mac.Write(raw)
			headers["X-ASWired-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		}
		if e := a.externalJSON(ctx, "POST", text(settings, "webhook"), headers, payload, nil); e != nil {
			return nil, e
		}
	case "telegram", "telegram bot":
		token := text(settings, "telegramToken")
		chat := defaultText(params, "chatId", text(settings, "telegramChatId"))
		if token == "" || chat == "" {
			return nil, errors.New("请配置Telegram Token与Chat ID")
		}
		if strings.ContainsAny(token, "/?# ") {
			return nil, errors.New("Telegram Token格式无效")
		}
		var result struct {
			OK bool `json:"ok"`
		}
		if e := a.externalJSON(ctx, "POST", "https://api.telegram.org/bot"+token+"/sendMessage", nil, map[string]any{"chat_id": chat, "text": message}, &result); e != nil {
			return nil, e
		}
		if !result.OK {
			return nil, errors.New("Telegram拒绝投递")
		}
	case "email", "smtp":
		if e := sendSMTP(ctx, settings, message); e != nil {
			return nil, e
		}
	default:
		return nil, errors.New("请先配置Webhook、Telegram或SMTP通知渠道")
	}
	return map[string]any{"success": true, "channel": channel, "deliveredAt": time.Now().UTC()}, nil
}
func sendSMTP(ctx context.Context, settings map[string]any, message string) error {
	host := text(settings, "smtpHost")
	port := int(number(settings, "smtpPort"))
	if port == 0 {
		port = 587
	}
	from := text(settings, "smtpFrom")
	to := text(settings, "smtpTo")
	if host == "" || from == "" || to == "" || strings.ContainsAny(from+to, "\r\n") {
		return errors.New("请配置SMTP地址、发件人和收件人")
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	connection, e := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", address)
	if e != nil {
		return errors.New("SMTP连接失败")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if port == 465 {
		connection = tls.Client(connection, cfg)
	}
	client, e := smtp.NewClient(connection, host)
	if e != nil {
		return errors.New("SMTP握手失败")
	}
	defer client.Close()
	if port != 465 {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP服务必须支持TLS")
		}
		if e = client.StartTLS(cfg); e != nil {
			return errors.New("SMTP TLS连接失败")
		}
	}
	if user := text(settings, "smtpUsername"); user != "" {
		if e = client.Auth(smtp.PlainAuth("", user, text(settings, "smtpPassword"), host)); e != nil {
			return errors.New("SMTP认证失败")
		}
	}
	if e = client.Mail(from); e != nil {
		return e
	}
	for _, recipient := range strings.Split(to, ",") {
		if e = client.Rcpt(strings.TrimSpace(recipient)); e != nil {
			return e
		}
	}
	writer, e := client.Data()
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(writer, "From: %s\r\nTo: %s\r\nSubject: ASWired notification\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", from, to, message)
	if e != nil {
		return e
	}
	if e = writer.Close(); e != nil {
		return e
	}
	return client.Quit()
}

func komariBaseURL(settings map[string]any) string {
	return strings.TrimRight(strings.TrimSpace(text(settings, "probeBaseUrl")), "/")
}

func (a *App) syncKomari(ctx context.Context, persist bool) (map[string]any, error) {
	a.komariMu.Lock()
	defer a.komariMu.Unlock()
	var settings map[string]any
	if e := a.DB.GetSetting(ctx, "settings", &settings); e != nil {
		return nil, e
	}
	base := komariBaseURL(settings)
	if base == "" {
		return nil, errors.New("请先配置Komari地址")
	}
	var version struct {
		Status string `json:"status"`
		Data   struct {
			Version string `json:"version"`
		} `json:"data"`
	}
	if e := a.externalJSON(ctx, "GET", base+"/api/version", nil, nil, &version); e != nil {
		return nil, e
	}
	if version.Status != "success" || !compatibleKomariVersion(version.Data.Version) {
		return nil, errors.New("Komari版本不匹配，仅接受1.2.5-fix2")
	}
	rpc := func(method string) (map[string]map[string]any, error) {
		var result map[string]map[string]any
		err := a.komariRPC(ctx, settings, method, map[string]any{}, &result)
		return result, err
	}
	nodes, e := rpc("common:getNodes")
	if e != nil {
		return nil, e
	}
	statuses, e := rpc("common:getNodesLatestStatus")
	if e != nil {
		return nil, e
	}
	candidates := []any{}
	for uuid, node := range nodes {
		candidates = append(candidates, map[string]any{"uuid": uuid, "name": node["name"]})
	}
	saved := 0
	if persist {
		servers, e := a.DB.ListRecords(ctx, "servers", "")
		if e != nil {
			return nil, e
		}
		bound := map[string]bool{}
		for _, server := range servers {
			uuid := text(server.Data, "komariUUID")
			if uuid == "" {
				continue
			}
			if bound[uuid] {
				return nil, errors.New("Komari UUID不能重复绑定服务器")
			}
			bound[uuid] = true
			sample, ok := statuses[uuid]
			_, nodeExists := nodes[uuid]
			if !ok || !nodeExists {
				old, _ := a.DB.GetRecord(ctx, "_komariObservations", server.ID)
				if old.Data != nil {
					old.Data["online"] = false
					if _, e := a.DB.SaveRecord(ctx, old); e != nil {
						return nil, e
					}
				}
				continue
			}
			sampled, e := time.Parse(time.RFC3339Nano, text(sample, "time"))
			if e != nil {
				continue
			}
			if sampled.After(time.Now().Add(time.Minute)) {
				continue
			}
			obs := map[string]any{"source": "Komari 1.2.5-fix2", "komari_uuid": uuid, "komari_base_url": base, "sampled_at": sampled.Format(time.RFC3339Nano), "online": sample["online"]}
			if region := strings.TrimSpace(text(nodes[uuid], "region")); region != "" {
				obs["region"] = region
			}
			for from, to := range map[string]string{"os": "os", "kernel_version": "kernel", "arch": "arch", "cpu_name": "cpu_name", "cpu_cores": "cpu_cores", "virtualization": "virtualization_system"} {
				if v, ok := nodes[uuid][from]; ok {
					obs[to] = v
				}
			}
			for from, to := range komariMetricNames {
				if v, ok := sample[from]; ok {
					obs[to] = v
				}
			}
			old, _ := a.DB.GetRecord(ctx, "_komariObservations", server.ID)
			previous := dateTime(text(old.Data, "sampled_at"))
			sameBinding := text(old.Data, "komari_uuid") == uuid && text(old.Data, "komari_base_url") == base
			if sameBinding && !sampled.After(previous) {
				// Online status can change without a new metrics timestamp.
				if boolean(old.Data, "online") != boolean(sample, "online") {
					old.Data["online"] = sample["online"]
					if _, e := a.DB.SaveRecord(ctx, old); e != nil {
						return nil, e
					}
				}
				continue
			}
			fresh, e := a.DB.GetRecord(ctx, "servers", server.ID)
			if e != nil || text(fresh.Data, "komariUUID") != uuid {
				continue
			}
			if _, e = a.DB.SaveRecord(ctx, store.Record{Collection: "_komariObservations", ID: server.ID, Data: obs, Version: old.Version}); e != nil {
				return nil, e
			}
			saved++
		}
	}
	return map[string]any{"success": true, "version": version.Data.Version, "candidates": candidates, "saved": saved, "readOnly": true, "message": fmt.Sprintf("Komari 连接正常，发现 %d 台服务器，同步 %d 台", len(candidates), saved)}, nil
}
