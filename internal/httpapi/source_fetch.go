package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"io"
	"net/http"
	"time"
)

func (a *App) fetchSource(ctx context.Context, source store.Record) ([]byte, string, string, error) {
	fallback := ""
	if endpoint := text(source.Data, "fetchEndpointId"); endpoint != "" {
		raw, info, e := a.fetchSourceThroughHome(ctx, source, endpoint)
		if e == nil {
			return raw, info, "home:" + endpoint, nil
		}
		if text(source.Data, "fetchFallback") != "direct" {
			return nil, "", "", e
		}
		fallback = "direct-fallback:" + endpoint
	}
	cacheKey := hashOpaque(text(source.Data, "url") + fmt.Sprint(source.Data["fetchHeaders"]))
	cache, _ := a.DB.GetRecord(ctx, "_sourceFetchCache", source.ID)
	sameCache := text(cache.Data, "key") == cacheKey
	req, e := http.NewRequestWithContext(ctx, "GET", text(source.Data, "url"), nil)
	if e != nil {
		return nil, "", "", errors.New("订阅地址无效")
	}
	req.Header.Set("User-Agent", "ASWired/"+Version)
	headers, _ := source.Data["fetchHeaders"].(map[string]any)
	for _, key := range []string{"Authorization", "User-Agent", "Accept"} {
		if value := text(headers, key); value != "" {
			req.Header.Set(key, value)
		}
	}
	if sameCache {
		if tag := text(cache.Data, "etag"); tag != "" {
			req.Header.Set("If-None-Match", tag)
		}
		if modified := text(cache.Data, "lastModified"); modified != "" {
			req.Header.Set("If-Modified-Since", modified)
		}
	}
	client := *a.client
	if source.OwnerID != "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = publicDial
		client.Transport = transport
		defer transport.CloseIdleConnections()
	}
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many redirects")
		}
		if next.URL.Scheme != "https" && next.URL.Scheme != "http" || next.URL.User != nil {
			return errors.New("invalid redirect")
		}
		if next.URL.Scheme != via[0].URL.Scheme || next.URL.Host != via[0].URL.Host {
			return errors.New("cross-origin source redirect rejected")
		}
		return nil
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, "", "", errors.New("订阅源连接失败")
	}
	defer res.Body.Close()
	if res.StatusCode == 304 && sameCache {
		raw, e := base64.StdEncoding.DecodeString(text(cache.Data, "body"))
		if e == nil && len(raw) <= 8<<20 {
			return raw, text(cache.Data, "userInfo"), "controller-cache", nil
		}
		return nil, "", "", errors.New("订阅缓存校验失败，请重试")
	}
	if res.StatusCode != 200 {
		return nil, "", "", fmt.Errorf("订阅源返回HTTP %d", res.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 8<<20+1))
	if e != nil || len(raw) > 8<<20 {
		return nil, "", "", errors.New("订阅读取失败或超过8MiB限制")
	}
	if res.Header.Get("ETag") != "" || res.Header.Get("Last-Modified") != "" {
		_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_sourceFetchCache", ID: source.ID, OwnerID: source.OwnerID, Version: cache.Version, Data: map[string]any{"key": cacheKey, "etag": res.Header.Get("ETag"), "lastModified": res.Header.Get("Last-Modified"), "body": base64.StdEncoding.EncodeToString(raw), "userInfo": res.Header.Get("Subscription-Userinfo")}})
	}
	if fallback == "" {
		fallback = "controller"
	}
	return raw, res.Header.Get("Subscription-Userinfo"), fallback, nil
}
func (a *App) fetchSourceThroughHome(ctx context.Context, source store.Record, id string) ([]byte, string, error) {
	endpoint, e := a.DB.GetRecord(ctx, "endpoints", id)
	if e != nil || disabledStatus(endpoint.Data) {
		return nil, "", errors.New("指定家用抓取端不可用")
	}
	a.mu.Lock()
	peer := a.peers[id]
	online := peer != nil && time.Since(peer.LastSeen) < 45*time.Second
	a.mu.Unlock()
	if !online {
		return nil, "", errors.New("指定家用抓取端离线")
	}
	cmd := agentwire.Command{ID: newID(), Action: "source.fetch", Params: map[string]any{"url": text(source.Data, "url"), "headers": source.Data["fetchHeaders"]}}
	raw, _ := json.Marshal(cmd)
	task, e := a.DB.SaveTask(ctx, store.Task{ID: cmd.ID, ServerID: id, Kind: cmd.Action, ActorID: "source-sync", Status: "queued", Input: raw, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()})
	if e != nil {
		return nil, "", e
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			latest, err := a.DB.GetTask(context.Background(), task.ID)
			if err == nil && latest.Status == "queued" {
				latest.Status = "failed"
				latest.Error = "源抓取等待超时"
				latest.UpdatedAt = time.Now().UTC()
				_, _ = a.DB.SaveTask(context.Background(), latest)
			}
			return nil, "", errors.New("家用端抓取超时")
		case <-ticker.C:
			result, e := a.DB.GetTask(ctx, task.ID)
			if e != nil {
				return nil, "", e
			}
			switch result.Status {
			case "failed", "unsupported", "unknown":
				return nil, "", errors.New("家用端未完成抓取：" + result.Status)
			case "success":
				var payload map[string]any
				if json.Unmarshal(result.Result, &payload) != nil {
					return nil, "", errors.New("家用端返回无效结果")
				}
				if number(payload, "status") != 200 {
					return nil, "", fmt.Errorf("家用端抓取返回HTTP %.0f", number(payload, "status"))
				}
				raw, e := base64.StdEncoding.DecodeString(text(payload, "body_base64"))
				if e != nil || len(raw) > 8<<20 {
					return nil, "", errors.New("家用端订阅超过限制或编码无效")
				}
				headers, _ := payload["headers"].(map[string]any)
				return raw, text(headers, "subscription-userinfo"), nil
			}
		}
	}
}
