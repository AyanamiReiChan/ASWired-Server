package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

const realityScanCollection = "_realityScans"
const realityScanLimit = 128
const realityScanTTL = 15 * time.Minute

var realityScanDefaults = []string{"www.microsoft.com", "www.apple.com", "www.cloudflare.com", "www.amazon.com", "www.mozilla.org"}

type realityScanTransport struct {
	dial  func(context.Context, string, string) (net.Conn, error)
	roots *x509.CertPool
}

type realityScanTarget struct {
	address string
	host    string
	port    int
	isIP    bool
}

type realityScanResult struct {
	Source             string   `json:"source,omitempty"`
	ServerID           string   `json:"serverId,omitempty"`
	ServerName         string   `json:"serverName,omitempty"`
	ID                 string   `json:"id"`
	Target             string   `json:"target"`
	Host               string   `json:"host"`
	IP                 string   `json:"ip"`
	Port               int      `json:"port"`
	Feasible           bool     `json:"feasible"`
	TLS13              bool     `json:"tls13"`
	H2                 bool     `json:"h2"`
	X25519             bool     `json:"x25519"`
	CertValid          bool     `json:"certValid"`
	CertChainValid     bool     `json:"certChainValid"`
	CertChainBytes     int      `json:"certChainBytes"`
	ServerNames        []string `json:"serverNames"`
	ALPN               string   `json:"alpn"`
	TLSVersion         string   `json:"tlsVersion"`
	CurveID            uint16   `json:"curveID"`
	LatencyMS          float64  `json:"latencyMs"`
	TCPMS              float64  `json:"tcpMs"`
	HandshakeMS        float64  `json:"handshakeMs"`
	CertificateExpires string   `json:"certificateExpires"`
	CertSubject        string   `json:"certSubject"`
	CertIssuer         string   `json:"certIssuer"`
	Reason             string   `json:"reason"`
	CheckedAt          string   `json:"checkedAt"`
}

func parseRealityScanTarget(raw string) (realityScanTarget, error) {
	host, port := raw, 443
	if ip, e := netip.ParseAddr(raw); e == nil {
		if ip.Zone() != "" {
			return realityScanTarget{}, errors.New("不支持带区域标识的IP地址")
		}
		host = ip.Unmap().String()
	} else if strings.ContainsAny(raw, ":[]") {
		var portText string
		var err error
		host, portText, err = net.SplitHostPort(raw)
		if err != nil {
			return realityScanTarget{}, errors.New("端口格式无效，IPv6带端口时须使用[地址]:端口")
		}
		port, err = strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || portText != strconv.Itoa(port) {
			return realityScanTarget{}, errors.New("端口须为1到65535的整数")
		}
	}
	isIP := false
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return realityScanTarget{}, errors.New("不支持带区域标识的IP地址")
		}
		host, isIP = ip.Unmap().String(), true
	} else {
		var err error
		host, err = realityDomain(host)
		if err != nil {
			return realityScanTarget{}, err
		}
	}
	return realityScanTarget{address: net.JoinHostPort(host, strconv.Itoa(port)), host: host, port: port, isIP: isIP}, nil
}

func parseRealityScanTargets(raw string) ([]realityScanTarget, error) {
	if len(raw) > 64<<10 {
		return nil, errors.New("扫描输入过长")
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(parts) == 0 {
		parts = realityScanDefaults
	}
	if len(parts) > realityScanLimit {
		return nil, errors.New("每次最多扫描128个目标")
	}
	targets := []realityScanTarget{}
	seen := map[string]bool{}
	expanded := 0
	appendTarget := func(raw string) error {
		expanded++
		if expanded > realityScanLimit {
			return errors.New("展开后超过128个目标，请缩小扫描范围")
		}
		target, err := parseRealityScanTarget(raw)
		if err != nil {
			return err
		}
		if !seen[target.address] {
			seen[target.address] = true
			targets = append(targets, target)
		}
		return nil
	}
	for _, part := range parts {
		if strings.Contains(part, "/") {
			prefix, err := netip.ParsePrefix(part)
			if err != nil || prefix.Addr().Is4In6() {
				return nil, errors.New("CIDR格式无效")
			}
			if prefix.Addr().BitLen()-prefix.Bits() > 7 {
				return nil, errors.New("每个CIDR最多包含128个地址，请使用更小的网段")
			}
			prefix = prefix.Masked()
			for addr := prefix.Addr(); addr.IsValid() && prefix.Contains(addr); addr = addr.Next() {
				if err := appendTarget(addr.String()); err != nil {
					return nil, err
				}
			}
		} else if err := appendTarget(part); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func realityCertificateNames(cert *x509.Certificate) []string {
	names := []string{}
	seen := map[string]bool{}
	for _, raw := range cert.DNSNames {
		name, err := realityDomain(raw)
		if err == nil && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func probeRealityConnection(ctx context.Context, target realityScanTarget, serverName string, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) realityScanResult {
	result := realityScanResult{Target: target.address, Host: serverName, Port: target.port, ServerNames: []string{}, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	started := time.Now()
	conn, err := dial(ctx, "tcp", target.address)
	if err != nil {
		result.Reason = err.Error()
		result.LatencyMS = float64(time.Since(started).Microseconds()) / 1000
		return result
	}
	defer conn.Close()
	tcpDone := time.Now()
	result.IP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	result.TCPMS = float64(tcpDone.Sub(started).Microseconds()) / 1000
	secure := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
	err = secure.HandshakeContext(ctx)
	result.HandshakeMS = float64(time.Since(tcpDone).Microseconds()) / 1000
	result.LatencyMS = float64(time.Since(started).Microseconds()) / 1000
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	state := secure.ConnectionState()
	result.TLSVersion = tls.VersionName(state.Version)
	result.TLS13 = state.Version == tls.VersionTLS13
	result.ALPN = state.NegotiatedProtocol
	result.H2 = state.NegotiatedProtocol == "h2"
	result.CurveID = uint16(state.CurveID)
	result.X25519 = state.CurveID == tls.X25519
	reasons := []string{}
	if !result.TLS13 {
		reasons = append(reasons, "未协商TLS 1.3")
	}
	if !result.H2 {
		reasons = append(reasons, "未协商h2")
	}
	if !result.X25519 {
		reasons = append(reasons, "未协商X25519")
	}
	if len(state.PeerCertificates) == 0 {
		reasons = append(reasons, "目标未返回证书")
	} else {
		leaf := state.PeerCertificates[0]
		result.CertificateExpires = leaf.NotAfter.UTC().Format(time.RFC3339Nano)
		result.CertSubject, result.CertIssuer = leaf.Subject.String(), leaf.Issuer.String()
		result.ServerNames = realityCertificateNames(leaf)
		intermediates := x509.NewCertPool()
		for i, cert := range state.PeerCertificates {
			result.CertChainBytes += len(cert.Raw)
			if i > 0 {
				intermediates.AddCert(cert)
			}
		}
		_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		result.CertChainValid = verifyErr == nil
		if verifyErr != nil {
			reasons = append(reasons, "证书信任链无效: "+verifyErr.Error())
		}
		if serverName != "" {
			hostErr := leaf.VerifyHostname(serverName)
			result.CertValid = result.CertChainValid && hostErr == nil
			if hostErr != nil {
				reasons = append(reasons, "证书域名不匹配: "+hostErr.Error())
			}
		} else {
			reasons = append(reasons, "IP目标需要确认可用SNI域名")
		}
	}
	result.Feasible = result.TLS13 && result.H2 && result.X25519 && result.CertValid
	result.Reason = strings.Join(reasons, "；")
	return result
}

func scanRealityTarget(ctx context.Context, target realityScanTarget, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) realityScanResult {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	serverName := target.host
	if target.isIP {
		serverName = ""
	}
	result := probeRealityConnection(ctx, target, serverName, dial, roots)
	if target.isIP {
		for _, name := range result.ServerNames {
			if ctx.Err() != nil {
				break
			}
			confirmed := probeRealityConnection(ctx, target, name, dial, roots)
			if confirmed.Feasible {
				result = confirmed
				break
			}
		}
		if !result.Feasible {
			result.Host = ""
			result.Reason = "未在原IP确认可用SNI域名；" + result.Reason
		}
	}
	result.ID = newID()
	return result
}

func (a *App) realityTransport() (func(context.Context, string, string) (net.Conn, error), *x509.CertPool) {
	if a.realityScanner != nil && a.realityScanner.dial != nil {
		return a.realityScanner.dial, a.realityScanner.roots
	}
	return publicDial, nil
}

func decodeRealityScan(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "invalid_json", "扫描请求格式不正确或包含未知字段")
		return false
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		fail(w, 400, "invalid_json", "请求只能包含一个JSON对象")
		return false
	}
	return true
}

func (a *App) realityPoolScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Targets  string `json:"targets"`
		ServerID string `json:"serverId"`
	}
	if !decodeRealityScan(w, r, &in) {
		return
	}
	targets, err := parseRealityScanTargets(in.Targets)
	if err != nil {
		fail(w, 400, "invalid_targets", err.Error())
		return
	}
	timeout := 65 * time.Second
	if in.ServerID != "" {
		timeout = 85 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	a.mu.Lock()
	if a.closing || a.realityScanRunning {
		a.mu.Unlock()
		fail(w, 409, "scan_busy", "已有扫描任务正在执行或主控正在停止，请稍后再试")
		return
	}
	a.realityScanRunning, a.realityScanCancel = true, cancel
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.realityScanRunning, a.realityScanCancel = false, nil
		a.mu.Unlock()
	}()
	previous, err := a.DB.ListRecords(ctx, realityScanCollection, "")
	if err != nil {
		fail(w, 503, "storage_error", "读取扫描记录失败")
		return
	}
	active := 0
	for _, rec := range previous {
		if time.Now().Before(dateTime(text(rec.Data, "expiresAt"))) {
			active++
		} else if err := a.DB.DeleteRecord(ctx, realityScanCollection, rec.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			fail(w, 503, "storage_error", "清理已过期扫描记录失败")
			return
		}
	}
	if active >= 64 {
		fail(w, 429, "scan_history_full", "短时间内扫描次数过多，请等待旧结果过期")
		return
	}
	expiresAt := time.Now().Add(realityScanTTL).UTC().Format(time.RFC3339Nano)
	results := make([]realityScanResult, len(targets))
	source := "controller"
	if in.ServerID != "" {
		source = "agent"
		results, err = a.scanRealityAgent(ctx, current(r), in.ServerID, targets)
		if err != nil {
			fail(w, 400, "agent_scan_failed", err.Error())
			return
		}
	} else {
		dial, roots := a.realityTransport()
		jobs := make(chan int, len(targets))
		for i := range targets {
			jobs <- i
		}
		close(jobs)
		var workers sync.WaitGroup
		for range min(16, len(targets)) {
			workers.Go(func() {
				for i := range jobs {
					results[i] = scanRealityTarget(ctx, targets[i], dial, roots)
				}
			})
		}
		workers.Wait()
	}
	if ctx.Err() != nil {
		fail(w, 408, "scan_cancelled", "扫描已取消或超过时限，结果未保存")
		return
	}
	feasible := 0
	for _, result := range results {
		if result.Feasible {
			feasible++
		}
	}
	id := newID()
	data := map[string]any{"scanId": id, "expiresAt": expiresAt, "source": source, "serverId": in.ServerID, "results": results, "total": len(results), "feasibleCount": feasible}
	if source == "agent" && len(results) > 0 {
		data["serverName"] = results[0].ServerName
	}
	if _, err = a.DB.SaveRecord(ctx, store.Record{Collection: realityScanCollection, ID: id, OwnerID: current(r).ID, Data: data}); err != nil {
		fail(w, 503, "storage_error", "扫描完成但结果保存失败，请重试")
		return
	}
	a.audit(ctx, current(r), "reality.target.scan", id, map[string]any{"total": len(results), "feasible": feasible})
	respond(w, 200, data)
}

func realityProbeEvidence(result realityScanResult) map[string]any {
	raw, _ := json.Marshal(result)
	var evidence map[string]any
	_ = json.Unmarshal(raw, &evidence)
	evidence["success"] = result.Feasible
	evidence["domain"] = result.Host
	evidence["source"] = "controller"
	if result.Source == "agent" {
		evidence["source"] = "agent"
		evidence["serverId"] = result.ServerID
		evidence["serverName"] = result.ServerName
	}
	if !result.Feasible {
		evidence["error"] = result.Reason
	}
	return evidence
}

func realityRecordTarget(rec store.Record) (realityScanTarget, error) {
	if target := text(rec.Data, "target"); target != "" {
		return parseRealityScanTarget(target)
	}
	port := int(number(rec.Data, "port"))
	if port == 0 {
		port = 443
	}
	return parseRealityScanTarget(net.JoinHostPort(text(rec.Data, "domain"), strconv.Itoa(port)))
}

func realityTargetKey(target, domain string) string { return target + "\x00" + domain }

func (a *App) realityPoolScanImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ScanID    string   `json:"scanId"`
		ResultIDs []string `json:"resultIds"`
	}
	if !decodeRealityScan(w, r, &in) {
		return
	}
	if in.ScanID == "" || len(in.ScanID) > 100 || len(in.ResultIDs) == 0 || len(in.ResultIDs) > realityScanLimit {
		fail(w, 400, "invalid_selection", "请选择本次扫描的1到128个有效结果")
		return
	}
	for attempt := 0; attempt < 12; attempt++ {
		scan, err := a.DB.GetRecord(r.Context(), realityScanCollection, in.ScanID)
		if err != nil {
			fail(w, 404, "scan_not_found", "扫描结果不存在或已清理，请重新扫描")
			return
		}
		if scan.OwnerID != current(r).ID {
			fail(w, 403, "scan_owner_denied", "只能导入本人发起的扫描结果")
			return
		}
		now := time.Now()
		if !now.Before(dateTime(text(scan.Data, "expiresAt"))) {
			fail(w, 410, "scan_expired", "扫描结果已过期，请重新扫描")
			return
		}
		var results []realityScanResult
		raw, err := json.Marshal(scan.Data["results"])
		if err != nil || json.Unmarshal(raw, &results) != nil {
			fail(w, 503, "invalid_evidence", "扫描证据无法读取")
			return
		}
		byID := map[string]realityScanResult{}
		for _, result := range results {
			byID[result.ID] = result
		}
		selected := []realityScanResult{}
		for _, id := range in.ResultIDs {
			result, found := byID[id]
			target, targetErr := parseRealityScanTarget(result.Target)
			domain, domainErr := realityDomain(result.Host)
			age := now.Sub(dateTime(result.CheckedAt))
			if !found || targetErr != nil || domainErr != nil || domain != result.Host || target.port != result.Port || !result.Feasible || !result.TLS13 || !result.H2 || !result.X25519 || result.CurveID != uint16(tls.X25519) || !result.CertValid || !result.CertChainValid || result.CertChainBytes < 1 || result.Reason != "" || age < 0 || age > realityScanTTL || !now.Before(dateTime(result.CertificateExpires)) {
				fail(w, 400, "invalid_scan_result", "所选结果不存在、不可用或探测证据已过期")
				return
			}
			selected = append(selected, result)
		}
		settings, err := a.DB.GetRecord(r.Context(), "_realityTargetSettings", "allowlist")
		if errors.Is(err, store.ErrNotFound) {
			settings = store.Record{Collection: "_realityTargetSettings", ID: "allowlist", Data: map[string]any{"domains": []string{}}}
		} else if err != nil {
			fail(w, 503, "storage_error", "读取允许列表失败")
			return
		}
		domains := stringList(settings.Data["domains"])
		allowed := map[string]bool{}
		for _, domain := range domains {
			allowed[domain] = true
		}
		existing, err := a.DB.ListRecords(r.Context(), realityPoolCollection, "")
		if err != nil {
			fail(w, 503, "storage_error", "读取目标池失败")
			return
		}
		seen := map[string]bool{}
		for _, rec := range existing {
			if target, err := realityRecordTarget(rec); err == nil {
				seen[realityTargetKey(target.address, text(rec.Data, "domain"))] = true
			}
		}
		newRecords := []store.Record{}
		newlyAllowed := map[string]bool{}
		for _, result := range selected {
			key := realityTargetKey(result.Target, result.Host)
			if seen[key] {
				continue
			}
			seen[key] = true
			if !allowed[result.Host] {
				allowed[result.Host] = true
				newlyAllowed[result.Host] = true
				domains = append(domains, result.Host)
			}
			digest := sha256.Sum256([]byte(key))
			newRecords = append(newRecords, store.Record{Collection: realityPoolCollection, ID: "scan-" + hex.EncodeToString(digest[:16]), OwnerID: current(r).ID, Data: map[string]any{"name": result.Host, "domain": result.Host, "target": result.Target, "port": result.Port, "status": "pending", "enabled": false, "contributorId": current(r).ID, "scanId": in.ScanID, "lastProbe": realityProbeEvidence(result)}})
		}
		if len(domains) > 200 {
			fail(w, 400, "allowlist_full", "导入后允许域名将超过200个，请先整理允许列表")
			return
		}
		settings.Data["domains"] = domains
		batch := append([]store.Record{settings, scan}, newRecords...)
		for _, rec := range existing {
			if newlyAllowed[text(rec.Data, "domain")] && boolean(rec.Data, "enabled") {
				rec.Data["enabled"] = false
				batch = append(batch, rec)
			}
		}
		saved, err := a.DB.CompareAndSaveRecords(r.Context(), batch)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			fail(w, 503, "storage_error", "导入未完成，允许列表和目标池均未改变")
			return
		}
		rows := []any{}
		for _, rec := range saved[2 : 2+len(newRecords)] {
			rows = append(rows, realityPoolRow(rec, allowed))
		}
		a.audit(r.Context(), current(r), "reality.target.scan.import", in.ScanID, map[string]any{"imported": len(rows), "skipped": len(in.ResultIDs) - len(rows)})
		respond(w, 200, map[string]any{"rows": rows, "imported": len(rows), "skipped": len(in.ResultIDs) - len(rows)})
		return
	}
	fail(w, 409, "conflict", "允许列表或目标池正在更新，请重试")
}

func probeRealityStored(ctx context.Context, target realityScanTarget, domain string, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) (map[string]any, error) {
	domain, err := realityDomain(domain)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	result := probeRealityConnection(ctx, target, domain, dial, roots)
	evidence := realityProbeEvidence(result)
	if !result.Feasible {
		return evidence, fmt.Errorf("目标未通过REALITY可用性检查: %s", result.Reason)
	}
	return evidence, nil
}
