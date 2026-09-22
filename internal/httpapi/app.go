package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/logfiles"
	"github.com/AyanamiReiChan/ASWired-Server/internal/releases"
	"github.com/AyanamiReiChan/ASWired-Server/internal/selfupdate"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"github.com/coder/websocket"
)

var Version = "0.2.0-dev"

type App struct {
	resolveRelease              func(context.Context, bool) (releases.Info, error)
	updateClient                *selfupdate.Client
	restart                     chan struct{}
	LogFiles                    *logfiles.Manager
	LogStreams                  map[string]*logfiles.Manager
	DB                          *store.Store
	Config                      config.Config
	Signer                      *auth.Signer
	MasterPrivate, MasterPublic string
	stateMu                     sync.RWMutex
	managedNodeMu               sync.Mutex
	agentUpdateMu               sync.Mutex
	agentDispatchMu             sync.Mutex
	xrayCacheMu                 sync.Mutex
	browserMu                   sync.Mutex
	browserSnapshots            map[string]browserSnapshot
	komariMu                    sync.Mutex
	identity                    *identityState
	jobs                        map[string]bool
	background                  sync.WaitGroup
	socketHandlers              sync.WaitGroup
	sockets                     map[*websocket.Conn]bool
	closing                     bool
	recoveryRequired            bool
	mu                          sync.Mutex
	peers                       map[string]*peer
	handshakes                  map[string]time.Time
	limits                      map[string]*rateWindow
	client                      *http.Client
	cancel                      context.CancelFunc
	geoCacheMu                  sync.Mutex
	geoCache                    map[string]geoCacheEntry
	realityScanRunning          bool
	realityScanCancel           context.CancelFunc
	realityScanner              *realityScanTransport
}
type rateWindow struct {
	Start time.Time
	Count int
}
type peer struct {
	SplitHeartbeat bool
	ConnectionMode string
	LastSeen       time.Time
	Transport      string
	Version        string
	Mode           string
	Capabilities   map[string]bool
}
type userKey struct{}
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func New(cfg config.Config, db *store.Store) (*App, error) {
	signer, e := auth.NewSigner(cfg.JWTSecret, cfg.JWTTTL)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(cfg.DataDir, 0700); e != nil {
		return nil, e
	}
	if e := recoverRestore(cfg.DataDir, db); e != nil {
		return nil, e
	}
	path := filepath.Join(cfg.DataDir, "master-identity.key")
	secret, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		private, _, err := agentwire.GenerateKey()
		if err != nil {
			return nil, err
		}
		f, err := os.CreateTemp(cfg.DataDir, ".identity-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		if err = f.Chmod(0600); err == nil {
			_, err = f.WriteString(private)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err = os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		secret, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	} else if e != nil {
		return nil, e
	}
	pub, e := agentwire.PublicKey(strings.TrimSpace(string(secret)))
	if e != nil {
		return nil, fmt.Errorf("master identity: %w", e)
	}
	dataKey, e := config.LoadOrCreateSecret(filepath.Join(cfg.DataDir, "data-encryption.key"))
	if e != nil {
		return nil, e
	}
	if e = db.SetEncryptionKey(dataKey); e != nil {
		return nil, e
	}
	a := &App{DB: db, Config: cfg, Signer: signer, MasterPrivate: strings.TrimSpace(string(secret)), MasterPublic: pub, peers: map[string]*peer{}, handshakes: map[string]time.Time{}, limits: map[string]*rateWindow{}, client: &http.Client{Timeout: 30 * time.Second}, geoCache: map[string]geoCacheEntry{}}
	a.restart = make(chan struct{}, 1)
	if _, e = config.LoadOrCreateSecret(filepath.Join(cfg.DataDir, "setup-token")); e != nil {
		return nil, e
	}
	return a, nil
}
func (a *App) Start(ctx context.Context) {
	ctx, a.cancel = context.WithCancel(ctx)
	a.background.Add(2)
	go func() { defer a.background.Done(); a.maintenance(ctx) }()
	go func() { defer a.background.Done(); a.logMaintenance(ctx) }()
}
func (a *App) Close() {
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Lock()
	a.closing = true
	scanCancel := a.realityScanCancel
	sockets := make([]*websocket.Conn, 0, len(a.sockets))
	for socket := range a.sockets {
		sockets = append(sockets, socket)
	}
	a.mu.Unlock()
	if scanCancel != nil {
		scanCancel()
	}
	for _, socket := range sockets {
		_ = socket.CloseNow()
	}
	a.background.Wait()
	a.socketHandlers.Wait()
}
func (a *App) trackSocket(socket *websocket.Conn) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		return false
	}
	if a.sockets == nil {
		a.sockets = map[*websocket.Conn]bool{}
	}
	a.sockets[socket] = true
	a.socketHandlers.Add(1)
	return true
}
func (a *App) forgetSocket(socket *websocket.Conn) {
	a.mu.Lock()
	delete(a.sockets, socket)
	a.mu.Unlock()
	a.socketHandlers.Done()
}
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/internal/komari/redeem", a.komariBridge(a.komariRedeem))
	mux.HandleFunc("POST /api/internal/komari/introspect", a.komariBridge(a.komariIntrospect))
	mux.HandleFunc("POST /api/komari/login", a.withAdmin(a.komariLogin))
	mux.HandleFunc("GET /api/logs/files", a.withAdmin(a.listLogFiles))
	mux.HandleFunc("GET /api/logs/entries", a.withAdmin(a.readFileLogs))
	mux.HandleFunc("POST /api/servers/{id}/logs", a.withAdmin(a.agentFileLogs))
	mux.HandleFunc("GET /api/security", a.withAdmin(a.securityState))
	mux.HandleFunc("POST /api/security/bans", a.withAdmin(a.securityBan))
	mux.HandleFunc("DELETE /api/security/bans/{id}", a.withAdmin(a.securityUnban))
	mux.HandleFunc("PUT /api/security/allowlist", a.withAdmin(a.securityAllowlist))
	mux.HandleFunc("POST /api/logs/files/remove", a.withAdmin(a.removeLogFiles))
	a.registerIdentity(mux)
	a.registerFederation(mux)
	a.registerOperations(mux)
	a.registerMembership(mux)
	a.registerMemberManagement(mux)
	a.registerTelegram(mux)
	a.registerEntryGuard(mux)
	a.registerLimitRules(mux)
	a.registerQRIdentity(mux)
	a.registerTemporarySubscriptions(mux)
	a.registerSubscriptionGenerator(mux)
	a.registerNodeWorkbench(mux)
	a.registerMerchantBilling(mux)
	a.registerIPDatabase(mux)
	a.registerRealityPool(mux)
	a.registerInvitations(mux)
	a.registerHomeIdentity(mux)
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("POST /api/setup", a.setup)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("GET /api/me", a.withUser(a.me))
	mux.HandleFunc("POST /api/logout", a.withUser(a.logout))
	mux.HandleFunc("POST /api/account/password", a.withUser(a.password))
	mux.HandleFunc("GET /api/state", a.withUser(a.state))
	mux.HandleFunc("GET /api/state/sync", a.withUser(a.browserState))
	mux.HandleFunc("GET /api/operations/tasks", a.withAdmin(a.browserTasks))
	mux.HandleFunc("GET /api/capabilities", a.withUser(a.capabilities))
	mux.HandleFunc("GET /api/templates/options", a.withUser(a.templateOptions))
	mux.HandleFunc("GET /api/federation/identity", a.withAdmin(func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]string{"masterPublicKey": a.MasterPublic})
	}))
	mux.HandleFunc("GET /api/settings", a.withAdmin(a.settingsGet))
	mux.HandleFunc("GET /api/system/update", a.withAdmin(a.releaseUpdateStatus))
	mux.HandleFunc("PUT /api/settings", a.withAdmin(a.settingsPut))
	mux.HandleFunc("GET /api/database/status", a.withAdmin(a.databaseStatus))
	mux.HandleFunc("POST /api/database/test", a.withAdmin(a.databaseTest))
	mux.HandleFunc("POST /api/database/migrate", a.withAdmin(a.databaseMigrate))
	mux.HandleFunc("DELETE /api/database/migrate", a.withAdmin(a.databaseCancel))
	mux.HandleFunc("GET /api/collections/{collection}", a.withUser(a.list))
	mux.HandleFunc("GET /api/collections/{collection}/{id}", a.withUser(a.get))
	mux.HandleFunc("POST /api/collections/{collection}", a.withUser(a.save))
	mux.HandleFunc("PUT /api/collections/{collection}/{id}", a.withUser(a.save))
	mux.HandleFunc("DELETE /api/collections/{collection}/{id}", a.withUser(a.delete))
	mux.HandleFunc("POST /api/logs/{collection}/preview", a.withAdmin(a.previewLogs))
	mux.HandleFunc("POST /api/logs/{collection}/delete", a.withAdmin(a.deleteLogsByDate))
	mux.HandleFunc("POST /api/actions", a.withUser(a.action))
	mux.HandleFunc("GET /api/servers/{id}/enrollment", a.withAdmin(a.enrollment))
	mux.HandleFunc("GET /api/servers/{id}/xray-cache", a.withAdmin(a.xrayCache))
	mux.HandleFunc("GET /api/agent/install/{id}/{file}", a.agentInstallDownload)
	mux.HandleFunc("GET /api/home/{id}/enrollment", a.withAdmin(a.homeEnrollment))
	mux.HandleFunc("GET /api/subscriptions/{id}/config", a.withUser(a.subscriptionConfig))
	mux.HandleFunc("POST /api/subscriptions/{id}/rotate", a.withUser(a.subscriptionRotate))
	mux.HandleFunc("GET /api/clash/subscribe", a.publicSubscription)
	mux.HandleFunc("GET /x/{code}", a.shortSubscription)
	mux.HandleFunc("GET /api/public/probe-servers", a.probeServers)
	mux.HandleFunc("GET /api/public/probe-link", a.probeLink)
	mux.HandleFunc("GET /api/public/appearance", a.publicAppearance)
	mux.HandleFunc("GET /api/public/probe-series", a.probeSeries)
	mux.HandleFunc("GET /api/public/probe-ws", a.probeWS)
	mux.HandleFunc("GET /api/traffic", a.withAdmin(a.traffic))
	mux.HandleFunc("GET /api/agent/ws", a.agentWS)
	mux.HandleFunc("POST /api/agent/pull", a.agentPull)
	mux.HandleFunc("GET /api/backups/{id}", a.withAdmin(a.backupDownload))
	mux.HandleFunc("POST /api/backups/restore", a.withAdmin(a.backupRestore))
	mux.HandleFunc("POST /mcp", a.mcp)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"status": "ok", "version": Version})
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "not_found", "接口不存在") })
	if a.Config.FrontendDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(a.Config.FrontendDir)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fail(w, 404, "not_found", "请使用网站入口访问 ASWired")
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				slog.Error("request panic", "path", r.URL.Path, "error", fmt.Sprint(v))
				fail(w, 500, "internal_error", "请求处理失败")
			}
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if origin := r.Header.Get("Origin"); origin != "" {
			allowed := a.originAllowed(origin)
			if !allowed {
				fail(w, 403, "origin_denied", "该网站来源未获允许")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, MM-Authorization, Authorization, X-MMwx-Probe-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}

		if r.URL.Path == "/api/backups/restore" {
			a.stateMu.Lock()
			defer a.stateMu.Unlock()
		} else if r.URL.Path != "/api/agent/ws" && r.URL.Path != "/api/public/probe-ws" {
			a.stateMu.RLock()
			defer a.stateMu.RUnlock()
		}
		a.mu.Lock()
		unavailable := a.recoveryRequired || a.closing
		a.mu.Unlock()
		if unavailable {
			fail(w, 503, "restart_required", "主控正在关闭或等待恢复，请重启后继续")
			return
		}
		if a.securityBlocked(r) {
			fail(w, 403, "ip_banned", "当前 IP 已被封禁")
			return
		}
		if !a.entryAllowed(r) {
			fail(w, 404, "not_found", "页面不存在")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *App) originAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	for _, configured := range append(append([]string{}, a.Config.AllowedOrigins...), a.Config.PublicURL) {
		candidate, err := url.Parse(strings.TrimRight(configured, "/"))
		if err == nil && candidate.Scheme != "" && candidate.Host != "" && candidate.User == nil && candidate.Path == "" && candidate.RawQuery == "" && candidate.Fragment == "" && strings.ToLower(candidate.Scheme) == scheme && strings.ToLower(candidate.Host) == host {
			return true
		}
	}
	return false
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, map[string]any{"error": apiError{code, message}})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	if e := d.Decode(v); e != nil {
		fail(w, 400, "invalid_json", "请求格式不正确")
		return false
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		fail(w, 400, "invalid_json", "请求只能包含一个有效JSON对象")
		return false
	}
	return true
}
func current(r *http.Request) store.User { return r.Context().Value(userKey{}).(store.User) }
func (a *App) withUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer asw_") {
			u, scopes, e := a.authenticateAPIToken(r)
			if e != nil {
				fail(w, 401, "unauthorized", "API令牌无效")
				return
			}
			if !a.workspaceAccount(r.Context(), u) {
				fail(w, 403, "forbidden", "此账户不能访问 ASWired 工作区")
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api/database/") || strings.HasPrefix(r.URL.Path, "/api/account/") || strings.HasPrefix(r.URL.Path, "/api/auth/") || r.URL.Path == "/api/logout" {
				fail(w, 403, "session_required", "此操作需要网页登录会话")
				return
			}
			if !hasScope(scopes, "read") || (r.Method != "GET" && r.Method != "HEAD" && !hasScope(scopes, "write")) {
				fail(w, 403, "scope_denied", "API令牌权限不足")
				return
			}
			ctx := context.WithValue(r.Context(), userKey{}, u)
			ctx = context.WithValue(ctx, apiScopesKey{}, scopes)
			next(w, r.WithContext(ctx))
			return
		}
		raw := strings.TrimSpace(r.Header.Get("MM-Authorization"))
		raw = strings.TrimPrefix(raw, "Bearer ")
		claims, e := a.Signer.Parse(raw)
		if e != nil {
			fail(w, 401, "unauthorized", "请登录后继续")
			return
		}
		u, e := a.DB.UserByID(r.Context(), claims.Subject)
		if e != nil || u.Disabled || u.TokenVersion != claims.TokenVersion {
			fail(w, 401, "session_expired", "登录已失效，请重新登录")
			return
		}
		if !a.workspaceAccount(r.Context(), u) {
			fail(w, 403, "forbidden", "此账户不能访问 ASWired 工作区")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	}
}
func (a *App) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return a.withUser(func(w http.ResponseWriter, r *http.Request) {
		if current(r).Role != "admin" {
			fail(w, 403, "forbidden", "需要管理员权限")
			return
		}
		next(w, r)
	})
}
func (a *App) allowAttempt(r *http.Request) bool {
	host := requestIP(r)
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.limits {
		if now.Sub(v.Start) > 2*time.Minute {
			delete(a.limits, k)
		}
	}
	v := a.limits[host]
	if v == nil || now.Sub(v.Start) > time.Minute {
		v = &rateWindow{Start: now}
		a.limits[host] = v
	}
	v.Count++
	return v.Count <= 10
}
func (a *App) status(w http.ResponseWriter, r *http.Request) {
	users, e := a.DB.ListUsers(r.Context())
	if e != nil {
		fail(w, 503, "storage_unavailable", "数据库暂不可用")
		return
	}
	respond(w, 200, map[string]any{"initialized": len(users) > 0, "version": Version, "capabilities": capabilityMap()})
}
func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "尝试过于频繁，请稍后再试")
		return
	}
	var in struct{ Username, Password, SetupToken string }
	if !decode(w, r, &in) {
		return
	}
	token := os.Getenv("ASWIRED_SETUP_TOKEN")
	if token == "" {
		raw, e := os.ReadFile(filepath.Join(a.Config.DataDir, "setup-token"))
		if e != nil {
			fail(w, 503, "setup_unavailable", "无法读取初始化令牌")
			return
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" || !constant(token, in.SetupToken) {
		fail(w, 403, "setup_token_required", "请输入主控数据目录 setup-token 文件中的初始化令牌")
		return
	}
	if e := validCredentials(in.Username, in.Password); e != nil {
		fail(w, 400, "invalid_credentials", e.Error())
		return
	}
	hash, e := auth.HashPassword(in.Password)
	if e != nil {
		fail(w, 500, "password_error", "无法保存密码")
		return
	}
	u := store.User{ID: newID(), Username: strings.TrimSpace(in.Username), PasswordHash: hash, Role: "admin", TokenVersion: 1}
	if e = a.DB.InitializeAdmin(r.Context(), u); e != nil {
		if errors.Is(e, store.ErrInitialized) {
			fail(w, 409, "initialized", "主控已初始化")
		} else {
			fail(w, 500, "storage_error", "初始化失败")
		}
		return
	}
	u, e = a.DB.UserByID(r.Context(), u.ID)
	if e != nil {
		fail(w, 500, "storage_error", "无法读取账户")
		return
	}
	a.issue(w, u)
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "尝试过于频繁，请稍后再试")
		return
	}
	var in struct{ Username, Password, Code, TurnstileToken string }
	if !decode(w, r, &in) {
		return
	}
	if e := a.verifyTurnstile(r, in.TurnstileToken, false); e != nil {
		a.securityEvent(r, "login.failed", "人机验证失败")
		fail(w, 400, "invalid_turnstile", e.Error())
		return
	}
	u, e := a.DB.UserByUsername(r.Context(), strings.TrimSpace(in.Username))
	if e != nil || !auth.VerifyPassword(u.PasswordHash, in.Password) || u.Disabled {
		a.securityEvent(r, "login.failed", "用户名或密码不正确")
		fail(w, 401, "invalid_credentials", "用户名或密码不正确")
		return
	}
	if e = a.verifyTOTP(r.Context(), u, in.Code); e != nil {
		code := "invalid_totp"
		if errors.Is(e, ErrTOTPRequired) {
			code = "totp_required"
		}
		if code != "totp_required" {
			a.securityEvent(r, "login.failed", "动态口令验证失败")
		}
		fail(w, 401, code, "请输入有效动态口令或恢复码")
		return
	}
	a.issue(w, u)
}
func (a *App) issue(w http.ResponseWriter, u store.User) {
	application, err := a.accountApplication(context.Background(), u)
	if err != nil {
		fail(w, 503, "storage_error", "无法读取账户类型")
		return
	}
	if application == "komari" {
		fail(w, 403, "forbidden", "Komari 已改为使用 ASWired 管理员账户，请使用管理员账户登录")
		return
	}
	if !a.permittedAdmin(u) {
		fail(w, 403, "forbidden", "此账户未获准进入 ASWired 后台")
		return
	}
	token, e := a.Signer.Issue(u.ID, u.TokenVersion)
	if e != nil {
		fail(w, 500, "token_error", "无法签发登录凭据")
		return
	}
	a.emitEvent(context.Background(), "account.login", u.ID, newID(), "你的 ASWired 账户刚刚建立了新登录会话。", nil)
	respond(w, 200, map[string]any{"token": token, "user": u})
}
func (a *App) me(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, map[string]any{"user": current(r)})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	u.TokenVersion++
	if e := a.DB.UpdateUser(r.Context(), u); e != nil {
		fail(w, 500, "storage_error", "退出失败，请重试")
		return
	}
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) password(w http.ResponseWriter, r *http.Request) {
	var in struct{ CurrentPassword, NewPassword, Code string }
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	if !auth.VerifyPassword(u.PasswordHash, in.CurrentPassword) {
		fail(w, 400, "invalid_password", "当前密码不正确")
		return
	}
	if e := a.verifyTOTP(r.Context(), u, in.Code); e != nil {
		fail(w, 401, "invalid_totp", "请输入有效动态口令或恢复码")
		return
	}
	if e := validCredentials(u.Username, in.NewPassword); e != nil {
		fail(w, 400, "invalid_password", e.Error())
		return
	}
	hash, e := auth.HashPassword(in.NewPassword)
	if e != nil {
		fail(w, 500, "password_error", "密码更新失败")
		return
	}
	u.PasswordHash = hash
	u.TokenVersion++
	if e = a.DB.UpdateUser(r.Context(), u); e != nil {
		fail(w, 500, "storage_error", "密码更新失败")
		return
	}
	u, e = a.DB.UserByID(r.Context(), u.ID)
	if e != nil {
		fail(w, 500, "storage_error", "无法读取新会话")
		return
	}
	a.issue(w, u)
}
func validCredentials(name, password string) error {
	if len(strings.TrimSpace(name)) < 2 || len(name) > 80 {
		return errors.New("用户名长度须为2至80个字符")
	}
	if len(password) < 12 || len(password) > 72 {
		return errors.New("密码须为12至72字节")
	}
	return nil
}
func newID() string {
	b := make([]byte, 18)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func constant(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func text(m map[string]any, k string) string {
	v := m[k]
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}
func number(m map[string]any, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		n, _ := v.Float64()
		return n
	}
	return 0
}
func boolean(m map[string]any, k string) bool { v, _ := m[k].(bool); return v }
func clone(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	out := map[string]any{}
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.UseNumber()
	_ = decoder.Decode(&out)
	return out
}
func (a *App) audit(ctx context.Context, u store.User, action, target string, details map[string]any) {
	if e := a.DB.AppendAudit(ctx, store.AuditEvent{ID: newID(), ActorID: u.ID, Action: action, Target: target, Details: details, CreatedAt: time.Now().UTC()}); e != nil {
		slog.Error("audit save failed", "action", action, "error", e)
	}
}
