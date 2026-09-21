package httpapi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/namesilo"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/net/idna"
)

var certificateMu sync.Mutex

type acmeUser struct {
	Email        string
	Key          crypto.PrivateKey
	Registration *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.Key }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }

type contextualTransport struct {
	Context context.Context
	Base    http.RoundTripper
}

func (t contextualTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.Base.RoundTrip(r.Clone(t.Context))
}

func certificateDomains(row map[string]any) ([]string, error) {
	domains := stringList(row["domains"])
	if len(domains) == 0 {
		domains = stringList(row["name"])
	}
	if len(domains) == 0 || len(domains) > 100 {
		return nil, errors.New("证书需要1至100个域名")
	}
	seen := map[string]bool{}
	result := []string{}
	for _, name := range domains {
		wildcard := strings.HasPrefix(name, "*.")
		if wildcard {
			name = strings.TrimPrefix(name, "*.")
		}
		ascii, e := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(name), "."))
		if e != nil || len(ascii) > 253 || !strings.Contains(ascii, ".") || net.ParseIP(ascii) != nil {
			return nil, errors.New("请输入有效DNS域名")
		}
		for _, label := range strings.Split(ascii, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return nil, errors.New("域名标签无效")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, errors.New("域名包含非法字符")
				}
			}
		}
		if wildcard {
			ascii = "*." + ascii
		}
		if !seen[ascii] {
			seen[ascii] = true
			result = append(result, ascii)
		}
	}
	return result, nil
}

func (a *App) acmeClient(ctx context.Context, asset store.Record) (*lego.Client, *acmeUser, store.Record, error) {
	row := asset.Data
	directory := text(row, "acmeDirectory")
	if directory == "" {
		directory = lego.LEDirectoryProduction
		if boolean(row, "staging") {
			directory = lego.LEDirectoryStaging
		}
	}
	parsed, e := url.Parse(directory)
	if e != nil || parsed.Host == "" || parsed.User != nil || parsed.Scheme != "https" {
		return nil, nil, store.Record{}, errors.New("ACME目录须为HTTPS地址；自建CA可配置受信任CA证书")
	}
	email := text(row, "email")
	if _, e := mail.ParseAddress(email); e != nil {
		return nil, nil, store.Record{}, errors.New("请为ACME账户配置有效联系邮箱")
	}
	digest := sha256.Sum256([]byte(directory + "\n" + strings.ToLower(email)))
	id := hex.EncodeToString(digest[:])
	account, e := a.DB.GetRecord(ctx, "_acmeAccounts", id)
	user := &acmeUser{Email: email}
	if e == nil {
		block, _ := pem.Decode([]byte(text(account.Data, "privateKey")))
		if block == nil {
			return nil, nil, account, errors.New("ACME账户密钥损坏")
		}
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, nil, account, e
		}
		user.Key = key
		if raw, ok := account.Data["registration"]; ok {
			b, _ := json.Marshal(raw)
			_ = json.Unmarshal(b, &user.Registration)
		}
	} else if errors.Is(e, store.ErrNotFound) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, nil, account, e
		}
		user.Key = key
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return nil, nil, account, e
		}
		account = store.Record{Collection: "_acmeAccounts", ID: id, Data: map[string]any{"email": email, "directory": directory, "privateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}}
	} else {
		return nil, nil, account, e
	}
	cfg := lego.NewConfig(user)
	cfg.CADirURL = directory
	cfg.UserAgent = "ASWired/" + Version
	cfg.Certificate.KeyType = certcrypto.EC256
	cfg.Certificate.Timeout = 90 * time.Second
	transport := http.DefaultTransport
	if a.client != nil && a.client.Transport != nil {
		transport = a.client.Transport
	}
	if ca := text(row, "caCertificatePEM"); ca != "" {
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(ca)) {
			return nil, nil, account, errors.New("自定义CA证书无效")
		}
		transport = &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, ResponseHeaderTimeout: 30 * time.Second}
	}
	cfg.HTTPClient = &http.Client{Transport: contextualTransport{Context: ctx, Base: transport}, Timeout: 90 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("ACME重定向过多")
		}
		if req.URL.Scheme != "https" && !isLoopbackHost(req.URL.Hostname()) {
			return errors.New("ACME不允许降级到非加密地址")
		}
		return nil
	}}
	client, e := lego.NewClient(cfg)
	if e != nil {
		return nil, nil, account, e
	}
	switch strings.ToUpper(text(row, "challenge")) {
	case "DNS-01", "DNS01", "":
		providerRow := clone(row)
		if providerID := text(row, "dnsProviderId"); providerID != "" {
			record, e := a.DB.GetRecord(ctx, "dnsProviders", providerID)
			if e != nil {
				return nil, nil, account, e
			}
			providerRow = clone(record.Data)
		}
		dns, e := dnsChallengeProvider(providerRow, cfg.HTTPClient)
		if e != nil {
			return nil, nil, account, e
		}
		if e = client.Challenge.SetDNS01Provider(dns); e != nil {
			return nil, nil, account, e
		}
	case "HTTP-01", "HTTP01":
		port := int(number(row, "httpChallengePort"))
		if port < 1 || port > 65535 {
			return nil, nil, account, errors.New("HTTP-01必须明确配置主控监听端口，并将公网80端口转发至此端口")
		}
		host := text(row, "httpChallengeHost")
		if host == "" {
			host = "0.0.0.0"
		}
		if net.ParseIP(host) == nil {
			return nil, nil, account, errors.New("HTTP验证监听地址必须为IP")
		}
		if e = client.Challenge.SetHTTP01Provider(http01.NewProviderServer(host, strconv.Itoa(port))); e != nil {
			return nil, nil, account, e
		}
	default:
		return nil, nil, account, errors.New("验证方式仅支持DNS-01和HTTP-01")
	}
	return client, user, account, nil
}

func dnsChallengeProvider(row map[string]any, client *http.Client) (challenge.Provider, error) {
	provider := strings.ToLower(defaultText(row, "provider", text(row, "type")))
	switch {
	case strings.Contains(provider, "cloudflare"):
		token := defaultText(row, "apiToken", text(row, "credential"))
		if token == "" {
			return nil, errors.New("Cloudflare需要DNS编辑令牌apiToken")
		}
		return cloudflare.NewDNSProviderConfig(&cloudflare.Config{AuthToken: token, ZoneToken: defaultText(row, "zoneToken", token), HTTPClient: client, TTL: 120, PropagationTimeout: 2 * time.Minute, PollingInterval: 2 * time.Second})
	case provider == "alidns" || provider == "alicloud" || provider == "aliyun" || strings.Contains(provider, "阿里"):
		key := defaultText(row, "accessKeyId", text(row, "accessKeyID"))
		secret := defaultText(row, "accessKeySecret", text(row, "secretKey"))
		if key == "" || secret == "" {
			return nil, errors.New("阿里云DNS需要accessKeyId和accessKeySecret")
		}
		return alidns.NewDNSProviderConfig(&alidns.Config{APIKey: key, SecretKey: secret, SecurityToken: text(row, "securityToken"), RegionID: defaultText(row, "region", "cn-hangzhou"), TTL: 600, PropagationTimeout: 2 * time.Minute, PollingInterval: 2 * time.Second, HTTPTimeout: 30 * time.Second})
	case provider == "dnspodcn" || provider == "tencentcloud" || provider == "dnspod" || strings.Contains(provider, "腾讯"):
		id := defaultText(row, "secretId", text(row, "secretID"))
		secret := text(row, "secretKey")
		if id == "" || secret == "" {
			return nil, errors.New("腾讯DNSPod需要secretId和secretKey")
		}
		return tencentcloud.NewDNSProviderConfig(&tencentcloud.Config{SecretID: id, SecretKey: secret, Region: text(row, "region"), SessionToken: text(row, "sessionToken"), TTL: 600, PropagationTimeout: 2 * time.Minute, PollingInterval: 2 * time.Second, HTTPTimeout: 30 * time.Second})
	case provider == "namesilo":
		key := defaultText(row, "apiKey", text(row, "credential"))
		if key == "" {
			return nil, errors.New("Namesilo需要apiKey")
		}
		return namesilo.NewDNSProviderConfig(&namesilo.Config{APIKey: key, TTL: 3600, PropagationTimeout: 10 * time.Minute, PollingInterval: 10 * time.Second})
	default:
		return nil, errors.New("DNS提供商须为Cloudflare、alidns、dnspodcn或namesilo")
	}
}
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (a *App) issueCertificate(ctx context.Context, actor store.User, id string, renew bool) (map[string]any, error) {
	certificateMu.Lock()
	defer certificateMu.Unlock()
	asset, e := a.DB.GetRecord(ctx, "certificates", id)
	if e != nil {
		return nil, e
	}
	domains, e := certificateDomains(asset.Data)
	if e != nil {
		return nil, e
	}
	if !boolean(asset.Data, "termsAgreed") {
		return nil, errors.New("请在证书配置中确认ACME服务条款（termsAgreed）")
	}
	if strings.HasPrefix(strings.ToUpper(text(asset.Data, "challenge")), "HTTP") {
		for _, domain := range domains {
			if strings.HasPrefix(domain, "*.") {
				return nil, errors.New("通配符证书需要DNS-01验证")
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	client, user, account, e := a.acmeClient(ctx, asset)
	if e != nil {
		return nil, e
	}
	if user.Registration == nil {
		var registrationResult *registration.Resource
		if kid := text(asset.Data, "eabKid"); kid != "" {
			registrationResult, e = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{TermsOfServiceAgreed: true, Kid: kid, HmacEncoded: text(asset.Data, "eabHmacKey")})
		} else {
			registrationResult, e = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		}
		if e != nil {
			return nil, fmt.Errorf("ACME账户注册失败: %w", e)
		}
		user.Registration = registrationResult
		account.Data["registration"] = registrationResult
		if _, e := a.DB.SaveRecord(ctx, account); e != nil {
			return nil, e
		}
	}
	result, e := client.Certificate.Obtain(certificate.ObtainRequest{Domains: domains, Bundle: true})
	if e != nil {
		return nil, fmt.Errorf("ACME签发失败: %w", e)
	}
	asset.Data["certificateURL"] = result.CertURL
	asset.Data["renewed"] = renew
	asset.Data["domains"] = domains
	asset, e = a.saveCertificateMaterial(ctx, asset, string(result.Certificate), string(result.PrivateKey), "acme")
	if e != nil {
		return nil, e
	}
	a.audit(ctx, actor, "certificate.issued", id, map[string]any{"domains": domains, "expires": asset.Data["expires"]})
	resultRow := map[string]any{"success": true, "row": rowOf(asset, false), "message": "证书已签发并验证"}
	if boolean(asset.Data, "autoDeploy") {
		deployment, err := a.deployCertificate(ctx, actor, id, nil)
		if err != nil {
			resultRow["deploymentError"] = err.Error()
			resultRow["message"] = "证书已签发，但自动部署失败：" + err.Error()
		} else {
			resultRow["tasks"] = deployment["tasks"]
			resultRow["deployment_errors"] = deployment["deployment_errors"]
			resultRow["message"] = deployment["message"]
		}
	}
	return resultRow, nil
}

func validateCertificatePair(certificatePEM, keyPEM string, domains []string) (*x509.Certificate, error) {
	if len(certificatePEM) > 1<<20 || len(keyPEM) > 128<<10 {
		return nil, errors.New("证书材料超出大小限制")
	}
	pair, e := tls.X509KeyPair([]byte(certificatePEM), []byte(keyPEM))
	if e != nil || len(pair.Certificate) == 0 {
		return nil, errors.New("证书和私钥无法匹配")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	if time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore.Add(-5*time.Minute)) {
		return nil, errors.New("证书尚未生效或已经过期")
	}
	for _, domain := range domains {
		testName := domain
		if strings.HasPrefix(domain, "*.") {
			covered := false
			for _, name := range leaf.DNSNames {
				if strings.EqualFold(name, domain) {
					covered = true
				}
			}
			if !covered {
				return nil, fmt.Errorf("证书不覆盖通配符域名%s", domain)
			}
			testName = "aswired-validation." + strings.TrimPrefix(domain, "*.")
		}
		if e := leaf.VerifyHostname(testName); e != nil {
			return nil, fmt.Errorf("证书不覆盖域名%s", domain)
		}
	}
	return leaf, nil
}

func (a *App) saveCertificateMaterial(ctx context.Context, asset store.Record, certificatePEM, keyPEM, source string) (store.Record, error) {
	domains, e := certificateDomains(asset.Data)
	if e != nil {
		return store.Record{}, e
	}
	leaf, e := validateCertificatePair(certificatePEM, keyPEM, domains)
	if e != nil {
		return store.Record{}, e
	}
	material, e := a.DB.GetRecord(ctx, "_certificateMaterial", asset.ID)
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		return store.Record{}, e
	}
	material = store.Record{Collection: "_certificateMaterial", ID: asset.ID, Version: material.Version, Data: map[string]any{"certificate": certificatePEM, "privateKey": keyPEM, "source": source, "serial": leaf.SerialNumber.String()}}
	asset.Data["expires"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	asset.Data["issuedAt"] = leaf.NotBefore.UTC().Format(time.RFC3339)
	asset.Data["serial"] = leaf.SerialNumber.String()
	asset.Data["status"] = "已签发"
	asset.Data["issuer"] = leaf.Issuer.String()
	asset.Data["materialSource"] = source
	saved, e := a.DB.CompareAndSaveRecords(ctx, []store.Record{material, asset})
	if e != nil {
		return store.Record{}, e
	}
	return saved[1], nil
}

func (a *App) deployCertificate(ctx context.Context, actor store.User, id string, params map[string]any) (map[string]any, error) {
	asset, e := a.DB.GetRecord(ctx, "certificates", id)
	if e != nil {
		return nil, e
	}
	material, e := a.DB.GetRecord(ctx, "_certificateMaterial", id)
	if e != nil {
		return nil, errors.New("证书没有已验证材料，请先申请或上传")
	}
	domains, e := certificateDomains(asset.Data)
	if e != nil {
		return nil, e
	}
	if _, e = validateCertificatePair(text(material.Data, "certificate"), text(material.Data, "privateKey"), domains); e != nil {
		return nil, e
	}
	ids := stringList(params["serverIds"])
	if len(ids) == 0 {
		ids = stringList(asset.Data["serverIds"])
	}
	if len(ids) == 0 {
		return nil, errors.New("请选择要部署的服务器ID")
	}
	tasks := []any{}
	deploymentErrors := []any{}
	seen := map[string]bool{}
	for _, serverID := range ids {
		if seen[serverID] {
			continue
		}
		seen[serverID] = true
		task, e := a.queue(ctx, actor, serverID, "certificate.deploy", map[string]any{"name": id, "certificate": material.Data["certificate"], "private_key": material.Data["privateKey"]})
		if e != nil {
			deploymentErrors = append(deploymentErrors, map[string]any{"serverId": serverID, "error": e.Error()})
			continue
		}
		tasks = append(tasks, taskRow(task))
	}
	message := "证书部署指令已排队，以节点结果为准"
	if len(deploymentErrors) > 0 {
		message = "部分服务器未能创建部署任务，请查看部署错误"
	}
	return map[string]any{"tasks": tasks, "deployment_errors": deploymentErrors, "message": message}, nil
}
