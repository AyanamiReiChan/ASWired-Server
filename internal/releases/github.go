// Package releases resolves explicitly requested updates from the public binary repository.
// It never polls in the background or downloads Agent binaries during a version check.
package releases

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const Repository = "AyanamiReiChan/ASWired-Release"
const DownloadBase = "https://github.com/" + Repository + "/releases/download/"

type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}
type Info struct {
	Version    string           `json:"version"`
	URL        string           `json:"url"`
	Prerelease bool             `json:"prerelease"`
	Agents     map[string]Asset `json:"agents"`
}
type githubRelease struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}
type Fetch func(context.Context, string) ([]byte, error)

func Newer(current, candidate string) bool {
	current = "v" + strings.TrimPrefix(current, "v")
	return semver.IsValid(candidate) && (!semver.IsValid(current) || semver.Compare(candidate, current) > 0)
}

func Latest(ctx context.Context, preview bool) (Info, error) {
	return Resolve(ctx, preview, fetch)
}

func Resolve(ctx context.Context, preview bool, get Fetch) (Info, error) {
	endpoint := "https://api.github.com/repos/" + Repository + "/releases/latest"
	if preview {
		endpoint = "https://api.github.com/repos/" + Repository + "/releases?per_page=20"
	}
	raw, err := get(ctx, endpoint)
	if err != nil {
		return Info{}, err
	}
	var releases []githubRelease
	if preview {
		err = json.Unmarshal(raw, &releases)
	} else {
		var release githubRelease
		err = json.Unmarshal(raw, &release)
		releases = []githubRelease{release}
	}
	if err != nil {
		return Info{}, errors.New("GitHub 版本响应无效")
	}
	var selected *githubRelease
	for i := range releases {
		r := &releases[i]
		if r.Draft || !semver.IsValid(r.Tag) || semver.Canonical(r.Tag) != r.Tag || (!preview && (r.Prerelease || semver.Prerelease(r.Tag) != "")) {
			continue
		}
		if selected == nil || semver.Compare(r.Tag, selected.Tag) > 0 {
			selected = r
		}
	}
	if selected == nil {
		return Info{}, errors.New("GitHub 尚无可用的完整发行版")
	}
	base := DownloadBase + selected.Tag + "/"
	assets := map[string]string{}
	for _, asset := range selected.Assets {
		if asset.URL != base+asset.Name || strings.ContainsAny(asset.Name, "/\\?#") {
			continue
		}
		if _, exists := assets[asset.Name]; exists {
			return Info{}, errors.New("发行版包含重复制品")
		}
		assets[asset.Name] = asset.URL
	}
	if assets["SHA256SUMS"] == "" {
		return Info{}, errors.New("发行版缺少 SHA256SUMS")
	}
	raw, err = get(ctx, assets["SHA256SUMS"])
	if err != nil {
		return Info{}, err
	}
	sums := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		digest, e := hex.DecodeString(fields[0])
		if e != nil || len(digest) != 32 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if _, exists := sums[name]; exists {
			return Info{}, errors.New("校验文件包含重复制品")
		}
		sums[name] = strings.ToLower(fields[0])
	}
	info := Info{Version: selected.Tag, URL: "https://github.com/" + Repository + "/releases/tag/" + selected.Tag, Prerelease: selected.Prerelease, Agents: map[string]Asset{}}
	for _, arch := range []string{"amd64", "arm64"} {
		name := "aswired-agent_" + selected.Tag + "_linux_" + arch
		if assets[name] != "" && sums[name] != "" {
			info.Agents[arch] = Asset{URL: assets[name], SHA256: sums[name]}
		}
		server := "aswired-server_" + selected.Tag + "_linux_" + arch + ".tar.gz"
		if assets[server] == "" || sums[server] == "" {
			return Info{}, fmt.Errorf("发行版缺少 %s 或校验值", server)
		}
	}
	if len(info.Agents) != 2 {
		return Info{}, errors.New("发行版缺少 Linux Agent 或校验值")
	}
	return info, nil
}

func fetch(ctx context.Context, address string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ASWired-release-check")
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !trustedDownload(r.URL) {
			return errors.New("GitHub 下载重定向无效")
		}
		return nil
	}}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("无法连接 GitHub: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, errors.New("GitHub 尚无已发布版本")
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub 请求失败（HTTP %d），请稍后重试", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if len(raw) > 1<<20 {
		return nil, errors.New("GitHub 版本信息超过大小限制")
	}
	return raw, err
}
func trustedDownload(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	switch u.Hostname() {
	case "github.com", "api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}
