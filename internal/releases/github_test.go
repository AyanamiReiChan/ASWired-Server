package releases

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestReleaseChannelAndChecksums(t *testing.T) {
	makeRelease := func(tag string, preview bool) map[string]any {
		assets := []any{map[string]string{"name": "SHA256SUMS", "browser_download_url": DownloadBase + tag + "/SHA256SUMS"}}
		for _, arch := range []string{"amd64", "arm64"} {
			for _, name := range []string{"aswired-agent_" + tag + "_linux_" + arch, "aswired-server_" + tag + "_linux_" + arch + ".tar.gz"} {
				assets = append(assets, map[string]string{"name": name, "browser_download_url": DownloadBase + tag + "/" + name})
			}
		}
		return map[string]any{"tag_name": tag, "prerelease": preview, "assets": assets}
	}
	var calls int
	fetch := func(_ context.Context, u string) ([]byte, error) {
		calls++
		if strings.HasSuffix(u, "SHA256SUMS") {
			tag := "v1.0.0"
			if strings.Contains(u, "v1.1.0-rc.1") {
				tag = "v1.1.0-rc.1"
			}
			var lines []string
			for _, arch := range []string{"amd64", "arm64"} {
				for _, name := range []string{"aswired-agent_" + tag + "_linux_" + arch, "aswired-server_" + tag + "_linux_" + arch + ".tar.gz"} {
					lines = append(lines, strings.Repeat("a", 64)+"  "+name)
				}
			}
			return []byte(strings.Join(lines, "\n")), nil
		}
		if strings.Contains(u, "per_page") {
			return json.Marshal([]any{makeRelease("v1.0.0", false), makeRelease("v1.1.0-rc.1", true)})
		}
		return json.Marshal(makeRelease("v1.0.0", false))
	}
	info, err := Resolve(context.Background(), false, fetch)
	if err != nil || info.Version != "v1.0.0" || len(info.Agents) != 2 || calls != 2 {
		t.Fatal(info, err, calls)
	}
	info, err = Resolve(context.Background(), true, fetch)
	if err != nil || info.Version != "v1.1.0-rc.1" {
		t.Fatal(info, err)
	}
	if Newer("1.0.0", "v1.0.0") || Newer("v2.0.0", "v1.0.0") || !Newer("development", "v1.0.0") || !Newer("v1.0.0", "v1.1.0") {
		t.Fatal("version comparison")
	}
	_, err = Resolve(context.Background(), false, func(_ context.Context, u string) ([]byte, error) {
		if strings.HasSuffix(u, "SHA256SUMS") {
			return []byte("invalid"), nil
		}
		return json.Marshal(makeRelease("v1.0.0", false))
	})
	if err == nil {
		t.Fatal("accepted incomplete checksum file")
	}
}

func TestReleaseRejectsUnsafeURLsAndDraft(t *testing.T) {
	for _, address := range []string{"http://github.com/file", "https://github.com.attacker.test/file", "https://user@github.com/file", "https://github.com:444/file"} {
		u, _ := url.Parse(address)
		if trustedDownload(u) {
			t.Fatal(address)
		}
	}
	_, err := Resolve(context.Background(), false, func(context.Context, string) ([]byte, error) {
		return []byte(`{"tag_name":"v1.0.0","draft":true}`), nil
	})
	if err == nil {
		t.Fatal("accepted draft release")
	}
}
