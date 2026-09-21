package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestS3PublishedSignatureVector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	e := signS3(req, nil, map[string]any{"accessKeyId": "AKIAIOSFODNN7EXAMPLE", "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "region": "us-east-1"}, time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(req.Header.Get("Authorization"), "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") {
		t.Fatal("AWS published signature does not match")
	}
	if awsPath("/a+b/中 文") != "/a%2Bb/%E4%B8%AD%20%E6%96%87" {
		t.Fatal("S3 path escaping wrong")
	}
}

func TestDriveResumableEncryptedBackup(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	var object []byte
	var base string
	refreshes, uploads, downloads := 0, 0, 0
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			r.ParseForm()
			if r.Form.Get("refresh_token") != "fixture-refresh" || r.Form.Get("grant_type") != "refresh_token" {
				w.WriteHeader(400)
				return
			}
			refreshes++
			respond(w, 200, map[string]string{"access_token": "fixture-access"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer fixture-access" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/upload/drive/v3/files":
			var metadata map[string]any
			if r.URL.Query().Get("uploadType") != "resumable" || json.NewDecoder(r.Body).Decode(&metadata) != nil || !strings.HasSuffix(text(metadata, "name"), ".aswb") {
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Location", base+"/upload-session")
			w.WriteHeader(200)
		case "/upload-session":
			if r.Method != "PUT" {
				w.WriteHeader(405)
				return
			}
			object, _ = io.ReadAll(r.Body)
			uploads++
			respond(w, 200, map[string]string{"id": "file-fixture"})
		case "/drive/v3/files/file-fixture":
			if r.URL.Query().Get("alt") != "media" {
				w.WriteHeader(400)
				return
			}
			downloads++
			w.Write(object)
		default:
			w.WriteHeader(404)
		}
	}))
	defer fixture.Close()
	base = fixture.URL
	cfg := map[string]any{"remoteBackup": map[string]any{"provider": "gdrive", "apiBaseURL": base, "tokenURL": base + "/token", "refreshToken": "fixture-refresh", "clientId": "fixture-client", "clientSecret": "fixture-secret", "encryptionPassword": "independent-drive-encryption-key"}}
	if e := a.DB.SetSetting(ctx, "settings", cfg); e != nil {
		t.Fatal(e)
	}
	u, _ := a.DB.UserByUsername(ctx, "test-admin")
	upload, e := a.remoteBackup(ctx, u, "backup.remote.upload", nil)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(string(object), "ASWBACK1") {
		t.Fatal("plaintext upload")
	}
	if _, e = a.remoteBackup(ctx, u, "backup.remote.download", map[string]any{"id": upload["id"]}); e != nil {
		t.Fatal(e)
	}
	if refreshes != 2 || uploads != 1 || downloads != 1 {
		t.Fatalf("actual provider flow missing: %d %d %d", refreshes, uploads, downloads)
	}
}
