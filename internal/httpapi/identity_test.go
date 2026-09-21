package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/fxamacker/cbor/v2"
)

func identityFixture(t *testing.T) (*App, store.User, http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	db, e := store.Open(store.Config{Driver: "sqlite", DSN: filepath.Join(dir, "identity.db")})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	a, e := New(config.Config{DataDir: dir, PublicURL: "https://panel.example.test", AllowedOrigins: []string{"https://panel.example.test", "https://probe.example.test"}, JWTSecret: bytes.Repeat([]byte{7}, 32), JWTTTL: time.Hour}, db)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := auth.HashPassword("identity-test-password")
	if e != nil {
		t.Fatal(e)
	}
	u := store.User{ID: "identity-user", Username: "identity-admin", PasswordHash: hash, Role: "admin", TokenVersion: 1}
	if e = db.CreateUser(context.Background(), u); e != nil {
		t.Fatal(e)
	}
	u, e = db.UserByID(context.Background(), u.ID)
	if e != nil {
		t.Fatal(e)
	}
	token, e := a.Signer.Issue(u.ID, u.TokenVersion)
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	a.registerIdentity(mux)
	return a, u, mux, token
}
func identityCall(t *testing.T, h http.Handler, path, token string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://panel.example.test")
	r.RemoteAddr = "127.0.0.1:19999"
	if token != "" {
		r.Header.Set("MM-Authorization", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var result map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	return w.Code, result
}
func TestIdentityTOTPRFCVectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		epoch int64
		code  string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		actual, e := totpCode(secret, v.epoch/30)
		if e != nil || actual != v.code {
			t.Fatalf("RFC time %d: got %s, %v", v.epoch, actual, e)
		}
	}
}
func TestIdentityTOTPConsumesCounterAndRecoveryOnce(t *testing.T) {
	a, u, _, _ := identityFixture(t)
	codes, hashes, e := newRecoveryCodes()
	if e != nil {
		t.Fatal(e)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes.Repeat([]byte{1}, 20))
	rec, _, e := a.loadTOTP(context.Background(), u.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.saveTOTP(context.Background(), rec, totpSettings{Enabled: true, Secret: secret, LastCounter: -1, RecoveryHashes: hashes}); e != nil {
		t.Fatal(e)
	}
	if !errors.Is(a.verifyTOTP(context.Background(), u, ""), ErrTOTPRequired) {
		t.Fatal("missing TOTP did not challenge")
	}
	code, _ := totpCode(secret, time.Now().Unix()/30)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a.verifyTOTP(context.Background(), u, code) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted one-time code %d times", accepted.Load())
	}
	if e = a.verifyTOTP(context.Background(), u, codes[0]); e != nil {
		t.Fatal(e)
	}
	if a.verifyTOTP(context.Background(), u, codes[0]) == nil {
		t.Fatal("recovery code reused")
	}
	_, settings, e := a.loadTOTP(context.Background(), u.ID)
	if e != nil || len(settings.RecoveryHashes) != 9 {
		t.Fatal("recovery consumption not persisted")
	}
	for _, hash := range settings.RecoveryHashes {
		if hash == codes[1] {
			t.Fatal("recovery plaintext persisted")
		}
	}
}
func TestIdentityTOTPSetupRequiresPasswordAndConfirmation(t *testing.T) {
	a, u, h, token := identityFixture(t)
	status, _ := identityCall(t, h, "/api/account/totp/begin", token, map[string]any{"password": "wrong"})
	if status == 200 {
		t.Fatal("TOTP setup accepted wrong password")
	}
	status, body := identityCall(t, h, "/api/account/totp/begin", token, map[string]any{"password": "identity-test-password"})
	if status != 200 {
		t.Fatalf("begin %d: %v", status, body)
	}
	_, before, _ := a.loadTOTP(context.Background(), u.ID)
	if before.Enabled {
		t.Fatal("TOTP enabled before confirmation")
	}
	code, _ := totpCode(body["secret"].(string), time.Now().Unix()/30)
	status, body = identityCall(t, h, "/api/account/totp/confirm", token, map[string]any{"code": code})
	if status != 200 || len(body["recoveryCodes"].([]any)) != 10 {
		t.Fatalf("confirm %d", status)
	}
	if e := a.verifyTOTP(context.Background(), u, code); e == nil {
		t.Fatal("confirmation code reused for login")
	}
}

func authenticatorCreate(t *testing.T, key *ecdsa.PrivateKey, id []byte, challenge, origin string) map[string]any {
	t.Helper()
	public, e := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if e != nil {
		t.Fatal(e)
	}
	rp := sha256.Sum256([]byte("panel.example.test"))
	data := append([]byte{}, rp[:]...)
	data = append(data, 0x45, 0, 0, 0, 0)
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(id)))
	data = append(data, id...)
	data = append(data, public...)
	attestation, e := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	if e != nil {
		t.Fatal(e)
	}
	client, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	encoded := base64.RawURLEncoding.EncodeToString(id)
	return map[string]any{"id": encoded, "rawId": encoded, "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(client), "attestationObject": base64.RawURLEncoding.EncodeToString(attestation), "transports": []string{"internal"}}}
}
func authenticatorGet(t *testing.T, key *ecdsa.PrivateKey, id []byte, challenge, origin, userID string, counter uint32) map[string]any {
	t.Helper()
	rp := sha256.Sum256([]byte("panel.example.test"))
	data := append([]byte{}, rp[:]...)
	data = append(data, 0x05)
	data = binary.BigEndian.AppendUint32(data, counter)
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	clientHash := sha256.Sum256(client)
	message := append(append([]byte{}, data...), clientHash[:]...)
	digest := sha256.Sum256(message)
	signature, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	encoded := base64.RawURLEncoding.EncodeToString(id)
	return map[string]any{"id": encoded, "rawId": encoded, "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(client), "authenticatorData": base64.RawURLEncoding.EncodeToString(data), "signature": base64.RawURLEncoding.EncodeToString(signature), "userHandle": base64.RawURLEncoding.EncodeToString([]byte(userID))}}
}
func identityChallenge(t *testing.T, body map[string]any) string {
	t.Helper()
	return body["options"].(map[string]any)["publicKey"].(map[string]any)["challenge"].(string)
}
func TestIdentityPasskeyRegistrationLoginJWTAndReplay(t *testing.T) {
	a, u, h, token := identityFixture(t)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	id := bytes.Repeat([]byte{9}, 16)
	status, begin := identityCall(t, h, "/api/account/passkeys/begin", token, map[string]any{"password": "identity-test-password", "name": "Test authenticator"})
	if status != 200 {
		t.Fatalf("register begin %d: %v", status, begin)
	}
	response := authenticatorCreate(t, key, id, identityChallenge(t, begin), "https://panel.example.test")
	finish := map[string]any{"challengeId": begin["challengeId"], "response": response}
	status, body := identityCall(t, h, "/api/account/passkeys/finish", token, finish)
	if status != 200 {
		t.Fatalf("register finish %d: %v", status, body)
	}
	status, _ = identityCall(t, h, "/api/account/passkeys/finish", token, finish)
	if status == 200 {
		t.Fatal("registration replay accepted")
	}
	status, begin = identityCall(t, h, "/api/passkey/login/begin", "", map[string]any{"username": u.Username})
	if status != 200 {
		t.Fatalf("login begin %d: %v", status, begin)
	}
	response = authenticatorGet(t, key, id, identityChallenge(t, begin), "https://panel.example.test", u.ID, 1)
	finish = map[string]any{"challengeId": begin["challengeId"], "response": response}
	status, body = identityCall(t, h, "/api/passkey/login/finish", "", finish)
	if status != 200 {
		t.Fatalf("login finish %d: %v", status, body)
	}
	claims, e := a.Signer.Parse(body["token"].(string))
	if e != nil || claims.Subject != u.ID {
		t.Fatal("passkey did not issue the user JWT")
	}
	status, _ = identityCall(t, h, "/api/passkey/login/finish", "", finish)
	if status == 200 {
		t.Fatal("assertion replay accepted")
	}
	user, e := a.passkeyAccount(context.Background(), u)
	if e != nil || user.credentials[0].Authenticator.SignCount != 1 {
		t.Fatal("credential counter not persisted")
	}
	status, begin = identityCall(t, h, "/api/passkey/login/begin", "", map[string]any{"username": u.Username})
	if status != 200 {
		t.Fatal("second login begin failed")
	}
	response = authenticatorGet(t, key, id, identityChallenge(t, begin), "https://probe.example.test", u.ID, 2)
	status, _ = identityCall(t, h, "/api/passkey/login/finish", "", map[string]any{"challengeId": begin["challengeId"], "response": response})
	if status == 200 {
		t.Fatal("another allowed origin completed a ceremony bound to panel origin")
	}
}
func TestIdentityCeremoniesExpireAndBindKind(t *testing.T) {
	a, _, _, _ := identityFixture(t)
	id, e := a.putCeremony(identityCeremony{Kind: "login"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.takeCeremony(id, "register"); e == nil {
		t.Fatal("wrong ceremony kind accepted")
	}
	id, e = a.putCeremony(identityCeremony{Kind: "login"})
	if e != nil {
		t.Fatal(e)
	}
	s := a.identityStore()
	s.mu.Lock()
	v := s.ceremonies[id]
	v.Expires = time.Now().Add(-time.Second)
	s.ceremonies[id] = v
	s.mu.Unlock()
	if _, e = a.takeCeremony(id, "login"); e == nil {
		t.Fatal("expired challenge accepted")
	}
}
