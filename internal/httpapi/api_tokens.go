package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/http"
	"strings"
	"time"
)

type apiScopesKey struct{}

func (a *App) createAPIToken(ctx context.Context, u store.User, params map[string]any) (map[string]any, error) {
	scopes := stringList(params["scopes"])
	if len(scopes) == 0 {
		scopes = []string{"read"}
	}
	for _, scope := range scopes {
		if scope != "read" && scope != "write" {
			return nil, errors.New("API权限仅支持read/write")
		}
	}
	days := int(number(params, "days"))
	if days == 0 {
		days = 90
	}
	if days < 1 || days > 365 {
		return nil, errors.New("令牌有效期须为1至365天")
	}
	id := newID()
	secret := newID() + newID()
	token := "asw_" + id + "." + secret
	sum := sha256.Sum256([]byte(secret))
	expires := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
	_, e := a.DB.SaveRecord(ctx, store.Record{Collection: "_apiTokens", ID: id, OwnerID: u.ID, Data: map[string]any{"hash": hex.EncodeToString(sum[:]), "expires": expires.Format(time.RFC3339), "scopes": scopes, "tokenVersion": u.TokenVersion}})
	if e != nil {
		return nil, e
	}
	row, e := a.DB.SaveRecord(ctx, store.Record{Collection: "tokens", ID: id, OwnerID: u.ID, Data: map[string]any{"name": defaultText(params, "name", "API Token"), "scopes": scopes, "expires": expires.Format(time.RFC3339), "status": "启用", "prefix": "asw_" + id[:6]}})
	if e != nil {
		_ = a.DB.DeleteRecord(ctx, "_apiTokens", id)
		return nil, e
	}
	return map[string]any{"token": token, "row": rowOf(row, false)}, nil
}
func (a *App) authenticateAPIToken(r *http.Request) (store.User, []string, error) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(strings.TrimPrefix(raw, "asw_"), ".")
	if !strings.HasPrefix(raw, "asw_") || len(parts) != 2 {
		return store.User{}, nil, errors.New("invalid API token")
	}
	rec, e := a.DB.GetRecord(r.Context(), "_apiTokens", parts[0])
	if e != nil {
		return store.User{}, nil, e
	}
	sum := sha256.Sum256([]byte(parts[1]))
	expiry, e := time.Parse(time.RFC3339, text(rec.Data, "expires"))
	if e != nil || time.Now().After(expiry) || !constant(text(rec.Data, "hash"), hex.EncodeToString(sum[:])) {
		return store.User{}, nil, errors.New("invalid API token")
	}
	u, e := a.DB.UserByID(r.Context(), rec.OwnerID)
	if e != nil || u.Disabled || u.TokenVersion != int64(number(rec.Data, "tokenVersion")) {
		return store.User{}, nil, errors.New("API token revoked")
	}
	return u, stringList(rec.Data["scopes"]), nil
}
func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope || s == "write" {
			return true
		}
	}
	return false
}
