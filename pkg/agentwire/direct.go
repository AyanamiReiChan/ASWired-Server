package agentwire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

const DirectHelloProtocol = "aswired-direct-hello-v1"

type DirectHello struct {
	Protocol        string `json:"protocol"`
	Nonce           string `json:"nonce"`
	PublicKey       string `json:"public_key"`
	ServerID        string `json:"server_id"`
	MasterPublicKey string `json:"master_public_key"`
	Timestamp       int64  `json:"timestamp"`
	Proof           string `json:"proof"`
}

func ValidDirectNonce(nonce string) bool { return canonicalDirectKey(nonce) }

func canonicalDirectKey(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func directHelloMessage(h DirectHello) ([]byte, error) {
	if h.Protocol != DirectHelloProtocol || !ValidDirectNonce(h.Nonce) || !canonicalDirectKey(h.PublicKey) || !canonicalDirectKey(h.MasterPublicKey) || h.ServerID == "" || len(h.ServerID) > 256 || strings.ContainsAny(h.ServerID, "\r\n") || h.Timestamp <= 0 {
		return nil, errors.New("invalid direct hello fields")
	}
	return []byte(strings.Join([]string{h.Protocol, h.Nonce, h.PublicKey, h.ServerID, h.MasterPublicKey, strconv.FormatInt(h.Timestamp, 10)}, "\n")), nil
}

func SignDirectHello(token string, h DirectHello) (DirectHello, error) {
	message, err := directHelloMessage(h)
	if err != nil {
		return DirectHello{}, err
	}
	if token == "" {
		return DirectHello{}, errors.New("direct hello token is required")
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(message)
	h.Proof = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return h, nil
}

func VerifyDirectHello(token string, h DirectHello) error {
	if !canonicalDirectKey(h.Proof) {
		return errors.New("invalid direct hello proof")
	}
	signed, err := SignDirectHello(token, h)
	if err != nil {
		return err
	}
	provided, _ := base64.RawURLEncoding.DecodeString(h.Proof)
	expected, _ := base64.RawURLEncoding.DecodeString(signed.Proof)
	if !hmac.Equal(provided, expected) {
		return errors.New("direct hello identity proof failed")
	}
	return nil
}
