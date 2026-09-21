package agentwire

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const FederationProtocol = "aswired-agent-share-v1"

type FederationGrant struct {
	Protocol          string            `json:"protocol"`
	ID                string            `json:"id"`
	Revision          uint64            `json:"revision"`
	ServerID          string            `json:"server_id"`
	AgentPublicKey    string            `json:"agent_public_key"`
	ConsumerPublicKey string            `json:"consumer_public_key"`
	Namespace         string            `json:"namespace"`
	Inbounds          map[string]string `json:"inbounds"`
	Actions           []string          `json:"actions"`
	ExpiresAt         int64             `json:"expires_at"`
	Revoked           bool              `json:"revoked"`
}
type SignedFederationGrant struct {
	Grant          FederationGrant `json:"grant"`
	OwnerPublicKey string          `json:"owner_public_key"`
	Signature      string          `json:"signature"`
}
type FederationRequest struct {
	GrantRevision      uint64  `json:"grant_revision"`
	Protocol           string  `json:"protocol"`
	ShareID            string  `json:"share_id"`
	Namespace          string  `json:"namespace"`
	AgentPublicKey     string  `json:"agent_public_key"`
	ConsumerPublicKey  string  `json:"consumer_public_key"`
	EphemeralPublicKey string  `json:"ephemeral_public_key"`
	IssuedAt           int64   `json:"issued_at"`
	Command            Command `json:"command"`
	Proof              string  `json:"proof"`
}
type FederationEnvelope struct {
	RequestID         string `json:"request_id"`
	ShareID           string `json:"share_id"`
	ConsumerPublicKey string `json:"consumer_public_key"`
	Hello             Hello  `json:"hello"`
}

func SignFederationGrant(grant FederationGrant, key ed25519.PrivateKey) (SignedFederationGrant, error) {
	b, e := json.Marshal(grant)
	if e != nil {
		return SignedFederationGrant{}, e
	}
	signature := ed25519.Sign(key, append([]byte(FederationProtocol+"/acl|"), b...))
	return SignedFederationGrant{Grant: grant, OwnerPublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}
func VerifyFederationGrant(s SignedFederationGrant) error {
	key, e := base64.RawURLEncoding.DecodeString(s.OwnerPublicKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid federation owner key")
	}
	sig, e := base64.RawURLEncoding.DecodeString(s.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid federation grant signature")
	}
	b, e := json.Marshal(s.Grant)
	if e != nil {
		return e
	}
	if !ed25519.Verify(key, append([]byte(FederationProtocol+"/acl|"), b...), sig) {
		return errors.New("federation ACL signature failed")
	}
	return nil
}
func FederationProof(private, peerPublic string, request FederationRequest) (string, error) {
	kb, e := decodeKey(private)
	if e != nil {
		return "", e
	}
	k, e := ecdh.X25519().NewPrivateKey(kb)
	if e != nil {
		return "", e
	}
	pb, e := decodeKey(peerPublic)
	if e != nil {
		return "", e
	}
	p, e := ecdh.X25519().NewPublicKey(pb)
	if e != nil {
		return "", e
	}
	secret, e := k.ECDH(p)
	if e != nil {
		return "", e
	}
	key, e := hkdf.Key(sha256.New, secret, nil, FederationProtocol+"/consumer-proof|"+request.ConsumerPublicKey+"|"+request.AgentPublicKey, 32)
	if e != nil {
		return "", e
	}
	request.Proof = ""
	b, e := json.Marshal(request)
	if e != nil {
		return "", e
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func VerifyFederationProof(private string, request FederationRequest) error {
	expected, e := FederationProof(private, request.ConsumerPublicKey, request)
	if e != nil {
		return e
	}
	if !hmac.Equal([]byte(expected), []byte(request.Proof)) {
		return errors.New("consumer identity authentication failed")
	}
	return nil
}
