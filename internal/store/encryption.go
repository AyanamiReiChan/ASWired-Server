package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

type EncryptionCodec struct{ aead cipher.AEAD }

func ValidateEncryptedJSON(key, raw []byte) error {
	s := &Store{}
	if e := s.SetEncryptionKey(key); e != nil {
		return e
	}
	var out any
	return s.decodeJSON(raw, &out)
}

func (s *Store) SetEncryptionKey(key []byte) error {
	if len(key) != 32 {
		return errors.New("data encryption key must contain 32 bytes")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return e
	}
	s.encryption = &EncryptionCodec{aead: g}
	return nil
}

type encryptedJSON struct {
	Version    int    `json:"_aswired_encrypted"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func (s *Store) encodeJSON(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil || s.encryption == nil {
		return raw, e
	}
	nonce := make([]byte, s.encryption.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	ct := s.encryption.aead.Seal(nil, nonce, raw, []byte("ASWired/storage/v1"))
	return json.Marshal(encryptedJSON{1, base64.RawURLEncoding.EncodeToString(nonce), base64.RawURLEncoding.EncodeToString(ct)})
}
func (s *Store) decodeJSON(raw []byte, out any) error {
	var env encryptedJSON
	if e := json.Unmarshal(raw, &env); e != nil {
		return decodePreciseJSON(raw, out)
	}
	if env.Version == 0 {
		return decodePreciseJSON(raw, out)
	}
	if env.Version != 1 || s.encryption == nil {
		return errors.New("data encryption key unavailable or format unsupported")
	}
	nonce, e := base64.RawURLEncoding.DecodeString(env.Nonce)
	if e != nil || len(nonce) != s.encryption.aead.NonceSize() {
		return errors.New("invalid encrypted data nonce")
	}
	ct, e := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if e != nil {
		return errors.New("invalid encrypted data")
	}
	plaintext, e := s.encryption.aead.Open(nil, nonce, ct, []byte("ASWired/storage/v1"))
	if e != nil {
		return errors.New("stored data authentication failed")
	}
	return decodePreciseJSON(plaintext, out)
}

func decodePreciseJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("stored JSON contains trailing data")
	}
	return nil
}
