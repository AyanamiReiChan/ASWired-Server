package agentwire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

const Protocol = "aswired-agent-v1"
const MaxPacket = 16 << 20

type Command struct {
	ID     string         `json:"id"`
	Action string         `json:"action"`
	Params map[string]any `json:"params,omitempty"`
}
type Result struct {
	ID     string         `json:"id"`
	Status string         `json:"status"`
	Error  string         `json:"error,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
}
type Report struct {
	ConnectionMode string          `json:"connection_mode,omitempty"`
	ServerID       string          `json:"server_id"`
	Token          string          `json:"token"`
	Version        string          `json:"version"`
	Mode           string          `json:"mode"`
	Observation    map[string]any  `json:"observation,omitempty"`
	Capabilities   map[string]bool `json:"capabilities,omitempty"`
	Results        []Result        `json:"results,omitempty"`
	Timestamp      int64           `json:"timestamp"`
}
type Reply struct {
	ConnectionMode string    `json:"connection_mode,omitempty"`
	ListenAddress  string    `json:"listen_address,omitempty"`
	Commands       []Command `json:"commands"`
	Interval       int       `json:"interval"`
	Error          string    `json:"error,omitempty"`
}
type Packet struct {
	Sequence   uint64 `json:"sequence"`
	Ciphertext string `json:"ciphertext"`
}
type Hello struct {
	PublicKey string `json:"public_key"`
	Packet    Packet `json:"packet"`
}
type DirectRequest struct {
	Token     string  `json:"token"`
	Command   Command `json:"command"`
	Timestamp int64   `json:"timestamp"`
}
type Channel struct {
	mu             sync.Mutex
	tx, rx         cipher.AEAD
	sent, received uint64
	public         string
	private        string
}

func GenerateKey() (private, public string, err error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func PublicKey(private string) (string, error) {
	b, e := decodeKey(private)
	if e != nil {
		return "", e
	}
	k, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func decodeKey(s string) ([]byte, error) {
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return nil, errors.New("invalid X25519 key")
	}
	return b, nil
}

func NewClient(masterPublic string) (*Channel, error) {
	private, _, e := GenerateKey()
	if e != nil {
		return nil, e
	}
	return NewClientWithPrivate(masterPublic, private)
}

func NewClientWithPrivate(masterPublic, private string) (*Channel, error) {
	b, e := decodeKey(masterPublic)
	if e != nil {
		return nil, e
	}
	p, e := ecdh.X25519().NewPublicKey(b)
	if e != nil {
		return nil, e
	}
	kb, e := decodeKey(private)
	if e != nil {
		return nil, e
	}
	k, e := ecdh.X25519().NewPrivateKey(kb)
	if e != nil {
		return nil, e
	}
	secret, e := k.ECDH(p)
	if e != nil {
		return nil, e
	}
	ep := base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
	ch, e := makeChannel(secret, masterPublic, ep, true)
	if e == nil {
		ch.private = private
	}
	return ch, e
}

type ClientState struct {
	PrivateKey string `json:"private_key"`
	Sent       uint64 `json:"sent"`
	Received   uint64 `json:"received"`
}

func (c *Channel) ClientState() (ClientState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.private == "" {
		return ClientState{}, errors.New("only clients can export state")
	}
	return ClientState{c.private, c.sent, c.received}, nil
}
func RestoreClient(masterPublic string, state ClientState) (*Channel, error) {
	c, e := NewClientWithPrivate(masterPublic, state.PrivateKey)
	if e != nil {
		return nil, e
	}
	c.sent = state.Sent
	c.received = state.Received
	return c, nil
}

func NewServer(masterPrivate, ephemeralPublic string) (*Channel, error) {
	b, e := decodeKey(masterPrivate)
	if e != nil {
		return nil, e
	}
	k, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return nil, e
	}
	b, e = decodeKey(ephemeralPublic)
	if e != nil {
		return nil, e
	}
	p, e := ecdh.X25519().NewPublicKey(b)
	if e != nil {
		return nil, e
	}
	secret, e := k.ECDH(p)
	if e != nil {
		return nil, e
	}
	return makeChannel(secret, base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), ephemeralPublic, false)
}
func makeChannel(secret []byte, master, ephemeral string, client bool) (*Channel, error) {
	salt := sha256.Sum256([]byte(Protocol + "|" + master + "|" + ephemeral))
	makeAEAD := func(direction string) (cipher.AEAD, error) {
		key, e := hkdf.Key(sha256.New, secret, salt[:], Protocol+"/"+direction, 32)
		if e != nil {
			return nil, e
		}
		block, e := aes.NewCipher(key)
		if e != nil {
			return nil, e
		}
		return cipher.NewGCM(block)
	}
	c2s, e := makeAEAD("agent-to-master")
	if e != nil {
		return nil, e
	}
	s2c, e := makeAEAD("master-to-agent")
	if e != nil {
		return nil, e
	}
	ch := &Channel{tx: s2c, rx: c2s, public: ephemeral}
	if client {
		ch.tx, ch.rx = c2s, s2c
	}
	return ch, nil
}
func (c *Channel) PublicKey() string { return c.public }
func nonce(seq uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}
func aad(seq uint64) []byte { return append([]byte(Protocol+"|"), nonce(seq)...) }
func (c *Channel) Seal(value any) (Packet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, e := json.Marshal(value)
	if e != nil {
		return Packet{}, e
	}
	if len(data) > MaxPacket {
		return Packet{}, errors.New("packet too large")
	}
	if c.sent == ^uint64(0) {
		return Packet{}, errors.New("channel exhausted")
	}
	c.sent++
	enc := c.tx.Seal(nil, nonce(c.sent), data, aad(c.sent))
	return Packet{Sequence: c.sent, Ciphertext: base64.RawURLEncoding.EncodeToString(enc)}, nil
}
func (c *Channel) Open(packet Packet, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if packet.Sequence == 0 || packet.Sequence != c.received+1 {
		return errors.New("invalid packet sequence or replay")
	}
	if len(packet.Ciphertext) > MaxPacket*2 {
		return errors.New("packet too large")
	}
	data, e := base64.RawURLEncoding.DecodeString(packet.Ciphertext)
	if e != nil {
		return errors.New("invalid ciphertext")
	}
	data, e = c.rx.Open(nil, nonce(packet.Sequence), data, aad(packet.Sequence))
	if e != nil {
		return errors.New("channel authentication failed")
	}
	if len(data) > MaxPacket {
		return errors.New("packet too large")
	}
	if e = json.Unmarshal(data, out); e != nil {
		return fmt.Errorf("invalid packet payload: %w", e)
	}
	c.received = packet.Sequence
	return nil
}
