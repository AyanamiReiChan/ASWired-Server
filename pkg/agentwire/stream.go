package agentwire

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const HeartbeatSeconds = 15
const TelemetrySeconds = 5
const binaryHeaderSize = 13 // ASW2, flags, uint64 sequence
const compressionThreshold = 1024

// Options are offered and selected inside the authenticated v1 handshake.
// Missing/unsupported options keep the complete v1 exchange unchanged.
type StreamOptions struct {
	Version          int    `json:"version"`
	Binary           bool   `json:"binary"`
	Compression      string `json:"compression,omitempty"`
	HeartbeatSeconds int    `json:"heartbeat_seconds,omitempty"`
	TelemetrySeconds int    `json:"telemetry_seconds,omitempty"`
	TelemetryDelta   bool   `json:"telemetry_delta,omitempty"`
}

func StreamOffer() *StreamOptions {
	return &StreamOptions{Version: 2, Binary: true, Compression: "gzip", TelemetryDelta: true}
}

func NegotiateStream(offer *StreamOptions) *StreamOptions {
	if offer == nil || offer.Version != 2 || !offer.Binary {
		return nil
	}
	selected := &StreamOptions{Version: 2, Binary: true, HeartbeatSeconds: HeartbeatSeconds, TelemetrySeconds: TelemetrySeconds}
	selected.TelemetryDelta = offer.TelemetryDelta
	if offer.Compression == "gzip" {
		selected.Compression = "gzip"
	}
	return selected
}

func (o *StreamOptions) Valid() bool {
	return o != nil && o.Version == 2 && o.Binary && (o.Compression == "" || o.Compression == "gzip") && o.HeartbeatSeconds == HeartbeatSeconds && o.TelemetrySeconds == TelemetrySeconds
}

// Identity and capabilities are inherited from the authenticated session.
// Token is sent uncompressed only when identity rotation changes it.
type Update struct {
	Kind         string            `json:"kind"`
	Timestamp    int64             `json:"timestamp"`
	Token        string            `json:"token,omitempty"`
	Busy         bool              `json:"busy,omitempty"`
	Observation  map[string]any    `json:"observation,omitempty"`
	Delta        *ObservationDelta `json:"delta,omitempty"`
	TelemetrySeq uint64            `json:"telemetry_seq,omitempty"`
	Capabilities map[string]bool   `json:"capabilities,omitempty"`
	Results      []Result          `json:"results,omitempty"`
}

func (u Update) Valid() bool {
	switch u.Kind {
	case "heartbeat":
		return u.Observation == nil && u.Delta == nil && u.TelemetrySeq == 0 && u.Capabilities == nil && len(u.Results) == 0
	case "telemetry":
		return len(u.Results) == 0 && ((u.Observation != nil && u.Delta == nil && u.TelemetrySeq == 0) || (u.Observation == nil && u.Delta != nil && u.TelemetrySeq > 0))
	case "results":
		return u.Observation == nil && u.Delta == nil && u.TelemetrySeq == 0 && u.Capabilities == nil && len(u.Results) > 0
	}
	return false
}

func binaryAAD(header []byte) []byte { return append([]byte(Protocol+"/binary-v2|"), header...) }

// SealBinary preserves the channel's sequence across the v1-to-v2 switch.
// Callers must not compress credentials, commands or arbitrary task results.
func (c *Channel) SealBinary(value any, compress bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := marshalPayload(value)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxPacket {
		return nil, errors.New("packet too large")
	}
	flags := byte(0)
	if compress && len(data) >= compressionThreshold {
		var b bytes.Buffer
		w, err := gzip.NewWriterLevel(&b, gzip.BestSpeed)
		if err != nil {
			return nil, err
		}
		if _, err = w.Write(data); err != nil {
			return nil, err
		}
		if err = w.Close(); err != nil {
			return nil, err
		}
		if b.Len() < len(data) {
			data, flags = b.Bytes(), 1
		}
	}
	if c.sent == ^uint64(0) {
		return nil, errors.New("channel exhausted")
	}
	c.sent++
	header := make([]byte, binaryHeaderSize)
	copy(header, "ASW2")
	header[4] = flags
	binary.BigEndian.PutUint64(header[5:], c.sent)
	return c.tx.Seal(header, nonce(c.sent), data, binaryAAD(header)), nil
}

func (c *Channel) OpenBinary(raw []byte, out any, allowCompression bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(raw) < binaryHeaderSize+c.rx.Overhead() || len(raw) > binaryHeaderSize+MaxPacket+c.rx.Overhead() {
		return errors.New("invalid binary packet size")
	}
	header := raw[:binaryHeaderSize]
	if string(header[:4]) != "ASW2" || header[4] > 1 || (header[4] == 1 && !allowCompression) {
		return errors.New("unsupported binary packet encoding")
	}
	seq := binary.BigEndian.Uint64(header[5:])
	if seq == 0 || seq != c.received+1 {
		return errors.New("invalid packet sequence or replay")
	}
	data, err := c.rx.Open(nil, nonce(seq), raw[binaryHeaderSize:], binaryAAD(header))
	if err != nil {
		return errors.New("channel authentication failed")
	}
	if header[4] == 1 {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return errors.New("invalid compressed payload")
		}
		data, err = io.ReadAll(io.LimitReader(r, MaxPacket+1))
		_ = r.Close()
		if err != nil {
			return errors.New("invalid compressed payload")
		}
	}
	if len(data) > MaxPacket {
		return errors.New("packet too large")
	}
	if err = json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid packet payload: %w", err)
	}
	c.received = seq
	return nil
}
