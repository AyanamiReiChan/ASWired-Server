package agentwire

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func streamPair(t *testing.T) (*Channel, *Channel) {
	t.Helper()
	private, public, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(public)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(private, client.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestUnescapedPayloadRemainsLegacyCompatible(t *testing.T) {
	client, server := streamPair(t)
	want := "user>>>account>>>traffic>>>uplink<&>"
	packet, err := client.Seal(map[string]string{"value": want})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, _ := base64.RawURLEncoding.DecodeString(packet.Ciphertext)
	plain, err := server.rx.Open(nil, nonce(packet.Sequence), ciphertext, aad(packet.Sequence))
	if err != nil || !bytes.Contains(plain, []byte(want)) || bytes.Contains(plain, []byte(`\u003e`)) {
		t.Fatalf("payload not compact: %s %v", plain, err)
	}
	var got map[string]string
	if err := server.Open(packet, &got); err != nil || got["value"] != want {
		t.Fatal("legacy decoder failed", got, err)
	}
}

func TestStreamNegotiationAndFallback(t *testing.T) {
	for _, offer := range []*StreamOptions{nil, {Version: 1, Binary: true}, {Version: 2}} {
		if NegotiateStream(offer) != nil {
			t.Fatal("unsupported peer upgraded")
		}
	}
	selected := NegotiateStream(StreamOffer())
	if !selected.Valid() || selected.Compression != "gzip" || selected.HeartbeatSeconds != 15 || selected.TelemetrySeconds != 5 {
		t.Fatalf("bad selection: %+v", selected)
	}
	selected = NegotiateStream(&StreamOptions{Version: 2, Binary: true, Compression: "unknown"})
	if !selected.Valid() || selected.Compression != "" {
		t.Fatal("compression was not negotiated")
	}
}

func TestBinarySwitchCompressionReplayAndTampering(t *testing.T) {
	client, server := streamPair(t)
	hello, _ := client.Seal(Report{ServerID: "node", Stream: StreamOffer()})
	var report Report
	if err := server.Open(hello, &report); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"counters": strings.Repeat("user>>>test>>>traffic>>>uplink=1000;", 1000)}
	packet, err := client.SealBinary(want, true)
	if err != nil || packet[4] != 1 || binary.BigEndian.Uint64(packet[5:13]) != 2 || len(packet) > 2048 {
		t.Fatal("missing compression or sequence continuity", len(packet), err)
	}
	var got map[string]string
	if server.OpenBinary(packet, &got, false) == nil {
		t.Fatal("unnegotiated compression accepted")
	}
	tampered := append([]byte(nil), packet...)
	tampered[4] = 0
	if server.OpenBinary(tampered, &got, true) == nil {
		t.Fatal("unauthenticated flags accepted")
	}
	tampered = append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 1
	if server.OpenBinary(tampered, &got, true) == nil {
		t.Fatal("unauthenticated ciphertext accepted")
	}
	if err := server.OpenBinary(packet, &got, true); err != nil || got["counters"] != want["counters"] {
		t.Fatal("round trip failed", err)
	}
	if server.OpenBinary(packet, &got, true) == nil {
		t.Fatal("replay accepted")
	}
	small, _ := server.SealBinary(Reply{AckResults: []string{"task"}}, true)
	if small[4] != 0 {
		t.Fatal("small reply compressed")
	}
	var reply Reply
	if err := client.OpenBinary(small, &reply, false); err != nil || len(reply.AckResults) != 1 {
		t.Fatal("reply failed", reply, err)
	}
	for _, raw := range [][]byte{nil, []byte("ASW2"), packet[:13]} {
		if client.OpenBinary(raw, &reply, true) == nil {
			t.Fatal("truncated packet accepted")
		}
	}
}

func TestBinaryDecompressionLimitAndCorruptGzip(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		client, server := streamPair(t)
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		if corrupt {
			_, _ = w.Write([]byte(`{"ok":true}`))
		} else {
			_, _ = w.Write(bytes.Repeat([]byte(" "), MaxPacket+1))
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		compressed := b.Bytes()
		if corrupt {
			compressed = compressed[:len(compressed)-4]
		}
		header := make([]byte, binaryHeaderSize)
		copy(header, "ASW2")
		header[4] = 1
		binary.BigEndian.PutUint64(header[5:], 1)
		raw := client.tx.Seal(header, nonce(1), compressed, binaryAAD(header))
		var out any
		if server.OpenBinary(raw, &out, true) == nil {
			t.Fatal("oversized or corrupt compressed data accepted")
		}
		if server.received != 0 {
			t.Fatal("failed payload consumed sequence")
		}
	}
}
