package agentwire

import "testing"

func TestRoundTripReplayAndTampering(t *testing.T) {
	priv, pub, _ := GenerateKey()
	cli, e := NewClient(pub)
	if e != nil {
		t.Fatal(e)
	}
	srv, e := NewServer(priv, cli.PublicKey())
	if e != nil {
		t.Fatal(e)
	}
	p, _ := cli.Seal(Report{ServerID: "node", Token: "test-only-token"})
	var report Report
	if e = srv.Open(p, &report); e != nil || report.Token != "test-only-token" {
		t.Fatal(e, report)
	}
	if srv.Open(p, &report) == nil {
		t.Fatal("replayed report accepted")
	}
	reply, _ := srv.Seal(Reply{Interval: 5, Commands: []Command{{ID: "op", Action: "core.status"}}})
	var out Reply
	if e = cli.Open(reply, &out); e != nil || len(out.Commands) != 1 {
		t.Fatal(e, out)
	}
	bad, _ := cli.Seal(report)
	bad.Ciphertext = bad.Ciphertext[:len(bad.Ciphertext)-4] + "AAAA"
	if srv.Open(bad, &report) == nil {
		t.Fatal("tamper accepted")
	}
	wrong, _, _ := GenerateKey()
	wrongServer, _ := NewServer(wrong, cli.PublicKey())
	first, _ := NewClient(pub)
	packet, _ := first.Seal(report)
	if wrongServer.Open(packet, &report) == nil {
		t.Fatal("wrong master accepted")
	}
}
