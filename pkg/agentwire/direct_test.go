package agentwire

import (
	"encoding/base64"
	"testing"
)

func TestDirectHelloProofBindsEveryField(t *testing.T) {
	_, key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	hello, err := SignDirectHello("secret-token", DirectHello{Protocol: DirectHelloProtocol, Nonce: nonce, PublicKey: key, ServerID: "server-one", MasterPublicKey: key, Timestamp: 123456})
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyDirectHello("secret-token", hello); err != nil {
		t.Fatal(err)
	}
	_, otherKey, _ := GenerateKey()
	cases := map[string]func(*DirectHello){
		"protocol":        func(h *DirectHello) { h.Protocol += "-other" },
		"nonce":           func(h *DirectHello) { h.Nonce = otherKey },
		"public key":      func(h *DirectHello) { h.PublicKey = otherKey },
		"server identity": func(h *DirectHello) { h.ServerID = "server-two" },
		"master identity": func(h *DirectHello) { h.MasterPublicKey = otherKey },
		"timestamp":       func(h *DirectHello) { h.Timestamp++ },
		"proof":           func(h *DirectHello) { h.Proof = nonce },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			modified := hello
			change(&modified)
			if VerifyDirectHello("secret-token", modified) == nil {
				t.Fatal("modified transcript accepted")
			}
		})
	}
	if VerifyDirectHello("other-token", hello) == nil || VerifyDirectHello("", hello) == nil {
		t.Fatal("wrong or empty token accepted")
	}
	for _, invalid := range []string{"", "abc", nonce + "=", nonce[:42] + "B", nonce + "\n"} {
		if ValidDirectNonce(invalid) {
			t.Fatalf("noncanonical nonce accepted: %q", invalid)
		}
	}
	badIdentity := hello
	badIdentity.ServerID = "one\ntwo"
	if _, err = SignDirectHello("secret-token", badIdentity); err == nil {
		t.Fatal("transcript delimiter injection allowed")
	}
}
