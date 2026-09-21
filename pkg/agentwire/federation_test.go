package agentwire

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestClientStateRestoresCountersWithoutNonceReuse(t *testing.T) {
	private, public, _ := GenerateKey()
	client, e := NewClient(public)
	if e != nil {
		t.Fatal(e)
	}
	server, e := NewServer(private, client.PublicKey())
	if e != nil {
		t.Fatal(e)
	}
	packet, _ := client.Seal(map[string]any{"secret": "one"})
	state, e := client.ClientState()
	if e != nil {
		t.Fatal(e)
	}
	var request map[string]any
	if e = server.Open(packet, &request); e != nil {
		t.Fatal(e)
	}
	reply, _ := server.Seal(map[string]any{"secret": "reply"})
	restored, e := RestoreClient(public, state)
	if e != nil {
		t.Fatal(e)
	}
	var response map[string]any
	if e = restored.Open(reply, &response); e != nil {
		t.Fatal(e)
	}
	next, _ := restored.Seal(map[string]any{"secret": "two"})
	if next.Sequence != 2 {
		t.Fatal("restoration reused nonce sequence")
	}
	if e = server.Open(next, &request); e != nil {
		t.Fatal(e)
	}
}
func TestFederationSignatureAndStaticConsumerProof(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	agentPrivate, agentPublic, _ := GenerateKey()
	consumerPrivate, consumerPublic, _ := GenerateKey()
	grant := FederationGrant{Protocol: FederationProtocol, ID: "one", Revision: 1, AgentPublicKey: agentPublic, ConsumerPublicKey: consumerPublic, Namespace: "n", Actions: []string{"stats.get"}}
	signed, e := SignFederationGrant(grant, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyFederationGrant(signed); e != nil {
		t.Fatal(e)
	}
	signed.Grant.Actions = []string{"core.config.apply"}
	if VerifyFederationGrant(signed) == nil {
		t.Fatal("modified ACL accepted")
	}
	request := FederationRequest{Protocol: FederationProtocol, AgentPublicKey: agentPublic, ConsumerPublicKey: consumerPublic, Command: Command{ID: "operation", Action: "stats.get"}}
	request.Proof, e = FederationProof(consumerPrivate, agentPublic, request)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyFederationProof(agentPrivate, request); e != nil {
		t.Fatal(e)
	}
	request.Command.Action = "core.config.apply"
	if VerifyFederationProof(agentPrivate, request) == nil {
		t.Fatal("proof did not bind command")
	}
}
