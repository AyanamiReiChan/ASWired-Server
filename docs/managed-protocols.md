# Managed Protocols

Managed inbounds can be created from Nodes or the selected server's Xray dialog.
Saving creates an inbound and node projection. Publishing compiles the complete
server configuration using only active subscription credentials.

| Protocol | Transport/security | User updates |
| --- | --- | --- |
| VLESS | TCP/REALITY, TCP/WS/gRPC with TLS or none | Dynamic |
| VMess | TCP/WS/gRPC with TLS or none | Dynamic |
| Trojan | TCP/WS/gRPC with TLS | Dynamic |
| Shadowsocks | Traditional AEAD, TCP and UDP | Dynamic |
| Hysteria2 | QUIC/UDP with TLS, ALPN h3 | Dynamic |
| SOCKS5, HTTP | TCP with optional TLS | Core reload |
| AnyTLS | Verified Mihomo, TCP/TLS | Joint core/bridge publish |
| Snell v3/v4 | Verified Mihomo, TCP | Joint core/bridge publish |

TLS requires a certificate and key already deployed on the Agent, plus the
client-facing SNI. Use the existing certificate deployment workflow. WS paths,
Host headers, gRPC service names, ALPN and protocol options are projected into
subscriptions. VLESS Vision requires TCP and TLS/REALITY.

Upgrade the Agent before enabling Hysteria2, SOCKS/HTTP, or auxiliary protocols.
`managed_protocols_v2` includes Hysteria user accounting through statistics
wrappers and revalidation of cached QUIC identities for each new stream.
`managed_account_reload` enables SOCKS/HTTP credential synchronization.
Empty SOCKS/HTTP subscriptions retain an unguessable disabled account, never
anonymous access. Reloading these accounts interrupts existing connections.
SOCKS UDP forwarding is disabled because the core does not bind UDP packets to
authenticated managed accounts; subscriptions advertise TCP only.

AnyTLS/Snell require a locally configured Mihomo binary, pinned version and
SHA256. The controller checks the reported capability. Both currently support
TCP only and cannot enforce original-client-IP limits. Snell supports at most
one active subscription per listening port. Xray supplies the local VLESS
accounting bridge. Failed auxiliary publication rolls the core back; failure is
reported rather than presented as applied. Deleting an auxiliary inbound also
removes its listener and bridge.

TUIC, Hysteria1, SS2022 dynamic users and per-user WireGuard provisioning are not
enabled. External node import remains independent. Existing incomplete legacy
inbounds must be explicitly configured before publication.

Configuration tasks carry managed profile version 2. Before dispatch or retry,
the controller compares managed listeners and credentials with current records;
stale tasks cannot restore deleted inbounds or revoked subscriptions. User
reconciliation remains digest-based; unchanged credentials are not resent.

Validation: controller lifecycle tests cover all nine managed protocol types.
For the cross-repository runtime contract test, set `ASWIRED_PROTOCOL_FIXTURES`
to a temporary directory, run Server's `TestManagedProtocolsCreate`, then Agent's
`TestControllerCompiledProtocols` with the same directory. This runs actual
controller-produced native configurations and checks forwarding, revocation,
restoration and Hysteria accounting, including WS/gRPC variants. Auxiliary
network integration additionally requires the pinned `ASWIRED_TEST_MIHOMO`.
