# External Node Protocols

Node import accepts a list of share URIs (one per line), a Base64 URI subscription,
or Clash YAML/JSON (`proxies`, a proxy array, or one proxy object). Both preview and
commit accept `content`; the existing `lines` request field remains supported.
An import contains 1-500 nodes and commits atomically. Preview does not persist
records, contact nodes, or return their credentials.

Supported protocols: VMess, VLESS, Trojan, Shadowsocks, Hysteria v1/v2, SOCKS5,
HTTP(S), AnyTLS, Snell, TUIC, and WireGuard. VLESS/VMess/Trojan support TCP, WS,
and gRPC where the protocol/security combination permits them. Hysteria v1
requires numeric `up` and `down` bandwidth in Mbps. WireGuard supports a single
peer, local IPv4/IPv6, private/public/preshared keys, MTU, and reserved bytes.
TUIC and WireGuard are imported client configurations, not provisioned inbounds.

Clash/Mihomo is the primary output format. Other client outputs are filtered by
their protocol and option support; in particular WireGuard is currently Clash
only, and Snell is Clash/Surge only. Unsupported options produce errors instead
of being represented as REALITY nodes. Templates may rename/reorder authorized
nodes, but cannot inject nodes or change their connection parameters.

Imports and source sync normalize the connection settings before deduplication.
Identity includes credentials, transport, TLS, and protocol options. Hysteria v1
is never rewritten as Hysteria2. VMess cipher/alterId, WS Host/path, gRPC service,
TLS options, SOCKS username, SS plugins, TUIC options, and WireGuard keys survive
supported URI/Clash round trips. Private keys and protocol passwords are removed
from list/state/preview responses.

Plans and proxy speedtests accept supported external nodes. Speedtests still
require an explicit request and a paired runner. UDP protocols cannot be checked
with the direct TCP probe; use the proxy latency test. Importing, viewing, and
filtering nodes does not dispatch Agent tasks or download data from the nodes.

Managed inbound provisioning is documented in `managed-protocols.md`. Managed
outbounds and federation retain their separate REALITY profile. Importing an
external node does not allocate a listener or modify server configuration.

Verification covers parser/renderer round trips, API preview/atomic import,
deduplication, source sync, task serialization, output scope checks, and secret
redaction. Real network handshakes for every protocol require live compatible
servers and are not asserted by these tests.
