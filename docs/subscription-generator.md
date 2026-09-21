# Subscription Generator

The administrator workspace at `/subscription-generator` selects saved nodes,
filters by protocol and tags, and produces Clash/Mihomo, Surge, or Loon output.
The node library also links to this page with its selected node IDs.

Without a package instance, the source is enabled shared or administrator-owned
external/manual nodes. Managed inbounds require an existing package instance;
its current node restrictions, owner credentials, expiry, quota, and IP whitelist
apply. Every selected node must be available and compatible with the chosen
client. Invalid selections fail the request instead of silently dropping nodes.

Custom mode has 17 bundled common-domain/network categories, with balanced,
minimal, all, and empty presets. These are a finite set of inline rules, not
complete continuously updated service domain databases. Category order is fixed:
blocking/private rules precede service rules, domestic rules follow, and the
final fallback uses the selected proxy group. The UI exposes category routing
and the included rules in its tooltips. Full rule sets can be supplied through
the existing template mode. Custom mode bypasses global template/rule overrides;
template mode uses a matching saved template and its normal rule overrides.

## API

- `GET /api/subscription-generator?subscriptionId=...`: metadata-only candidate
  nodes, compatible formats, rule categories, and the current administrator's
  generated link history. No node passwords are included.
- `POST /api/subscription-generator`: takes `nodeIds` (1-500), `format`, `mode`
  (`custom` or `template`), `categories` or `templateId`, optional `subscriptionId`
  and `name`. Returns the configuration, MIME type, filename, and node count.
- `createLink: true` also requires `expiresInDays` (1-90). It saves a selection
  record and returns a token-bearing URL once. Only the token hash is persisted;
  the configuration and node credentials are not copied into the link record.
- `DELETE /api/subscription-generator/{id}` revokes the current administrator's
  generated link. History remains visible.
- `GET /api/generated-subscribe?token=...` regenerates current configuration.
  It rechecks node/source availability, package restrictions, parent token
  rotation, creator role/disable/token version, link expiry, and revocation.
  Expiry is capped by the parent package. This endpoint remains accessible
  through the hidden-entry guard using its own opaque credential.

File-only generation does not create a public link. Template records referenced
by live generated links cannot be deleted. Requests read the controller's saved
inventory and never issue Agent tasks or fetch external subscriptions/rule sets.

Configuration generation and parsing are covered by automated tests. Surge and
Loon output has not been verified in their native applications.
