# Subscription Template Management

`/templates` manages administrator-owned records in `policies`. The supported
types are Clash (YAML/JSON), Surge (INI), and Loon (INI). Existing records without
a type are treated as Clash. Client protocol compatibility is still enforced;
templates do not enable protocols a client cannot represent.

## Creation and Editing

The UI accepts file uploads, pasted content, a blank starting configuration,
a template URL, legacy V2 Clash configuration, or an existing workspace
subscription. URL imports are explicit one-time requests, limited to 1 MiB;
HTTPS is required except for loopback, and redirects are rejected. Templates
are not periodically fetched. Creation and preview do not contact Agents.

Imported complete configurations have their embedded node definitions removed.
References to those nodes become dynamic selectors. Clash supports existing
template expansion and rule overrides. Surge and Loon use `{{PROXY_NODES}}` in
`[Proxy Group]` to insert the current subscription's authorized node names;
`[Proxy]` is regenerated from those nodes. External proxy providers and native
remote proxy/include sections are rejected. Native groups are checked for
missing members and cyclic references. Other client-specific sections remain
in the document and should be reviewed before sharing a template.

Saves through template management preserve metadata and atomically store the
previous content in `_documentVersions`. `recordVersion` rejects stale edits.
Existing template types cannot be changed. Referenced templates cannot be
deleted until their subscription/rule bindings are removed.

## Selection and Visibility

Each client type can have one default. A subscription's matching explicit
binding wins; otherwise the matching format default is used. Clash templates
also apply to Stash. Temporary subscriptions bypass these templates.

`GET /api/templates/options` returns metadata only. Members receive only
templates marked `userVisible`. Public subscription requests can select a
visible matching template with `?template=<id>`. Visibility controls user
selection, not administrator-assigned subscription bindings or defaults.

Admin actions use `POST /api/actions`: `template.preview`, `template.import`,
`template.history`, `template.restore`, `template.default`, and
`template.visibility`. User links and authenticated previews use the same
template selection. Native client output is tested at the configuration level;
it has not been run in the Surge or Loon applications.
