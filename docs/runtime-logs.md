# Controller runtime log files

The log page reads JSON lines directly from managed files, never reconstructing
history from database audit or task rows. System events use `logs/aswired.log`,
scheduled executions use `logs/schedule.log`, and security events use
`logs/security.log` beneath the controller data directory. New audit events are
written only to files. Legacy database history is not re-imported after upgrade
or clearing files. Task dispatch/configuration state remains in the database.

Each Agent writes `logs/agent.log`, `logs/xray-access.log` and
`logs/xray-error.log` beneath its own data directory. The Agent tab selects a
server and stream and reads the corresponding real files over its encrypted
WebSocket, HTTP or Pull command channel. Agent execution begins/results include
action, task ID, status and duration without command input or configuration.
Log-read commands do not generate log entries or persist in task history.

Agent log synchronization is manual for all three streams. Opening the tab,
changing server/stream/line count, and the page auto-refresh timer do not dispatch
Agent reads. The administrator clicks **同步日志** or **同步日志文件** for one bounded
read; the UI displays its snapshot and synchronization time. Changing the scope
discards that snapshot and cancels the pending HTTP wait. A command already
delivered to the Agent may still finish. No background log mirror is maintained.
Cleanup uses the snapshot already returned by `logs.remove`, with the selected
line limit, instead of issuing another `logs.read`. A cleanup failure invalidates
the visible snapshot and requires manual synchronization to check the outcome.

Controller design principle: minimize Agent network traffic while preserving
required heartbeats, accurate accounting and control operations. Prefer bounded,
on-demand reads, reuse existing results, and avoid redundant requests driven by
browser polling. System, scheduled and security log refreshes read controller
files and do not fetch Agent log data.

Each file is limited to 50 MiB. Before the next record crosses that limit, the
controller archives the active file as `aswired-<20-digit Unix nanoseconds>.log`.
The newest five archives are retained. A single record over the limit is written
to stderr only. The directory and new files use permissions 0700 and 0600.

Administrators can use the **日志文件** panel on `/audit`:

- `GET /api/logs/entries?stream=system&limit=200` reads recent file lines.
  `stream` is `system`, `schedule` or `security`. Reads are bounded at 2000 lines
  and 2 MiB, newest first, with an explicit truncation flag.
- `GET /api/logs/files?stream=system` returns the real directory, file inventory, byte sizes,
  modification times, active-file flag and rotation limits.
- `POST /api/logs/files/remove?stream=system` accepts `{ "name": "aswired.log", "confirm": true }`
  for a single file, or `{ "all": true, "confirm": true }` for all managed files.
  The UI requires confirmation before either action.

Removing the active file truncates its contents while preserving the open writer.
Archives are deleted. Writes, rotation and cleanup share a mutex; the next write
continues at the new end of the file. Clearing all files operates on the inventory
at execution time, including archives created since the UI was refreshed.
Cleanup refreshes the visible lines and inventory together without creating a
replacement audit row. Cleanup is irreversible; an I/O error can leave a partially cleaned directory, so refresh
the inventory before retrying. Unrelated files and symlinks are never managed.

`POST /api/servers/{id}/logs` accepts `operation: read|remove`, `stream:
agent|xray-access|xray-error`, `limit`, and the same deletion scope/confirmation.
This administrator-only endpoint returns the Agent file inventory and lines.
An offline/unsupported Agent produces an explicit error, never cached task text.

Security controls are separate from event history. Administrator-only
`/api/security` endpoints manage temporary (one hour) or permanent IP bans and
manual IP/CIDR exemptions. Managed server IPs are exempt. Bans apply to login,
entry and public subscription routes, not Agent control or existing sessions.
Clearing security.log leaves these rules intact. Request IP follows the existing
ASWIRED_TRUSTED_PROXIES policy; forwarded addresses are ignored from untrusted peers.
