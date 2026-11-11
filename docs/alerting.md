# Alerting

Alerts come from four places: **thresholds** on metrics, **checks**, **host liveness** and a few **system conditions** (vulnerability findings, certificate expiry, storage, vulnerability database updates). All of them feed one state machine.

## State machine

```
 condition not OK        N consecutive failing evaluations       condition OK for resolve_count evaluations
      ─────────────▶ pending ───────────────────────────▶ firing ───────────────────────────────────▶ resolved
                       │ recovers first: dropped silently    │ warning -> critical: "escalated" (notifies again)
```

- **pending**: the condition is failing but has not yet failed `for_count` times (thresholds) or `failure_threshold` times (checks). A pending alert that recovers disappears without notification.
- **firing**: notifies the matching channels. A move from warning to critical (or, for certificates, to a later expiry stage) is an escalation and notifies again.
- **resolved**: after `resolve_count` consecutive OK evaluations (**Settings, Alerting**, default 1).
- A threshold alert whose metric stops being reported while the host is still reporting (for example an unmounted disk) is resolved automatically after 15 minutes.
- Alerts keep a timeline (fired, escalated, acked, expected, silenced, notified, flapping, resolved), kept for `alert_history_days` (default 180).

Severity is `warning` or `critical`. Channels choose a minimum severity.

## Thresholds

A rule has a metric, optional warn and crit values, `for_count` (consecutive samples, so "4 samples at a 30 s interval" is about two minutes), an enabled flag and an optional **label match** to target one instance (for example `disk` on mount `/data*`; globs allowed).

Inheritance, most specific first: **host, group, tenant, provider (global)**. At each level a rule with a matching label beats the wildcard rule. The first match wins as a whole (warn, crit and `for_count` are not merged field by field), and a disabled rule at a more specific level switches the metric off for that scope. The host page shows the merged view with the origin of each effective rule. Scope in the API is `global` (with `tenant_id` for tenant level), `group` or `host`.

Metrics where lower is worse (disk-fill forecast) alert at or below the value; all others at or above it. Warn must be less severe than crit.

### Metric catalog and defaults

| Key | Metric | Label | Unit | Warn | Crit | For | On |
|---|---|---|---|---|---|---|---|
| `cpu` | CPU usage | | % | 85 | 95 | 4 | yes |
| `memory` | Memory usage (excl. cache) | | % | 90 | 97 | 3 | yes |
| `swap` | Swap usage | | % | 60 | 85 | 4 | yes |
| `disk` | Disk usage | `mount` | % | 80 | 90 | 2 | yes |
| `inodes` | Inode usage | `mount` | % | 80 | 90 | 2 | yes |
| `disk_fill_hours` | Disk full in (linear fit over 24 h; lower is worse) | `mount` | h | 72 | 24 | 2 | yes |
| `load` | 1-minute load per CPU core | | | 2 | 4 | 4 | yes |
| `temperature` | Temperature | `sensor` | °C | 80 | 90 | 3 | yes |
| `net_errors` | Network errors | `iface` | /s | 10 | 100 | 3 | yes |
| `if_util` | SNMP interface utilisation (max of in/out) | `ifname` | % | 80 | 95 | 3 | yes |
| `security_updates` | Security updates pending | | | 1 | none | 1 | no |
| `reboot_required` | Reboot required | | | 1 | none | 1 | no |
| `bruteforce` | Failed logins from one IP in the window | | | 10 | 50 | 1 | yes |
| `portscan` | Distinct sources flagged as port scanners in the last 10 minutes (Linux) | | | 1 | none | 1 | yes |
| `container_restarts` | Container restarts since last collection | `container` | | 1 | 5 | 1 | yes |
| `host_down` | Seconds without contact (critical only) | | s | none | 120 | 1 | yes |
| `host_storage_mb` | Stored metric data for one host (checked nightly) | | MB | 512 | none | 1 | yes |

Rules are seeded on first start as provider-level rules and are edited under **Thresholds**. SNMP devices use at least 180 s for `host_down`.

## Checks

Create checks under **Checks** or `POST /api/v1/checks`. Common fields: `name`, `type`, `target`, optional `host_id`, `interval_seconds` (10 to 86400, default 60; certificates 6 h), `timeout_seconds` (default 10), `failure_threshold` (default 3, agent checks 2), `severity` (`warning` or `critical`, default critical), `config` (type-specific JSON).

| Type | Runs on | Target | Config |
|---|---|---|---|
| `ping` | server | host or IP | `count` (default 3) |
| `tcp` | server | `host:port` | |
| `http` | server | full http(s) URL | `method`, `headers`, `body`, `expect_status` (`200`, `2xx`, `200-299,301`; default 2xx/3xx), `keyword`, `keyword_absent`, `keyword_regex`, `follow_redirects`, `ignore_tls`, `basic_user`, `basic_password`, `max_latency_ms`, `check_cert` |
| `cert` | server | `host:port` | `server_name` (SNI), `allow_invalid`, `warn_days` 30, `notice_days` 14, `crit_days` 7 |
| `dns` | server | name | `record_type` (A, AAAA, CNAME, MX, TXT, NS), `resolver`, `expect` |
| `service` | agent host | service name (systemd unit or Windows service) | `state` (default running/active) |
| `process` | agent host | process name | `regex` |
| `port` | agent host | port number | `protocol` (`tcp` or `udp`) |
| `container` | agent host | container name or id prefix | `require_healthy` |
| `push` | none (the job calls in) | none; the server generates a URL | `grace_seconds` (default 300) |

Agent checks are evaluated from the state the agent reports and must be attached to an agent host; the other types may be standalone or attached to any host. Checks attached to an agentless "target" host drive that host's up/down status. Certificate expiry raises a separate alert that escalates at `warn_days`, `notice_days` and `crit_days` (critical at the last). Ping needs `cap_net_raw` on the server ([install.md](install.md)). **Run now** executes a check immediately.

### Push (heartbeat) checks

A push check inverts the direction: the monitored job (a cron entry, backup script or CI task) calls a URL, and the check goes down when no call arrives within `interval_seconds` plus `grace_seconds` (defaults 3600 and 300). Use it for anything that cannot be probed from outside.

The editor shows the URL, built from the configured server URL, with `curl` examples. The URL is `https://<server>/api/push/<token>`; `GET` and `POST` both work and every request records a beat. Optional query parameters: `status=up` (default) or `status=down` to report a failure at once, and `msg=` (up to 500 characters) shown as the last result. A new check waits one full interval plus grace for its first beat before it can go down. `failure_threshold` defaults to 1. **Run now** re-judges the check from its last beat.

```sh
curl -fsS -m 10 --retry 3 https://sentrel.example.com/api/push/<token>
curl -fsS -m 10 "https://sentrel.example.com/api/push/<token>?status=down&msg=backup+failed"
```

The endpoint needs no login; the token is the credential. It is 192 random bits, looked up by SHA-256 hash and compared in constant time. Unknown, malformed and disabled tokens all return the same 404, each token accepts 60 requests a minute (then 429), and a client that sends 30 unknown tokens in a minute is blocked for the rest of that minute. Only users with the monitoring permission see the URL; `POST /api/v1/checks/{id}/regenerate-token` (the editor's Regenerate button) issues a new one and the old one stops working at once.

## Dependencies

A host or a check can **depend on** a parent: another host or check in the same tenant (the "Depends on" picker in host Settings and in the check editor, or `parent_type` (`host`, `check` or empty to clear) and `parent_id` on `PUT /api/v1/hosts/{id}` and `/checks/{id}`). The server rejects unknown parents, parents in another tenant, self references and cycles, and a host cannot depend on one of its own checks.

While the parent is down (a host marked down, or a check past its failure threshold), alerts for the dependent are still raised, listed and recorded, but nothing is sent: the alert shows `suppressed_by` ("parent X is down") and the timeline records `silenced` with the same text. Fire, escalation, resolution and repeat notifications are all withheld. A check has one effective parent: its own if it names one, otherwise its host's. An explicit parent replaces the host's parent rather than adding to it, so a healthy explicit parent keeps alerts flowing while the host's parent is down, and clearing the check's parent restores inheritance. If an alert is still firing once the parent recovers it is not announced again unless its channel has repeats on; set `repeat_minutes` for that. Deleting a parent removes the link.

## Flap suppression

Each fire and resolve of an alert is a transition. When an alert records `flap_threshold` transitions (default 6) within `flap_window_minutes` (default 30) it is marked **flapping**: one "flapping" notification is sent, then fired, resolved, escalation and reminder notifications for it are paused. When a whole window passes without transitions, flapping ends ("state stable again") and normal notifications resume. Set the threshold to 0 to disable.

## Notification routing

- **Grouping**: events for the same channel arriving within `group_wait_seconds` (default 30) are sent as one message. A newer event for the same alert replaces an older queued one (fire plus resolve inside the window becomes one "resolved" item).
- **Delivery** is retried up to three times (5 s, then 10 s apart); results are in the notification log.
- **Repeats**: each channel has `repeat_minutes` (new channels default to `default_repeat_minutes` under Settings, Alerting; 240 out of the box). Unacknowledged, non-flapping, non-silenced firing alerts are re-sent at that interval; 0 disables repeats. Repeats stop when the alert is acknowledged (and resume if the acknowledgement is removed), resolved, muted, or suppressed by a maintenance window or a down parent. An alert that fired while suppressed and was never notified is sent once the suppression ends.
- **Filters** per channel: tenant (a channel in a tenant only sees that tenant's alerts), minimum severity (default warning), send-resolved, host IDs, group IDs, tags.

## Muting notifications

Every threshold rule has a `notify` flag (default on). When it is off, alerts raised by that rule still fire, appear in the alert list and timeline and are marked `muted`, but nothing is sent to notification channels for them: not on firing, escalation, flapping, resolution or reminders. Each skipped notification is recorded in the alert timeline as `silenced` with the detail "notifications disabled for this rule". Rules set the flag like any other field, so it follows the same inheritance (host, group, tenant, provider).

To mute one metric on a single host without editing the rule chain, use the toggle on the host page or `PUT /api/v1/hosts/{id}/notify` with `{"metric":"bruteforce","notify":false}`. This writes a host-level rule that copies the effective warning, critical, `for_count` and enabled values and changes only `notify`. `GET /api/v1/hosts/{id}/security` reports the effective setting for failed-login alerts as `notify_failed_logins` and for port-scan alerts (metric `portscan`) as `notify_portscan`.

## Acknowledgements

**Acknowledge** is the one action on an alert. It takes an optional note, stops the alert's repeat reminders and marks it handled. There is no manual resolve: an alert clears when its condition does. When a host or check is deleted its alerts are deleted with it.

- **If it comes back.** An acknowledged alert that clears and fires again within `flap_window_minutes` keeps its acknowledgement and note, and does not send a new "fired" notification. If it keeps returning it is marked flapping, which sends one notification (see [Flapping](#flapping)). Once it has been clear for longer than the window, the next fire is a new, unacknowledged alert.
- **This is expected.** Tick this when acknowledging an alert that is normal for you, such as a machine that is only switched on when needed. The alert moves from the **Active** tab to the **Expected** tab, is left out of the dashboard and host problem counts (a down host shows as "down (expected)"), and sends no notifications at all, however often it fires and clears. It stays that way until someone chooses **No longer expected** on the alert or in the Expected tab, which also works while the alert is clear. Its timeline still records each fire and resolve.
- **Undo.** **Unacknowledge** removes a plain acknowledgement, and reminders resume.

Several alerts can be acknowledged at once from the Active tab. Over the API: `POST /api/v1/alerts/{id}/ack` with `{"comment":"…","expected":true}`, `POST /api/v1/alerts/{id}/unack`, and `GET /api/v1/alerts?status=expected`.

## Maintenance windows

Scope: `all`, `tenant`, `group` or `host`. Types: one-off (start, end) or recurring `daily`, `weekly` (weekdays, Sunday is 0) or `monthly` (same day of month as the start), at `start_time` (HH:MM) in the window's timezone for `duration_minutes` (1 minute to 7 days).

- `suppress_alerts` (default on): alerts still evaluate and appear in the timeline (as "silenced"), but no notifications are sent for firing, escalation, resolution or reminders. Affected hosts show "in maintenance" and status pages show "maintenance".
- `allow_jobs` (default on): jobs scheduled "in maintenance window" (for example package upgrades) are released when a window that allows jobs becomes active for the host.

## Notification channels

Create channels under **Notifications**; **Test** sends a sample message. Secrets are never returned by the API.

| Type | Required config | Other config |
|---|---|---|
| `webhook` | `url` | `method`, `headers`, `template`, `content_type`, `username`/`password` (basic auth), `skip_verify` |
| `discord`, `slack`, `teams` | `url` (incoming webhook) | `skip_verify` |
| `telegram` | `bot_token`, `chat_id` | |
| `ntfy` | `topic` | `server` (default `https://ntfy.sh`), `token`, `priority` |
| `gotify` | `server`, `token` | `priority` |
| `pushover` | `token`, `user_key` | `priority` |
| `email` | `to` (list) | uses the SMTP relay from **Settings, Email** |

### Webhook template

Without a `template` the webhook receives this JSON (grouped alerts are in `alerts`):

```json
{"subject":"[CRITICAL] Disk usage / on web-1","status":"firing","severity":"critical",
 "alerts":[{"alert_id":42,"event":"fired","status":"firing","severity":"critical","title":"...","message":"...",
            "host":"web-1","host_id":7,"tenant":"","value":93.2,"threshold":90,"started_at":1760000000,
            "resolved_at":0,"url":"https://monitor.example.com/alerts/42","acked":false}],
 "url":"https://monitor.example.com/alerts","product":"Sentrel","sent_at":1760000030}
```

With a template, the body is rendered with Go `text/template` against the message. Fields use the Go names:

| Message | Meaning |
|---|---|
| `.Subject`, `.Status` (`firing`, `resolved`, `mixed`), `.Severity`, `.URL`, `.Product`, `.SentAt` | summary |
| `.Items` | list of alerts |

| Item (`range .Items`) | Meaning |
|---|---|
| `.AlertID`, `.Event` (`fired`, `resolved`, `escalated`, `flapping`, `reminder`, `test`), `.Status`, `.Severity` | identity and state |
| `.Title`, `.Message`, `.Host`, `.HostID`, `.Tenant` | description |
| `.Value`, `.Threshold` (nullable numbers), `.StartedAt`, `.ResolvedAt` (Unix seconds), `.URL`, `.Acked` | details |

Functions: `json` (encode a value as JSON), `upper`, `lower`, `time` (Unix seconds to RFC 3339), `value` (nullable number to string). Example for a chat service:

```
{"text": {{json .Subject}}, "alerts": [{{range $i, $a := .Items}}{{if $i}},{{end}}{{json $a.Title}}{{end}}]}
```

The template is validated when the channel is saved.
