# REST API

Everything the web UI does goes through the REST API under `/api/v1`; there is no private UI-only interface. The machine-readable description is generated from the server's route table:

```sh
curl -s https://monitor.example.com/api/v1/openapi.json
```

It is an OpenAPI 3.0.3 document listing every path, method, query parameter, request and response schema, and the permission each operation requires. The UI also has an API page built from it.

Requests and responses are JSON (`Content-Type: application/json`). Errors have the shape `{"code":"forbidden","error":"..."}` with HTTP 400 (`bad_request`), 401 (`unauthorized`, `mfa_required`), 403 (`forbidden`, including CSRF failures), 404 (`not_found`), 409 (`conflict`, `confirmation_required`), 429 (`locked_out`) or 500. Successful writes return the object, or 204 with no body. Timestamps are Unix seconds. List endpoints accept filters such as `status`, `severity`, `host_id`, `limit` and `before` (see the OpenAPI document for each).

## Authentication

### API keys (for scripts and integrations)

Create a key in the UI (**API keys**) or with `POST /api/v1/api-keys` from a logged-in session (a key cannot create another key). The secret `sentrel_<prefix>_<secret>` is shown once.

```sh
export HB=https://monitor.example.com
export KEY=sentrel_abcd1234_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

curl -s -H "Authorization: Bearer $KEY" $HB/api/v1/hosts?status=down
```

A key acts as its owner, narrowed by its scopes. A key can never do more than its owner's role allows.

| Scope | Grants |
|---|---|
| `read` | view hosts, alerts, checks, metrics, vulnerabilities |
| `write` | read + acknowledge alerts, manage checks, thresholds, maintenance windows, channels, groups, status pages, vulnerability ignore, and host settings |
| `jobs` | read + create jobs (upgrades, IP blocks, vulnerability scans) |
| `admin` | everything the owner's role has, including users, tenants, settings and audit |

Scopes combine (`["read","jobs"]`). Optional `expires_days`. API-key requests do not need CSRF tokens. Revoke with `DELETE /api/v1/api-keys/{id}` or in the UI.

### Roles

| Role | Permissions |
|---|---|
| `admin` | all |
| `operator` | read, ack, monitoring, hosts, host settings, jobs |
| `viewer` | read |
| `tenant_admin` | read, ack, monitoring, host settings, jobs, users, branding, audit, all limited to their tenant |
| `tenant_viewer` | read, limited to their tenant |

The permission needed by each operation appears in its `description` in the OpenAPI document. See [security.md](security.md) for the full matrix.

### Session cookie and CSRF (what the UI uses)

```sh
curl -s -c jar -H 'Content-Type: application/json' $HB/api/v1/auth/login \
     -d '{"username":"admin","password":"..."}'
# response contains "csrf_token"; the cookie sentrel_session is stored in the jar
curl -s -b jar -H "X-CSRF-Token: <csrf_token>" -H 'Content-Type: application/json' \
     -X POST $HB/api/v1/alerts/42/ack -d '{"comment":"looking into it"}'
```

State-changing requests (anything except GET, HEAD, OPTIONS) authenticated by cookie must send the `X-CSRF-Token` header returned at login, otherwise they get 403. If the account needs a second factor, login returns `mfa_required` and further calls fail with 401 until `/auth/mfa/totp` (or the passkey endpoints) succeeds. Prefer API keys for automation.

## Examples

```sh
# Hosts and alerts
curl -s -H "Authorization: Bearer $KEY" "$HB/api/v1/hosts?q=web&kind=agent"
curl -s -H "Authorization: Bearer $KEY" "$HB/api/v1/alerts?status=active&severity=critical"

# Create an HTTP check (needs write scope)
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
     -X POST $HB/api/v1/checks -d '{
  "name": "shop homepage", "type": "http", "target": "https://shop.example.com/",
  "interval_seconds": 60, "failure_threshold": 3,
  "config": {"expect_status": "200", "keyword": "Add to cart", "max_latency_ms": 1500}}'

# Threshold override for one host and mount
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
     -X POST $HB/api/v1/thresholds -d '{
  "scope": "host", "scope_id": 7, "metric": "disk", "label_match": "/data*",
  "warn": 90, "crit": 97, "for_count": 2}'

# Acknowledge, then resolve
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -X POST $HB/api/v1/alerts/42/ack -d '{"comment":"deploying a fix"}'

# Maintenance window for host 7 for two hours
NOW=$(date +%s)
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -X POST $HB/api/v1/maintenance -d "{
  \"name\":\"kernel update\",\"scope\":\"host\",\"scope_ids\":[7],
  \"starts_at\":$NOW,\"ends_at\":$((NOW+7200)),\"recurrence\":\"none\",\"timezone\":\"UTC\"}"

# Dry-run an upgrade, then run it for real (needs the host's allow_upgrades and confirm)
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -X POST $HB/api/v1/jobs -d '{"host_id":7,"type":"upgrade","dry_run":true}'
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -X POST $HB/api/v1/jobs -d '{"host_id":7,"type":"upgrade","confirm":true,"schedule":"maintenance"}'

# Create an enrolment token (needs the admin scope; the response includes ready-to-run install commands)
curl -s -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -X POST $HB/api/v1/enrollment-tokens -d '{"ttl_minutes":60,"tags":["web"]}'
```

Overview bars: `GET /api/v1/hosts/beats?days=30` returns daily uptime per host (`{"<host_id>":[{"day":"2026-10-01","uptime":99.5}]}`, `uptime` is `null` without data, up to 90 days) and `GET /api/v1/checks/beats?limit=40` returns the latest results per check (`{"<check_id>":[{"t":1760000000,"ok":true,"latency_ms":12.3}]}`, oldest first, up to 100). Both accept `tenant_id` as provider users.

Job parameters: `upgrade` takes `params.packages` (comma separated) and `params.security_only`; `block_ip` and `unblock_ip` take `params.ip` (and `params.minutes` for blocks; the dedicated `POST /hosts/{id}/block` is simpler). Jobs return `queued`, `scheduled`, `sent`, `running`, `succeeded`, `failed`, `cancelled`, `expired` or `rejected`; poll `GET /jobs/{id}`.

## Live events

`GET /api/v1/events` is a server-sent-events stream (`alert.changed`, `host.updated`, `host.connected`, `job.updated`, `check.changed`, ...) filtered to what the caller may see. The UI uses it to refresh without polling; a proxy must not buffer it.

## Metrics

### Prometheus exposition: `GET /metrics`

Text format 0.0.4 with the latest value of every series, so an existing Prometheus can scrape Sentrel:

```yaml
scrape_configs:
  - job_name: sentrel
    scheme: https
    metrics_path: /metrics
    authorization:
      credentials: sentrel_abcd1234_xxxxxxxx      # API key with read scope
    static_configs:
      - targets: ['monitor.example.com']
```

Series are named `sentrel_<metric>` (for example `sentrel_cpu_usage_percent`, `sentrel_mem_used_percent`, `sentrel_disk_used_percent{mount="/"}`, `sentrel_check_up{check_id="3",check_type="http"}`), carry `host_id`, `tenant_id` and a `host` label with the host name, and are exposed as gauges. Also exposed: `sentrel_server_info{version}`, `sentrel_server_agents_connected` (provider users only) and `sentrel_alerts_firing{severity}`. A tenant-bound key sees only its tenant's series.

By default `/metrics` requires authentication and answers 401 without it. Use an API key with read scope. An administrator can turn off `metrics_auth` ("Require an API key for /metrics" under Settings, Security) for an intentionally public or trusted-network scrape endpoint; explicit existing opt-outs are preserved.

### PromQL: `GET /api/v1/metrics/query`

A range query over Sentrel's embedded TSDB. Parameters: `query`, `start`, `end` (Unix seconds; `start` also accepts a duration such as `6h` meaning "that long ago"), `step` (seconds or a duration). Tenant users are automatically restricted to their own series; provider users may add `tenant_id`.

```sh
curl -s -H "Authorization: Bearer $KEY" -G $HB/api/v1/metrics/query \
     --data-urlencode 'query=avg by (host) (sentrel_cpu_usage_percent)' \
     --data-urlencode 'start=6h' --data-urlencode 'step=300'
```

`GET /api/v1/metrics/names` lists available metric names; `GET /api/v1/hosts/{id}/metrics?panel=cpu|memory|load|disk|network|...` returns the series the host page graphs use.

### Metric export: `GET /api/v1/hosts/{id}/metrics/export`

Returns every standard graph series for one host (CPU, memory, swap, load, disk per mount, network per interface, temperatures and so on) as a file. Needs `read` scope and the host must be in your tenant (otherwise 404).

| Parameter | Meaning |
|---|---|
| `format` | `csv` (default) or `json` |
| `range` | Seconds back from now, for example `86400`. Alternatively give `start` and `end` (unix seconds) |
| `step` | Resolution as seconds or a duration (`60`, `5m`). Default is chosen from the range |

CSV has one row per timestamp: `timestamp` (ISO 8601 UTC), `unix`, then one column per series named `metric{label=value}`. JSON is `{host, start, end, step, series:[{name, labels, unit, points:[[unix, value]]}]}`. Both are sent as attachments. A request that would produce more than 50,000 rows is rejected with 400 and a suggested coarser `step`.

```sh
curl -s -H "Authorization: Bearer $KEY" "$HB/api/v1/hosts/12/metrics/export?format=csv&range=86400&step=300" -o web1.csv
```

### Public status pages

`GET /api/v1/public/status/{slug}` (add `?token=...` for token-protected pages) needs no authentication and returns only the labels and statuses chosen on the page. The UI route is `/status/{slug}`.
