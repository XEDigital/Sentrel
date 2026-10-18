# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Sentrel is pre-1.0, so any release may contain breaking changes; they are called out under "Changed" or "Removed" with migration notes.

## [Unreleased]

## [0.9.8] - 2026-10-18

### Fixed

- Windows agent install in self-signed TLS mode failed when run unattended (as SYSTEM from a scheduled task, GPO or remote management tool) with "There is no Runspace available to run scripts in this thread". The certificate pin check was a PowerShell script block, which .NET can call on a thread without a runspace. Both the generated install command and `install-agent.ps1` now use a compiled .NET class for the check (same SPKI pin, same behaviour), on Windows PowerShell 5.1 and PowerShell 7. Interactive installs were not affected.

### Removed

- `install-agent.ps1 -InsecureDownload`. It had not been generated since self-signed installs switched to certificate pinning, and now stops with an error pointing to `-PinSha256`.

## [0.9.7] - 2026-10-15

### Fixed

- Up-to-date agents showed "update available" and the Update agent button had no effect: release builds labelled the bundled agent `v0.9.6` while agents report `0.9.6`, so the versions never matched. With automatic agent updates on, this also queued a needless update job every hour. The bundled agent version is now read without the leading `v`.

### Changed

- Host Details: each label sits above its value. Short values share a row, and long ones such as CPU, IP addresses and connection use the full width.

## [0.9.6] - 2026-10-14

### Changed

- Web UI:
  - **Overview:** leads with active alerts, then affected hosts and checks, and shows the five most recent events.
  - **Navigation:** grouped into Monitor, Operations, Setup & routing, and Administration. Administration starts collapsed and the sidebar remembers collapsed sections.
  - **Host pages:** show every applicable tab directly, wrapping on small screens.
  - **Hosts list:** search and sorting stay visible and the detailed filters open on demand. Selecting hosts shows a separate bulk-action bar.
  - **Empty states:** tell "no data yet" apart from "no matches".
  - **Styling:** refined spacing, keyboard focus, mobile wrapping and theme styling.

## [0.9.5] - 2026-10-14

### Fixed

- Agent self-update on Linux failed with "staged update changed unexpectedly" on agents running 0.9.3 or 0.9.4. The installer's own `chmod` of the staged binary was mistaken for a replaced file.

### Upgrade notes

- Linux agents on 0.9.3 or 0.9.4 cannot update themselves to this release, because the update runs inside the installed agent. Update each of them once; later updates work from the UI again. Agents on 0.9.2 or earlier, and Windows agents, update normally.
  - Package installs: upgrade the package (`sudo apt install ./sentrel-agent_0.9.5_amd64.deb` or `sudo dnf upgrade ./sentrel-agent-0.9.5-1.x86_64.rpm`, using the file for your architecture).
  - Script installs: replace the binary and restart. Do not re-run the install command, which enrols the host again:

    ```sh
    curl -fsSLO https://github.com/XEDigital/Sentrel/releases/download/v0.9.5/sentrel-agent-linux-amd64
    curl -fsSLO https://github.com/XEDigital/Sentrel/releases/download/v0.9.5/SHA256SUMS
    sha256sum -c SHA256SUMS --ignore-missing
    sudo install -m 0755 sentrel-agent-linux-amd64 /usr/local/bin/sentrel-agent
    sudo systemctl restart sentrel-agent
    ```

    Use `sentrel-agent-linux-arm64` on ARM64.

## [0.9.4] - 2026-10-14

### Added

- [Roadmap](ROADMAP.md).

### Changed

- The project moved to https://github.com/XEDigital/Sentrel and the container image to `ghcr.io/xedigital/sentrel`. Old GitHub links redirect, and servers on 0.9.3 keep receiving updates. Docker users should switch the image name (see docs/install.md); `ghcr.io/packetghost99/sentrel` receives no further updates.

## [0.9.3] - 2026-10-14

Security release: fixes from an external review. Upgrading is recommended for every installation. Operator-signing users: see Removed.

### Security

- Agent enrolment in self-signed mode now verifies the server certificate against a trust pool holding only the pinned CA (chain, host name or IP, validity and server-auth usage), instead of accepting any chain that merely contained the CA. The CA returned at enrolment must also match the pin.
- A signed agent hello now updates the replay state only after the certificate chain, agent ID binding, revocation and host checks pass, so a forged hello can no longer make a legitimate reconnect look stale.
- Linux agent self-update: the root helper holds an exclusive lock in a root-only directory from staging to rollback, stages into a unique `O_EXCL` file in the root-owned install directory, and verifies, tests and installs that same file. `rollback-update` only works while a protected pending-update marker (written by `install-update`, within 15 minutes) exists; the new `confirm-update` verb clears it once the new version has connected.
- Operator signing no longer crosses the server trust boundary: the operator private key is never read by a page the server serves, so a compromised server cannot capture it. `sentrel-sign job` (alias `sign-job`) now decodes the job spec, prints the agent, job type, every parameter, dry-run flag, issue and expiry times and job id, rejects malformed, unknown-type and expired specs, requires typing `yes` (or `-yes`), and signs exactly the decoded bytes. `-json` gives machine-readable output.
- SSO accounts are bound to the provider's stable identity (OIDC issuer and `sub`, or the forward-auth header name and value) in a new `external_identities` table, not to a mutable username. A different subject with the same or colliding username no longer reuses an account, and a changed issuer does not bind to old users. Usernames, emails and names are refreshed on login. Existing `oidc` and `proxy` accounts with no identity are linked once at their next login. Forward-auth requires a stable, unique username from the proxy (docs/sso.md).
- A failed TLS reconfiguration no longer falls back to plain HTTP. The new certificate, key and bind are validated before listeners are swapped, a failure keeps or restores the last working configuration and is logged and audited, and if that fails too the server exits. `--force-http` remains the explicit recovery action.
- Stored monitoring credentials no longer appear in API responses. Checks and notification channels share one response serialiser for list, get, create, update and token regeneration: the check `basic_password`, credential-bearing headers (Authorization, Proxy-Authorization, Cookie, X-Api-Key and any header with token, secret, key, password or auth in its name), URL passwords, secret query parameters (token, key, secret, password, sig, signature, auth) and the path of Discord, Slack and Teams webhook URLs are shown as `********`. Sending `********` or leaving a secret out on update keeps the stored value, and audit entries never contain them.
- A check's own dependency now replaces its host's inherited parent instead of adding to it, matching the documentation.
- Moving a host to another tenant now also moves live alerts, queued notifications and cached checks, so the former tenant no longer receives alert content, events or notifications for it, and moves host-scoped threshold rules with the host. Threshold resolution, the merged view, listing and deletion ignore a host rule whose tenant does not own the host. Dependencies, host-scoped maintenance windows and update schedules of the former tenant are removed on transfer.
- A rejected host update (unauthorised or unknown tenant move, invalid field) no longer persists any other field; valid updates commit in one transaction and are audited once.
- `POST /checks/{id}/run` now needs the monitoring permission, shares the scheduler's concurrency limit and returns 409 when the check is already running.
- Disabled tenants no longer keep API access: one validity check (user enabled, tenant exists and is enabled, key not expired) now covers sessions, API keys and new logins. Re-enabling a tenant makes its keys work again. Scheduled checks and agents keep running during suspension (docs/security.md).
- Account security needs an interactive session: profile and password changes, TOTP and passkey changes, session listing and revocation and API-key create/list/revoke refuse API keys (HTTP 403 `interactive_session_required`). `revoke-others` can no longer select every session when called with a key.
- A forced password change is enforced: a flagged local account can only change its password, complete MFA, call `GET /auth/me` and log out (HTTP 403 `password_change_required`; the UI shows a change-password screen), and its API keys are rejected until the change.
- Recovery codes are consumed atomically (exactly one winner under concurrency) and a storage error no longer lets the login through.
- `PUT /users/{id}` validates every field (password, auth source, role, tenant) before writing, applies the change in one transaction, then audits and invalidates sessions.
- External accounts follow the directory on every login: LDAP and RADIUS recompute and save role and tenant from the current mappings and refuse an unmapped user with no default role. For LDAP, RADIUS, OIDC and forward-auth alike, a lowered role revokes the user's existing sessions, and a tenant change or removed access also revokes their API keys.
- API keys with an unknown prefix cost a SHA-256 comparison instead of a 64 MiB Argon2 hash, and over-long bearer tokens are rejected early.
- WebAuthn state is bounded: at most 16 cached origins (request hosts must be plain `host[:port]`) and 1000 outstanding challenges.

### Removed

- "Sign in browser" for operator-signed jobs. Sign with `sentrel-sign job` and paste the signature. If you ever selected your operator key in the browser, rotate it (see docs/agents.md, "Migrating from browser signing"). `sign-job` scripts now need `-yes`.

### Changed

- CI and release workflows use the current major versions of their GitHub Actions (Node 24 runtimes).
- CI: the build and test job has read-only repository access; signing and publishing run in a separate release job, only for version tags.
- Security reports go through GitHub private vulnerability reporting (SECURITY.md).

## [0.9.2] - 2026-10-14

### Added

- `sentrel-loadtest` (`cmd/sentrel-loadtest`): a development tool that simulates many agents against a test server, and a Capacity section in the operations docs with measured CPU, memory and API latency from 50 to 4,000 simulated agents.
- Push (heartbeat) checks: a new `push` check type with a secret URL, `GET`/`POST /api/push/{token}?status=up|down&msg=...`. The check goes down when no beat arrives within the interval plus grace (defaults 3600 s and 300 s). Tokens are 192 random bits, looked up by hash and compared in constant time, unknown tokens all return 404, and requests are rate-limited per token and per client. The editor shows the URL, `curl` examples and a Regenerate button; API `POST /checks/{id}/regenerate-token`.
- Dependencies: hosts and checks can name a parent host or check in the same tenant (cycles are rejected). While the parent is down, dependent alerts are still raised and shown as "suppressed: parent X is down" but are not notified, including repeats. "Depends on" pickers in host Settings and the check editor; `parent_type`/`parent_id` on host and check updates.
- Repeat notification help text: the per-channel repeat interval (and the global default in Settings, Alerting) now documents that repeats stop on acknowledgement, resolution, muting and suppression.
- Disk health for Linux agents: SMART (through the new root helper verb `priv smart`, needs smartmontools), software RAID from `/proc/mdstat` and ZFS pools, collected every 30 minutes. A Disk health card on the host System tab, SMART metrics, and alerts for failed SMART, a rising bad-sector count, NVMe wear at 90% or more, degraded md arrays and ZFS pools that are not online. API `GET /hosts/{id}/disk-health`. Windows is not covered.
- Update schedules (auto-patching): recurring daily, weekly, monthly or maintenance-window upgrade jobs per scope, security updates only by default, never rebooting. Hosts with upgrades off, read-only agents and operator-signed agents are skipped and listed in the last run. A maintenance-window schedule queues at most one job per host every 12 hours. Jobs, Schedules now holds both update and scan schedules; API `/update-schedules`.
- CI security scanning: CodeQL, gosec, govulncheck and `npm audit` on every push and weekly, and Dependabot for Go modules, npm and GitHub Actions.

### Changed

- Less cluttered web UI:
  - Explanations moved behind (i) tooltips.
  - Host security, upgrade and cleanup settings moved into a Configure panel, as one compact row each with a Default or Custom marker.
  - Global Settings has a grouped section list, and sign-in providers hide their fields until enabled.
  - The dashboard has a single Health card.
  - Stat cards are equal height.
  - Chart legends use readable series names.
  - Host lists, host pages and dashboards fit phone screens.
- Go 1.26.9.
- Dependabot no longer opens major-version updates; those are done by hand with testing.

### Fixed

- Exported chart PNGs were blank: the image was captured before the chart had drawn.
- Restoring a backup caps the size of each restored file.

## [0.9.1] - 2026-10-13

### Added

- Update notifications: the server checks the latest GitHub release every 6 hours (and on demand) and shows a green "Update vX.Y.Z" pill next to the version in the sidebar and a one-time dismissible banner, both for administrators only. Settings, Updates shows the release notes, the install method and a "Check now" button. The check sends only a `User-Agent` and an ETag; turn it off in Settings, Updates or with `SENTREL_DISABLE_UPDATE_CHECK=1`.
- One-click, signed server updates for systemd installs. The server downloads and verifies the release, then a root-owned updater (`sentrel-updater.path` and `.service`, installed by `install-server.sh`) re-verifies the Ed25519 signature with the key compiled into the installed binary, refuses downgrades, swaps the binary, restarts, checks health for up to 90 seconds and rolls back on failure. Disable with `SENTREL_DISABLE_SELF_UPDATE=1`. Docker and package installs show the exact `docker pull` or `apt`/`dnf` commands instead.
- Release `SHA256SUMS.sig` verification shared with `sentrel-sign` in `internal/release`; the public key is the trust root and cannot be overridden at run time.
- API: `GET /server/updates`, `POST /server/updates/check`, `POST /server/updates/install`, `GET /server/updates/status`; audit entries `server.update_requested`, `server.update_applied`, `server.update_rolled_back`.
- `scripts/dev-deploy.sh` defaults to the next patch version after the latest tag with `-dev` and installs the updater units.

### Changed

- Documentation no longer says Sentrel never calls out: the version check is the one automatic outbound request, and it can be disabled.

## [0.9.0] - 2026-10-13

First public release.

### Added

- Monitoring server, agent and web UI: one server binary with embedded UI, SQLite state, embedded Prometheus time-series store and internal certificate authority; agents for Linux (amd64, arm64) and Windows (amd64) that connect outbound over gRPC.
- Agent metrics, services, listening ports, processes, Docker containers, package inventory and security events; server-side checks (ping, TCP, HTTP, certificate expiry, DNS) and agent-evaluated checks (service, process, port, container); SNMP v2c/v3 with YAML device profiles; agentless target hosts.
- Alerting: inherited thresholds, flap detection, grouping, acknowledgements, maintenance windows, and notification channels (webhook, Discord, Slack, Teams, Telegram, ntfy, Gotify, Pushover, email).
- Public and token-protected status pages, Prometheus `/metrics`, tenant-scoped PromQL API, REST API with API keys and OpenAPI document.
- Multi-tenancy with roles, per-tenant branding, LDAP and RADIUS sign-in, TOTP and passkeys, audit log.
- Signed remote jobs (package upgrades, IP blocks, agent self-update with rollback), each off by default per host.
- Backup and restore CLI and UI.
- Documentation, CONTRIBUTING with DCO, GitHub Actions CI and signed releases.
- Windows agent fixes (read-only service enumeration, per-user installed applications, clearer message when the Security log is unreadable) and an MSI installer built from `deploy/windows/agent.wxs` when `wixl` is available.
- Redesigned web UI: light theme by default with dark toggle, beat bars and uptime pills for hosts and checks, refreshed dashboard, self-hosted Inter font.
- Port-scan detection on Linux (nftables): a detection-only kernel chain counts SYNs to closed ports per source, the agent polls the result, and flagged sources raise a `portscan` alert and can be auto-blocked. Windows is not yet supported.
- Per-rule notification muting and a host toggle for failed-logon alerts.
- Disk usage analysis (run automatically when disk alerts fire) and opt-in disk cleanup jobs for Linux and Windows.
- Vulnerability findings show the available fixed version and can queue an upgrade to it.
- Agent write policy (`server`, `operator`, read-only), set only on the host. Operator-signed jobs use a second Ed25519 signature made offline or in the browser (`sentrel-sign`).
- OpenID Connect login and forward-auth header login.
- Optional CVE scanning: Grype matching is off by default, and the database is only downloaded when you enable it.
- Agents page (`/agents`): create an enrolment token with a write policy, pick a platform and architecture, and copy a one-liner or download the `.deb`, `.rpm` or `.msi` from this server with the exact follow-up commands. Shows agents by version and write policy and lists outdated hosts with an Update action. `GET /api/v1/agents/install-info` and `GET /download/agent/pkg/{file}` back it; `scripts/build.sh` embeds the agent packages (not the server ones) with a manifest when `nfpm` and `wixl` are present.
- Self-signed TLS mode: generated install commands pin the server certificate (`curl --pinnedpubkey`, `install-agent.sh --pin-sha256`, `install-agent.ps1 -PinSha256`) instead of disabling certificate checks.
- `.deb` and `.rpm` packages for the server and agent, a multi-arch container image on GHCR, cosign-signed release checksums and SPDX SBOMs.
- Resource usage measurements in `docs/operations.md`.
- `SECURITY.md`, `docs/threat-model.md`, `docs/comparison.md`.

### Security

Fixes from an internal security review:

- The Linux privileged helper no longer follows symlinks when writing or changing ownership of state as root (agent user to root escalation).
- The Windows agent data folder is restricted to SYSTEM and Administrators; updates are staged in a protected directory and verified from a private copy.
- SSRF guard for tenant-owned checks and notification channels, applied after DNS resolution.
- A trusted-proxy list for client IP and scheme headers.

- Replay state for agent hellos and job IDs persists across restarts.
- Disk usage analysis is limited to mount points; logout cookie flags corrected; job-cancel events carry tenant tags; hardened systemd unit for the server.
- Added a test that calls every `{id}` route as a user from another tenant, and a live-event tenancy test.

[Unreleased]: https://github.com/XEDigital/Sentrel/commits/main
