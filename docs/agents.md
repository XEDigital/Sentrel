# Agents

The agent (`sentrel-agent`) is a single static binary for Linux (amd64, arm64) and Windows (amd64). It makes one outbound gRPC connection to the server, reconnects with exponential backoff (2 s up to 60 s, with jitter), buffers metric batches while offline, and applies the configuration the server sends.

## Installing

Open **Agents** in the sidebar (also reachable from **Add host**). The page walks through four steps:

1. **Enrolment**: create a one-time token (valid 1 hour, 24 hours or 7 days) with an optional display name, group and tags, a write policy (Standard, Operator-signed with your operator public key, or Read-only) and, on Linux, whether to monitor Docker containers (root-equivalent, off by default).
2. **Platform**: Ubuntu/Debian, RHEL/Rocky/Alma/Fedora, other Linux, or Windows, and x86-64 or ARM64.
3. **Install**: a one-liner to paste, or the package from this server with its size, SHA-256 and the exact follow-up commands.
4. **Waiting for the agent**: the page polls the host list and shows "Connected: host" when the agent appears.

A banner shows how the connection is verified (public certificate, pinned self-signed certificate, or a warning for plain HTTP), and warns when the server's public URL is unset or points at localhost. The top of the page counts agents by version and write policy and lists outdated hosts with an **Update** action (it uses the same update job as the host page, so operator-signed hosts wait for your signature and read-only hosts must be reinstalled).

Registration generates an ECDSA P-256 key on the host, sends a CSR plus the token, and receives a client certificate, the CA certificate and the server's job-verification public key.

### Packages

If the server was built with `nfpm` and `wixl` (see [development.md](development.md)), it embeds the agent packages and serves them without authentication from `/download/agent/pkg/<file>` (only files listed in the build manifest; anything else is 404). `GET /api/v1/agents/install-info` lists them with size, SHA-256 and URL, together with the server URL, TLS mode and, in self-signed mode, the CA fingerprint and the server certificate's pin. Server packages are not embedded.

```sh
# Debian / Ubuntu                                   # RHEL family
sudo apt install ./sentrel-agent_X_amd64.deb        sudo dnf install ./sentrel-agent-X.x86_64.rpm
sudo sentrel-agent register --server https://monitor.example.com --token ABCD-1234-EFGH
sudo systemctl enable --now sentrel-agent
```

```powershell
msiexec /i sentrel-agent-X-x64.msi SERVER=https://monitor.example.com TOKEN=ABCD-1234-EFGH /qn
```

Add `--ca-fingerprint FP` (`CAFINGERPRINT=FP` for the MSI) in self-signed mode, `--write-jobs operator --operator-key KEY` or `--write-jobs none` for a write policy (`WRITEJOBS=` and `OPERATORKEY=` for the MSI). A package-based Docker setup needs `sudo usermod -aG docker sentrel-agent` before starting the service.

### Self-signed certificates: pinning

In `selfsigned` TLS mode the generated commands never disable certificate checks. The installer is fetched with `curl -fsSL -k --pinnedpubkey "sha256//<spki>"`, where `<spki>` is the base64 SHA-256 of the server certificate's public key, and the same pin is passed on as `--pin-sha256` (`-PinSha256` on Windows) so the binary download is pinned too. `--ca-fingerprint` then pins the CA at registration. The pin changes when the server certificate is regenerated (name change, or less than 30 days left); copy a fresh command from the Agents page. `wget` cannot pin a key, so `--pin-sha256` requires `curl`. On Windows the pin is checked by a small compiled .NET class (`SentrelPin`) rather than a PowerShell script block, so the command also works unattended, for example as SYSTEM from a scheduled task, GPO or remote management tool. The Linux `--insecure-download` option remains for old scripts but is no longer generated; Windows `-InsecureDownload` was removed and now stops with an error pointing to `-PinSha256`.

### Linux

Requires systemd. Run as root:

```sh
curl -fsSL https://monitor.example.com/install/agent.sh | sudo sh -s -- --server https://monitor.example.com --token ABCD-1234-EFGH
```

| Option | Meaning |
|---|---|
| `--server URL`, `--token TOKEN` | required |
| `--ca-fingerprint FP` | pin the server CA (self-signed TLS mode; the UI adds it for you) |
| `--name NAME` | display name |
| `--binary PATH` | use a local binary instead of downloading from `<server>/download/agent/linux/<arch>` |
| `--docker` | opt in: add the agent user to the `docker` group so containers can be monitored (root-equivalent, off by default) |
| `--pin-sha256 B64` | self-signed mode: verify the server certificate by the base64 SHA-256 of its public key for every download (needs curl) |
| `--insecure-download` | deprecated, no longer generated: skip TLS verification for the binary download only |
| `--uninstall` | remove the agent |

The installer: creates the system user `sentrel-agent` and adds it to the `adm`, `systemd-journal` and (only with `--docker`) `docker` groups; installs `/usr/local/bin/sentrel-agent`; writes `/etc/sentrel-agent/agent.yaml`, `/etc/sentrel-agent/job.pub` (root-owned) and state in `/var/lib/sentrel-agent` (`0700`); validates and installs the sudoers rule `/etc/sudoers.d/sentrel-agent` (validated before registering, so a failure does not burn the token); installs the unit `sentrel-agent.service` (`MemoryMax=192M`, `CPUQuota=25%`, `Nice=10`, `Restart=always`).

### Windows

From an elevated PowerShell:

```powershell
& ([scriptblock]::Create((irm https://monitor.example.com/install/agent.ps1))) -Server https://monitor.example.com -Token ABCD-1234-EFGH
```

Parameters: `-Server`, `-Token`, `-CaFingerprint`, `-BinaryPath`, `-Name`, `-WriteJobs`, `-ReadOnly`, `-OperatorKey`, `-PinSha256`, `-Uninstall`. The script installs to `C:\Program Files\Sentrel Agent\sentrel-agent.exe`, keeps config and keys in `C:\ProgramData\Sentrel Agent` (restricted to SYSTEM and Administrators), registers the `SentrelAgent` service (automatic delayed start, restart on failure) and starts it.

For fleet deployment an MSI is built (`msiexec /i sentrel-agent-<version>-x64.msi SERVER=https://monitor.example.com TOKEN=ABCD-1234-EFGH /qn`). `scripts/build.sh` builds it from `deploy/windows/agent.wxs` when `wixl` (msitools) is installed; otherwise the release has no MSI. Optional properties: `CAFINGERPRINT`, `NAME`, `WRITEJOBS=server|operator|none` and `OPERATORKEY=<key>[,<key>...]`.

### Manual install

Run `sentrel-agent register SERVER_URL TOKEN [--ca-fingerprint FP] [--name NAME] [--write-jobs server|operator|none] [--operator-key B64]... [--read-only] [--config FILE] [--state-dir DIR]`, then `sentrel-agent service install` and `service start` on Windows, or run `sentrel-agent run` under your own supervisor.

## Collected data

Intervals and switches come from **Settings, Agents**, overridable per host (Settings tab for collection, Security and Packages tabs for the rest). Defaults: collect every 30 s; inventory hourly; top 10 processes; services, listening ports, Docker and temperatures on; security scan every 60 s.

| Data | Details |
|---|---|
| Host info | hostname, OS, platform and version, kernel, architecture, CPU model and cores, memory, boot time, IP addresses, virtualisation, `os-release` ID |
| Metrics | CPU total/iowait/steal, memory, swap, load 1/5/15 and per core, disk used/total and I/O, inode usage, disk-full ETA, network throughput and errors, temperatures, process count, uptime, agent CPU and memory |
| State | services (systemd units or Windows services; all, or only watched ones), listening ports, top processes and the list of process names, Docker containers (state, health, restarts, CPU, memory), reboot-required flag |
| Inventory | installed and upgradable packages (apt, dnf, yum, zypper, pacman, apk) with security flags; on Windows installed applications and pending Windows Updates |
| Security | failed SSH logins from `auth.log`/`secure` or journald (Linux), failed logons event 4625 (Windows), fail2ban jails, active IP blocks |

Services named in `service` checks are always reported even when service collection is off.

## Privilege model

**Linux.** The agent runs as the unprivileged user `sentrel-agent`. Anything needing root goes through `sudo -n /usr/local/bin/sentrel-agent priv <verb>`, and the only sudo rule is:

```
sentrel-agent ALL=(root) NOPASSWD: /usr/local/bin/sentrel-agent priv *
```

The helper validates its own arguments. Verbs: `pkg-refresh`, `pkg-upgrade`, `block-ip`, `unblock-ip`, `list-blocks`, `scan-sync`, `scan-list`, `scan-off`, `fail2ban-status`, `smart`, `disk-usage`, `disk-cleanup`, `install-update`, `rollback-update`, `confirm-update`. Package names and versions are matched against strict patterns, IPs must parse and not be loopback or unspecified, block durations are 1 to 129600 minutes, and update files must be regular files inside the agent state directory, verified against the root-owned key (`/etc/sentrel-agent/job.pub`). Package upgrades run in their own `systemd-run --scope` unit, so they are outside the agent's CPU and memory limits and survive an agent restart.

IP blocking uses an `inet sentrel` nftables table with timeout sets (and falls back to iptables/ip6tables rules tagged `sentrel-block:<expiry>`). Uninstalling removes the nftables table.

### Port-scan detection (Linux)

The same `inet sentrel` table also holds the port-scan detector. The kernel does the work; the agent only keeps the list of open ports current and reads the result back.

- `priv scan-sync PORTS [--threshold N] [--allow IP,CIDR,...]` creates (idempotently, in one atomic nft transaction) the sets `open_tcp`, `scanners4`/`scanners6` (timeout 10 minutes), `probe4`/`probe6` (per-source meters, 1 minute), `allow4`/`allow6` and the chain `scan`, and replaces `open_tcp` and the allowlist. `PORTS` is `-` or a comma-separated list of ports 1-65535; every argument is validated strictly and nothing goes through a shell. `priv scan-list` prints the flagged sources and their remaining timeout as JSON. `priv scan-off` removes the chain and sets (the block lists are never touched).
- The chain hooks `input` at priority -5 (after the block list at -10, so blocked sources are not counted, and before the usual firewall priority 0) with policy `accept`. It only counts: it contains no `drop`, `reject`, NAT or mangle statement, so it can never change traffic. For TCP SYNs that are not from loopback, not to a port in `open_tcp` and not from an allowlisted address, a per-source meter (`limit rate over N/minute`, burst N) adds the source to `scanners4`/`scanners6`; every further probe refreshes its 10-minute timeout. It does not use conntrack. UDP is not tracked.
- The agent reads `/proc/net/tcp` and `/proc/net/tcp6` every 30 seconds and calls `scan-sync` when the set of listening ports (or the threshold or allowlist) changed, at most once a minute (a service started in the last minute can be counted as closed until then). It calls `scan-list` every 30 seconds and reports a source when first seen and again every 5 minutes while it keeps scanning. The Sentrel server's address, loopback and the allowlist are excluded.
- Settings: `portscan_enabled` (default on), `portscan_threshold_per_min` (default 20) and `portscan_allowlist` (CIDRs) in agent defaults. A host inherits them and can override the first two on its Security tab, Port-scan detection. Addresses on the never-block list are also passed to the agent and never flagged. Disabling removes the rules.
- Requirements: `nft` installed and a kernel with nftables dynamic sets and meters (Linux 4.x or newer with nf_tables). Otherwise the host reports `portscan_supported=false` with the reason and the UI shows "not available on this host". There is no iptables fallback. Windows hosts report "not yet supported on Windows".

Note that membership of the `docker` group is equivalent to root on the host; for that reason the installer does not add the agent to it unless you pass `--docker`. Without it container monitoring is unavailable; to enable it later run `sudo usermod -aG docker sentrel-agent && sudo systemctl restart sentrel-agent`.

**Windows.** The service runs as LocalSystem (the default for a service without an account), so there is no privilege boundary: upgrades install Windows Updates through the Windows Update API, blocks are Windows Firewall rules named `Sentrel block <ip>`.

Remote actions (upgrade, IP block, disk cleanup) are governed by permission settings with global defaults (upgrades off, cleanup and IP blocking on) that each host inherits or overrides on its Packages, Storage and Security views; see [security.md](security.md#privilege-boundary-and-opt-in-remote-actions).

## Scheduled updates

Jobs, Schedules, **Update schedules** queue package upgrades on a recurring basis. A schedule has a scope (`all`, `tenant`, `group` or `host`), a name, and one of four timings: `daily`, `weekly` (weekday 0 to 6, Sunday is 0), `monthly` (day 1 to 28) or `maintenance`. Times use the timezone set under Settings, General. A daily, weekly or monthly schedule fires once, after its time on a matching day. A `maintenance` schedule queues one upgrade job per host and holds it until the host's next maintenance window that allows jobs opens; it queues another only after the previous one finishes, fails or expires.

By default only security updates are installed (`security_only`); choose all updates to install everything pending. Schedules never reboot hosts.

Each run records how many jobs it queued and which hosts it skipped, with the reason: nothing to install, remote upgrades not enabled for the host, a read-only agent, or an agent that requires operator-signed jobs. The jobs run as `system:update-schedule:<id>` and show in the job history. The API is `/update-schedules`; creating, editing and deleting need the `jobs` permission and are audited as `update.schedule_created`, `update.schedule_updated` and `update.schedule_deleted`.

## Write policy: read-only and operator-signed agents

By default the server's signature is enough for any job. To limit what a compromised server could do to a host, choose a write policy when you install (it can only be changed locally, by re-registering or editing the root-owned `agent.yaml`; the server cannot change it):

- `--read-only` (same as `--write-jobs none`): the agent runs only SAFE jobs (`refresh_inventory`, `collect_now`, `disk_usage`, `unblock_ip`) and answers every other job with `rejected: agent is read-only`.
- `--write-jobs operator --operator-key KEY`: jobs that change the host also need a signature from an operator key. `--operator-key` can be repeated (the installers accept a list; the MSI property takes a comma-separated list).

Linux: `curl -fsSL https://SERVER/install/agent.sh | sudo sh -s -- --server https://SERVER --token TOKEN --write-jobs operator --operator-key KEY` (or `--read-only`). Windows: `-WriteJobs operator -OperatorKey KEY` or `-ReadOnly`.

### Operator workflow

1. On a trusted machine (not the server): `sentrel-sign keygen-operator -out operator.key`. This writes the private key (PKCS#8 PEM, mode 0600) and `operator.key.pub`, and prints the public key and its 16-character key id. Keep the private key safe and offline.
2. Install agents with `--write-jobs operator --operator-key <public key>`. The host page shows an "Operator-signed jobs" badge and lists the key ids the agent reported.
3. Start any WRITE action (upgrade, disk cleanup, IP block, agent update) as usual. The job is created with status `awaiting_signature` and is not sent. On a read-only host the server answers `403`.
4. Sign it offline, on your own machine: run `sentrel-sign job -key operator.key -spec <base64 spec>` (the job page shows a copy-ready command; the spec is also returned by `GET /api/v1/jobs/{id}/spec`, and `-spec` accepts a file containing it). The tool decodes the exact bytes and prints the job id, agent id, job type, every parameter, dry-run flag, issued and expiry times and timeout, then asks you to type `yes`. Compare this with what you meant to run: the job page's summary comes from the server, the tool's output comes from the bytes being signed. It refuses malformed specs, unknown job types and expired specs. For scripts use `-yes`, and `-json` for machine-readable output. Then paste the printed signature on the job page, or `POST /api/v1/jobs/{id}/operator-signature` with `{"signature": "...", "key_id": ""}`.

   Operator keys are never entered into the web UI: a compromised server could replace the page and capture the key.
5. The server checks the signature against the keys the agent reported, queues the job and sends it with both signatures. Unsigned jobs expire (24 hours by default).

The server's job signature is still required. Hosts on `operator` or `none` are skipped by automatic updates; update them with an explicit job.

**Migrating from browser signing.** Earlier versions offered "Sign in browser", which read `operator.key` into the page served by the server. That option has been removed. Nothing changes for your agents or public keys, but if you ever selected the key file in that page, treat it as exposed to the server: run `sentrel-sign keygen-operator -out operator2.key`, reinstall or reconfigure the agents with the new `--operator-key` (keep the old key listed only while you transition), then discard the old key. From now on sign with `sentrel-sign job` (`sign-job` still works as an alias, but now shows the job and asks for `yes`; scripts need `-yes`).

Config keys (`agent.yaml`): `write_jobs: server|operator|none` and `operator_keys: [base64 raw Ed25519 public keys]`.

## Configuration file

`/etc/sentrel-agent/agent.yaml` (Windows: `C:\ProgramData\Sentrel Agent\agent.yaml`) is written by `register`:

```yaml
server_url: https://monitor.example.com
agent_id: 1b3c...-uuid
state_dir: /var/lib/sentrel-agent
ca_fingerprint: sha256:...   # only when pinned
name: web-1                  # optional display name
log_level: info              # debug | info | warn (optional)
write_jobs: operator         # server (default) | operator | none; local policy for jobs that change the host
operator_keys: ["base64..."] # operator public keys, for write_jobs: operator
```

What to collect is not configured here; it comes from the server and changes apply to connected agents immediately. State directory contents: `agent.key`, `agent.crt`, `ca.pem`, update staging and `update-pending.json` during an update. Use `sentrel-agent run --config FILE` to start with a different file.

## Self-update and rollback

Start an update from the host page or via the API (`POST /api/v1/hosts/{id}/update-agent`, needs `confirm: true`). The server embeds the agent builds it was compiled with. The job carries the download path, SHA-256, version and an Ed25519 signature over OS, architecture, version and hash. The agent then:

1. downloads the binary over its normal TLS channel (system trust store plus the server CA received at registration), and checks the size, SHA-256 and signature;
2. runs the new binary's `self-test`, which must authenticate against the server;
3. hands it to the root helper (`priv install-update`), which takes an exclusive root-owned lock, copies it into a private uniquely named file in the root-only install directory, verifies hash and signature of that copy against the root-owned key, runs it once, keeps the old binary as `sentrel-agent.old`, swaps the file and writes `update-pending.json` plus a protected marker under `/var/lib/sentrel-agent-priv` (Linux);
4. exits so systemd (or the Windows service manager's restart action) starts the new version.

Rollback is automatic: the update marker counts start attempts, and if the new version starts more than three times, or has not connected to the server within three minutes, the helper restores `sentrel-agent.old` and the old version restarts. `rollback-update` is refused unless the protected marker exists and is less than 15 minutes old, so it cannot be used to downgrade outside a failed update. A successful connection clears the markers (`confirm-update`), and the server marks the job succeeded when the agent reconnects with the new version. The update, success and rollback events appear in the job output and audit log.

## Uninstalling

- Linux: `curl -fsSL https://monitor.example.com/install/agent.sh | sudo sh -s -- --uninstall`. This stops the service, deletes the nftables table, the unit, sudoers rule, binaries, `/etc/sentrel-agent`, `/var/lib/sentrel-agent` and the user.
- Windows: run the script with `-Uninstall`; it also removes `Sentrel block *` firewall rules.
- Then delete the host in the UI (this revokes the certificate and removes its data) or use **Revoke** to keep the history.

## Troubleshooting

`sentrel-agent status` prints the version, server URL, agent id and state directory, then tries an authenticated self-test connection:

```
server:   reachable, credentials accepted
server:   NOT REACHABLE - <reason>
```

`sentrel-agent self-test` does the same and exits non-zero on failure. Common reasons:

| Message | Cause and fix |
|---|---|
| `invalid or expired enrollment token` | token already used, expired or mistyped; create a new one |
| `too many registration attempts` | more than 20 registrations per minute from one IP; wait |
| certificate or "pinned CA" errors | wrong server URL or TLS mode; in self-signed mode pass `--ca-fingerprint` |
| `clock skew too large` | the signed hello is accepted within 5 minutes only; fix NTP |
| `replayed hello`, `hello signature invalid` | duplicate agent running with the same identity, or a proxy mangling the stream |
| `agent certificate revoked or host deleted` | the host was deleted or revoked; the agent writes a `REVOKED` file in its state directory and stops retrying. Re-register with a new token |
| `server unavailable` | server down, firewall, or a proxy without HTTP/2 (see [tls-and-proxies.md](tls-and-proxies.md)) |
| `sudo: a password is required` in job output | sudoers rule missing; re-run the installer |

Logs: `journalctl -u sentrel-agent -f` on Linux; on Windows stop the service and run `sentrel-agent run` in an elevated console to see the log output. Set `log_level: debug` in `agent.yaml` and restart. If nothing appears in the UI, also check that the host's clock is correct and that outbound connections to the server port are allowed.
