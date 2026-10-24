# Vulnerability scanning

Sentrel matches each Linux host's package inventory against the [Grype](https://github.com/anchore/grype) vulnerability database, embedded in the server as a library. No scanner runs on the monitored host; agents only send package lists.

## How matching works

1. The agent reports installed packages (name, version, architecture, package type `deb`/`rpm`/`apk`, source package and, for `deb`, the source package's version when it differs from the binary's) with the host's `os-release` `ID` and `VERSION_ID`.
2. The server converts them to Grype package records with the host's distribution and runs Grype's default matchers, including source-package ("upstream") matching, and normalises results by CVE. Debian and Ubuntu data is keyed by source package, so a binary with its own version number (for example `libldb2` `2:2.6.2+samba4.17.12…`, built from `samba` `2:4.17.12…`) is compared by its source version. Agents before 0.9.11 do not report it, and such packages can show CVEs that are already fixed until the agent is updated.
3. Each finding stores the CVE/advisory id, package, installed and fixed version, fix state, severity (Critical, High, Medium, Low, Negligible, Unknown), CVSS score and vector, EPSS, whether it is in CISA's Known Exploited Vulnerabilities catalogue, description and reference URLs.
4. Findings that were present before but are no longer matched become `fixed`. Findings you ignored stay ignored. Per-host counts are stored as the `vulnerabilities_open{severity}` series.

Supported distributions (`ID` in `/etc/os-release`): `ubuntu`, `debian`, `raspbian` (matched as Debian), `rhel`, `centos`, `rocky`, `almalinux`, `ol`, `amzn`, `fedora`, `alpine`, `sles`, `opensuse-leap`, `mariner`, `azurelinux`, `wolfi`, `chainguard`, `photon`. Other Linux distributions (for example Arch) are recorded as "skipped" with the reason.

Windows hosts are covered through Windows Update, see [Windows](#windows). SNMP devices and agentless targets have no inventory and are skipped.

## How CVEs are counted

Every count in the UI and the API uses one model:

- **The unit is one open CVE on one host.** A CVE that hits several packages of a host (or is fixed by several Windows updates) counts once. A CVE on two hosts counts twice in fleet totals.
- **Severity** is the highest severity among the packages that carry the CVE.
- **Total** counts every severity. **Other** is Negligible plus Unknown. Counts are labelled with their scope, for example "645 critical/high" or "3,456 total".
- **Badges** (hosts list, host header, the host's CVEs tab, the dashboard tile) show critical plus high, and say so in their tooltip.
- **Fixable now** means the CVE can be acted on today: the remediation is `upgrade`, `upgrade_kernel`, `remove_old_kernel` or `reboot` (a Windows update counts as `upgrade`). CVEs whose fix is not published yet (`wait`) or unknown (`none`) are not fixable. The same number appears on the Vulnerabilities page, the By host table, the dashboard and `GET /hosts/{id}`, and the "Fixable now" filter (`GET /vulnerabilities?fixable=1`) lists exactly these.
- Only agent hosts that are not revoked are counted. The findings list defaults to all severities and open findings on every page.

`GET /vulnerabilities/summary` returns `hosts[]` and `totals`, each with `critical`, `high`, `medium`, `low`, `other`, `total`, `fixable`, `kev` and `inactive`. `GET /hosts/{id}` has the same object as `vuln_counts`; `GET /dashboard` has `vulnerabilities` (per severity), `vulnerabilities_total`, `vulnerabilities_fixable` and `vulnerabilities_inactive`.

## Windows

Windows hosts get CVE findings from Windows Update rather than from package matching:

1. The agent searches for pending software updates through the Windows Update Agent and reports, for each one, its title, KB article, MSRC severity and the CVE ids Microsoft lists for it (`IUpdate.CveIDs`).
2. The server creates one finding per host and CVE (package = the update title and KB, fixed version = the KB id). Severity maps from MSRC: Critical is Critical, Important is High, Moderate is Medium, Low is Low. Remediation is `upgrade`.
3. When the local vulnerability database is available, the server looks each CVE up in it to add CVSS, EPSS, the CISA KEV flag, description and references. Without the database the findings carry the MSRC severity only; **Update database & scan all** (or any scan of the host) fills in the details later.
4. A finding resolves automatically as soon as its update is no longer pending. A failed update search never resolves anything.
5. Install an update from the host's CVEs tab (**Install update KBxxxxxxx**), which opens the upgrade dialog for that KB (`params.packages` of the `upgrade` job accepts KB ids on Windows).

Notes: findings exist only while vulnerability scanning is enabled. Microsoft does not fill in the CVE list for every update, so some pending security updates show no CVEs. **Third-party applications on Windows are not matched to CVEs.**

## Update database and scan all

The **Update database & scan all** button (Vulnerabilities page) calls `POST /api/v1/vulnerabilities/refresh` (settings permission, 409 while scanning is disabled or a refresh is already running) and returns `{started: true}`. The server updates the database; when that finishes, whether it downloaded a newer build or was already current, it queues a scan for every visible, non-revoked agent host. It runs on the server, so it carries on if the browser is closed. Progress is in `GET /api/v1/vulnerabilities/db`: `refresh_pending`, `refresh_phase` (`updating`, `scanning`, `done` or `failed`), `refresh_error`, `refresh_scan_total` and `refresh_scan_remaining`. The page shows "Updating database…" and then "Scanning N hosts…". A small menu next to the button keeps **Scan all** and **Update database only**.

## Turning scanning on

Scanning is **off by default** for new installs, because the database is large (about 3 GB). Turn it on in the setup wizard or under Settings, Vulnerabilities. The server then downloads the database in the background and shows progress on the Vulnerabilities page. While scanning is off, no database is downloaded or opened, scan requests return 409 ("Vulnerability scanning is disabled; enable it in Settings") and the CVE badges are hidden. Installs that already had a database or scan history keep scanning enabled on upgrade. When you turn scanning off you can also delete the database files (`delete_db: true` in `PUT /api/v1/settings/vuln`); they are never deleted automatically.

## The database

- Location: `<data dir>/vulndb/`. Plan for roughly **3 GB** of disk space on the data volume (schema v6).
- First run: if scanning is enabled and no local database exists, the server downloads it in the background; scans fail with "vulnerability database not downloaded yet" until it finishes.
- Updates: checked daily at `sync_hour` (server local time, default 2), or immediately if the database is older than 36 hours. **Update now** (`POST /api/v1/vulnerabilities/db/sync`, settings permission) starts a manual update. A failed update raises the system alert "Vulnerability database update failed" and clears when the next one succeeds.
- Status (build time, schema, size, last check, last error) is shown on the Vulnerabilities page and at `GET /api/v1/vulnerabilities/db`.
- Scans never need Internet access once the database is on disk; the server opens the existing database at start without network access.

## When scans run

| Trigger | Notes |
|---|---|
| After inventory | when a host's package inventory changed and `scan_after_inventory` is on (default) |
| Manual | host page, **Scan all** (queues all visible hosts) or **Update database & scan all** |
| Schedules | **Scan schedules** (Jobs, Schedules): scope `all`, `tenant`, `group` or `host`; `daily` or `weekly` (weekday 0 to 6, Sunday is 0); time of day in the timezone set under Settings, General |
| After a server restart | scans that were running are marked failed and re-queued |

Scans run one at a time from a queue with a 10 minute limit each. The scan history (packages, findings by severity, database build used) is kept per host.

## Alerts

After each scan the server evaluates one alert per host. It counts distinct open CVEs at or above `alert_severity` (`Critical` default, `High`, `Medium`, or `none` to disable) and, when `only_fixable` is on (default), only those that are fixable now (see [How CVEs are counted](#how-cves-are-counted): a fix not yet in the host's repositories does not count). It is evaluated again after each package inventory, since a newly pending update can make a CVE fixable. Findings that only affect a kernel that is installed but not running (see [Kernels](#kernels)) are not counted unless `alert_on_inactive_kernels` is on (default off). The alert is critical when any Critical finding is counted, otherwise warning, and clears when the count reaches zero. Notification channels, maintenance windows and acknowledgement behave as for any alert ([alerting.md](alerting.md)).

## Fixing findings with upgrades

Findings returned by `GET /api/v1/vulnerabilities` carry three extra fields: `available_version` (the pending package update for the same host and package, or empty), `upgradable` and `os` (`linux` or `windows`). `upgradable` is true for Linux agent hosts when an update is pending whose version is at or above the fixed version; versions are compared with the rules of the package format (deb, rpm or apk), and when the format is unknown any pending update counts. The UI uses this to offer an upgrade of just the affected packages, which creates a normal `upgrade` job (`params.packages`) and therefore needs `allow_upgrades` on the host and a confirmation.

After an upgrade finishes the agent resends its package inventory; when the inventory changed and `scan_after_inventory` is on, the host is rescanned and fixed findings move to `fixed`.

## Ignoring findings

Mark a finding `ignored` (UI, or `PUT /api/v1/vulnerabilities/{id}` with `{"status":"ignored"}`; `monitoring` permission) to drop it from counts and alerts. Reopen with `{"status":"open"}`. Ignored findings stay ignored across rescans.

## Settings

**Settings, Vulnerabilities** (`vuln` section): `enabled` (default on), `db_url`, `sync_hour` (2), `scan_after_inventory` (on), `alert_severity` (Critical), `only_fixable` (on), `alert_on_inactive_kernels` (off).

## Kernels

On Debian and Ubuntu the kernel ABI is part of the package name (`linux-image-7.0.0-28-generic`, `linux-headers-7.0.0-28`, `linux-modules-...`), so a newer kernel is a different package and an old kernel never shows an available upgrade. On RPM distributions the installonly packages (`kernel`, `kernel-core`, `kernel-modules`, `kernel-modules-core`, `kernel-modules-extra`, `kernel-devel`) are installed side by side, with the version-release as the ABI. Sentrel groups these packages by ABI, compares the ABI with the running kernel (`uname -r`, reported as `kernel_version` in the host info) and reports one `remediation` per finding:

| `remediation` | Meaning | Action |
|---|---|---|
| `remove_old_kernel` | the finding only affects a kernel that is neither running nor the newest installed | remove that kernel (`kernel_abi`) |
| `reboot` | the running kernel is affected, but a newer kernel is already installed | reboot the host |
| `upgrade_kernel` | the running (or newest) kernel is affected, no newer kernel is installed and the kernel meta-package (`linux-generic`, `linux-image-virtual`, `kernel`, ...) has an update pending | upgrade `kernel_meta`, then reboot |
| `upgrade` | a normal package with the fix available | upgrade it |
| `wait` | the fix is not in the repositories yet | wait |
| `none` | no fix is known | none |

Findings also carry `kernel_abi` and `inactive` (true when every affected package belongs to a kernel that is not running). `remediation` is empty for non-agent hosts. `GET /vulnerabilities?inactive=0` leaves inactive findings out (the UI's "Include inactive kernels" filter, on by default). `GET /vulnerabilities/summary` and the dashboard add `inactive` counts next to the totals, which are unchanged.

`GET /hosts/{id}/kernels` returns `{running, installed: [{abi, packages, running, newest, removable, cve_count, critical, high}], reboot_required, reboot_pending, allow_upgrades, write_policy, removable_cves, removable_critical}`. `cve_count` is the number of CVEs that exist only in that kernel, that is, the ones removing it resolves. `GET /vulnerabilities/kernels` returns the same fleet-wide (tenant scoped): `[{host_id, host_name, running, removable: [{abi, cve_count, critical}], reboot_pending, ...}]` for hosts with removable kernels or a pending reboot.

### Removing an old kernel

The `remove_kernel` job (`params: {abi}`) is a write job: it needs `allow_upgrades` on the host (a dry run does not) and `confirm`, follows the agent's write policy (read-only agents refuse it, operator-signed hosts wait in `awaiting_signature`) and is not available for Windows. A dry run lists the exact packages. The agent's privileged helper (`priv remove-kernel [--dry-run] ABI`) validates the ABI against a strict pattern, refuses the running kernel and the newest installed kernel (the running and newest kernels are always kept), looks up the installed packages of that ABI with `dpkg-query` or `rpm -qa` and purges exactly those (`apt-get purge -y`, or `dnf remove -y`) in a systemd scope, without a shell. When it finishes the agent resends its inventory so the host is rescanned. The disk-cleanup task `old_kernels` uses the same logic for every old kernel.

The UI offers this on a finding ("Remove kernel 7.0.0-28"), in a card at the top of the host CVE tab, and fleet-wide on the Vulnerabilities page, where "Remove on all eligible hosts" runs dry runs first and then one confirmation. There is no remote reboot action.

### Metrics and automatic removal

The server records `old_kernels_installed` (removable kernels) and `kernel_reboot_pending` (1 when the newest installed kernel is not the running one) on every inventory. Both are in the threshold catalog (`old_kernels`, `kernel_reboot_pending`) and disabled by default.

The per-host setting `auto_remove_old_kernels` (default off) queues a `remove_kernel` job for each removable kernel at the host's next maintenance window that allows jobs. It only works with `allow_upgrades`, never for read-only or operator-signed hosts, and runs at most once a day per host.

## Air-gapped and mirrored databases

Set `db_url` to your own mirror. It follows Grype's distribution layout:

- either the base URL (the server appends `/v6/latest.json`), for example `https://mirror.internal/grype/databases`, or a direct URL ending in `.json`;
- `latest.json` is a small document describing the newest database; its `path` field is the archive file name, **relative to the location of `latest.json`**, and it carries the archive checksum.

To operate a mirror: on a machine with Internet access fetch Anchore's `https://grype.anchore.io/databases/v6/latest.json` and the archive named in its `path` (at the same relative location), transfer both into the isolated network, serve them over HTTP(S) at the URL you configured, and repeat on your own schedule. The server's daily update check then picks up each new archive. Updates are skipped when the mirrored `latest.json` is not newer than what is installed. Keep the file layout and checksum intact, since the server verifies the checksum. Because validity-age checks are disabled in Sentrel, an old mirror still works; check the build date in the status panel to see how stale it is.

Anchore is not contacted when `db_url` points to your mirror. The server also needs no other Internet access for vulnerability scanning.
