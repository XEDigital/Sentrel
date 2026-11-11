package app

import "net/http"

const (
	GET    = http.MethodGet
	POST   = http.MethodPost
	PUT    = http.MethodPut
	DELETE = http.MethodDelete
)

// registerRoutes declares every REST endpoint. The UI uses only these.
func (a *App) registerRoutes(r *apiRouter) {
	s := a.auth
	// Public / setup / auth.
	r.add(routeDef{Method: GET, Path: "/public/info", Summary: "Server info, branding and setup state", Tag: "auth", Public: true, Resp: PublicInfo{}}, a.apiPublicInfo)
	r.add(routeDef{Method: POST, Path: "/setup", Summary: "Complete first-run setup", Tag: "auth", Public: true, Req: SetupReq{}}, a.apiSetup)
	r.add(routeDef{Method: POST, Path: "/auth/login", Summary: "Log in with username and password", Tag: "auth", Public: true, Req: loginReq{}, Resp: loginResp{}}, s.login)
	r.add(routeDef{Method: POST, Path: "/auth/passkey/begin", Summary: "Begin passwordless passkey login", Tag: "auth", Public: true}, s.passkeyLoginBegin)
	r.add(routeDef{Method: POST, Path: "/auth/passkey/finish", Summary: "Finish passwordless passkey login", Tag: "auth", Public: true, Query: []string{"challenge_id"}}, s.passkeyLoginFinish)
	r.add(routeDef{Method: GET, Path: "/auth/oidc/start", Summary: "Begin OpenID Connect single sign-on (redirects to the provider)", Tag: "auth", Public: true}, s.oidcStart)
	r.add(routeDef{Method: GET, Path: "/auth/oidc/callback", Summary: "OpenID Connect redirect URI", Tag: "auth", Public: true, Query: []string{"code", "state"}}, s.oidcCallback)
	r.add(routeDef{Method: POST, Path: "/auth/logout", Summary: "Log out", Tag: "auth", MFAOK: true, PWOK: true}, s.logout)
	r.add(routeDef{Method: GET, Path: "/auth/me", Summary: "Current user and permissions", Tag: "auth", MFAOK: true, PWOK: true, Resp: MeResp{}}, a.apiMe)
	r.add(routeDef{Method: PUT, Path: "/auth/me", Summary: "Update own profile", Tag: "auth", Interactive: true, Req: profileReq{}}, a.apiUpdateMe)
	r.add(routeDef{Method: POST, Path: "/auth/password", Summary: "Change own password", Tag: "auth", MFAOK: true, PWOK: true, Interactive: true, Req: changePWReq{}}, a.apiChangePassword)
	r.add(routeDef{Method: POST, Path: "/auth/mfa/totp", Summary: "Verify TOTP or recovery code", Tag: "auth", MFAOK: true, PWOK: true, Req: codeReq{}}, s.mfaTOTP)
	r.add(routeDef{Method: POST, Path: "/auth/mfa/passkey/begin", Summary: "Begin passkey second factor", Tag: "auth", MFAOK: true, PWOK: true}, s.passkeyMFABegin)
	r.add(routeDef{Method: POST, Path: "/auth/mfa/passkey/finish", Summary: "Finish passkey second factor", Tag: "auth", MFAOK: true, PWOK: true}, s.passkeyMFAFinish)
	r.add(routeDef{Method: POST, Path: "/auth/totp/setup", Summary: "Start TOTP enrolment", Tag: "auth", MFAOK: true, Interactive: true, Resp: totpSetupResp{}}, s.totpSetup)
	r.add(routeDef{Method: POST, Path: "/auth/totp/enable", Summary: "Confirm TOTP enrolment", Tag: "auth", MFAOK: true, Interactive: true, Req: codeReq{}}, s.totpEnable)
	r.add(routeDef{Method: POST, Path: "/auth/totp/disable", Summary: "Disable TOTP", Tag: "auth", Interactive: true, Req: pwReq{}}, s.totpDisable)
	r.add(routeDef{Method: POST, Path: "/auth/passkeys/register/begin", Summary: "Begin passkey registration", Tag: "auth", MFAOK: true, Interactive: true}, s.passkeyRegisterBegin)
	r.add(routeDef{Method: POST, Path: "/auth/passkeys/register/finish", Summary: "Finish passkey registration", Tag: "auth", MFAOK: true, Interactive: true, Query: []string{"challenge_id", "name"}}, s.passkeyRegisterFinish)
	r.add(routeDef{Method: GET, Path: "/auth/passkeys", Summary: "List own passkeys", Tag: "auth", Interactive: true}, a.apiListPasskeys)
	r.add(routeDef{Method: DELETE, Path: "/auth/passkeys/{id}", Summary: "Delete a passkey", Tag: "auth", Interactive: true}, a.apiDeletePasskey)
	r.add(routeDef{Method: GET, Path: "/auth/sessions", Summary: "List own sessions", Tag: "auth", Interactive: true}, a.apiListSessions)
	r.add(routeDef{Method: POST, Path: "/auth/sessions/revoke-others", Summary: "Log out all other sessions", Tag: "auth", Interactive: true}, a.apiRevokeOtherSessions)

	// Dashboard and search.
	r.add(routeDef{Method: GET, Path: "/dashboard", Summary: "Overview counts and recent events", Tag: "dashboard", Perm: PermRead}, a.apiDashboard)

	// Hosts.
	r.add(routeDef{Method: GET, Path: "/hosts", Summary: "List hosts", Tag: "hosts", Perm: PermRead, Resp: []Host{}, Query: []string{"q", "status", "kind", "group_id", "tag", "tenant_id"}}, a.apiListHosts)
	r.add(routeDef{Method: GET, Path: "/hosts/beats", Summary: "Daily uptime bars for every host", Tag: "hosts", Perm: PermRead, Query: []string{"days", "tenant_id"}}, a.apiHostBeats)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}", Summary: "Host detail", Tag: "hosts", Perm: PermRead, Resp: HostDetail{}}, a.apiGetHost)
	r.add(routeDef{Method: PUT, Path: "/hosts/{id}", Summary: "Update host settings", Tag: "hosts", Perm: PermHostSettings, Req: hostUpdate{}}, a.apiUpdateHost)
	r.add(routeDef{Method: DELETE, Path: "/hosts/{id}", Summary: "Delete host and its data", Tag: "hosts", Perm: PermHosts}, a.apiDeleteHost)
	r.add(routeDef{Method: POST, Path: "/hosts/{id}/revoke", Summary: "Revoke the agent certificate", Tag: "hosts", Perm: PermHosts}, a.apiRevokeHost)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/metrics", Summary: "Standard metric series for graphs", Tag: "hosts", Perm: PermRead, Query: []string{"panel", "start", "end", "step"}}, a.apiHostMetrics)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/metrics/export", Summary: "Export all standard metric series as CSV or JSON", Tag: "hosts", Perm: PermRead, Query: []string{"format", "range", "start", "end", "step"}}, a.apiHostMetricsExport)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/packages", Summary: "Installed / upgradable packages", Tag: "hosts", Perm: PermRead, Resp: []Package{}, Query: []string{"upgradable", "q"}}, a.apiHostPackages)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/kernels", Summary: "Installed kernels, the running one and removable old kernels", Tag: "hosts", Perm: PermRead, Resp: kernelsResp{}}, a.apiHostKernels)
	r.add(routeDef{Method: PUT, Path: "/hosts/{id}/notify", Summary: "Mute or unmute notifications for one metric on a host", Tag: "hosts", Perm: PermHostSettings, Req: hostNotifyReq{}}, a.apiHostNotify)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/security", Summary: "Failed logins, IP blocks and fail2ban", Tag: "hosts", Perm: PermRead}, a.apiHostSecurity)
	r.add(routeDef{Method: POST, Path: "/hosts/{id}/block", Summary: "Block an IP on the host firewall", Tag: "hosts", Perm: PermJobs, Req: blockReq{}}, a.apiBlockIP)
	r.add(routeDef{Method: POST, Path: "/hosts/{id}/unblock", Summary: "Remove an IP block", Tag: "hosts", Perm: PermJobs, Req: blockReq{}}, a.apiUnblockIP)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/disk-usage", Summary: "Latest disk usage analysis for a mount", Tag: "hosts", Perm: PermRead, Resp: DiskUsageReport{}, Query: []string{"mount"}}, a.apiGetDiskUsage)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/disk-health", Summary: "Latest SMART, RAID and ZFS health snapshot (Linux agents)", Tag: "hosts", Perm: PermRead, Resp: DiskHealthResp{}}, a.apiHostDiskHealth)
	r.add(routeDef{Method: POST, Path: "/hosts/{id}/disk-usage", Summary: "Queue a disk usage analysis", Tag: "hosts", Perm: PermJobs, Req: diskUsageReq{}}, a.apiPostDiskUsage)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/disk-cleanup/tasks", Summary: "Disk cleanup tasks available on the host", Tag: "hosts", Perm: PermRead, Resp: []CleanupTask{}}, a.apiDiskCleanupTasks)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/thresholds", Summary: "Merged threshold view for a host", Tag: "thresholds", Perm: PermRead, Resp: []MergedRule{}}, a.apiHostThresholds)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/lldp", Summary: "LLDP neighbours (SNMP devices)", Tag: "hosts", Perm: PermRead, Resp: []LLDPNeighbor{}}, a.apiHostLLDP)
	r.add(routeDef{Method: GET, Path: "/hosts/{id}/uptime", Summary: "Daily uptime history", Tag: "hosts", Perm: PermRead, Query: []string{"days"}}, a.apiHostUptime)
	r.add(routeDef{Method: POST, Path: "/hosts/{id}/update-agent", Summary: "Upgrade the agent to the server's version", Tag: "hosts", Perm: PermJobs, Req: confirmReq{}}, a.apiUpdateAgent)
	r.add(routeDef{Method: POST, Path: "/hosts/{id}/refresh-inventory", Summary: "Ask the agent to send its package inventory now", Tag: "hosts", Perm: PermRead}, a.apiRefreshInventory)
	r.add(routeDef{Method: POST, Path: "/hosts/{id}/scan", Summary: "Run a vulnerability scan now", Tag: "vulnerabilities", Perm: PermJobs}, a.apiScanHost)
	r.add(routeDef{Method: POST, Path: "/hosts/snmp", Summary: "Add an SNMP device", Tag: "hosts", Perm: PermHosts, Req: snmpHostReq{}, Resp: Host{}}, a.apiCreateSNMPHost)
	r.add(routeDef{Method: PUT, Path: "/hosts/{id}/snmp", Summary: "Update SNMP settings", Tag: "hosts", Perm: PermHosts, Req: snmpHostReq{}}, a.apiUpdateSNMPHost)
	r.add(routeDef{Method: POST, Path: "/hosts/target", Summary: "Add an agentless target (checks only)", Tag: "hosts", Perm: PermHosts, Req: targetHostReq{}, Resp: Host{}}, a.apiCreateTargetHost)
	r.add(routeDef{Method: POST, Path: "/snmp/test", Summary: "Test SNMP connectivity", Tag: "hosts", Perm: PermHosts, Req: snmpTestReq{}}, a.apiSNMPTest)
	r.add(routeDef{Method: GET, Path: "/snmp/profiles", Summary: "List SNMP device profiles", Tag: "hosts", Perm: PermRead}, a.apiSNMPProfiles)
	r.add(routeDef{Method: POST, Path: "/snmp/profiles/reload", Summary: "Reload custom SNMP profiles from disk", Tag: "hosts", Perm: PermSettings}, a.apiSNMPReload)

	// Enrolment.
	r.add(routeDef{Method: POST, Path: "/enrollment-tokens", Summary: "Create a one-time enrolment token", Tag: "enrolment", Perm: PermHosts, Req: tokenReq{}, Resp: tokenResp{}}, a.apiCreateToken)
	r.add(routeDef{Method: GET, Path: "/enrollment-tokens", Summary: "List unused enrolment tokens", Tag: "enrolment", Perm: PermHosts, Resp: []EnrollmentToken{}}, a.apiListTokens)
	r.add(routeDef{Method: DELETE, Path: "/enrollment-tokens/{id}", Summary: "Delete an enrolment token", Tag: "enrolment", Perm: PermHosts}, a.apiDeleteToken)
	r.add(routeDef{Method: GET, Path: "/agents/binaries", Summary: "Agent builds available for install and update", Tag: "enrolment", Perm: PermRead}, a.apiAgentBinaries)
	r.add(routeDef{Method: GET, Path: "/agents/install-info", Summary: "How to install an agent from this server: URL, TLS pinning data and downloadable packages", Tag: "enrolment", Perm: PermHosts, Resp: installInfo{}}, a.apiInstallInfo)

	// Groups.
	r.add(routeDef{Method: GET, Path: "/groups", Summary: "List host groups", Tag: "groups", Perm: PermRead, Resp: []HostGroup{}}, a.apiListGroups)
	r.add(routeDef{Method: POST, Path: "/groups", Summary: "Create a host group", Tag: "groups", Perm: PermMonitoring, Req: groupReq{}, Resp: HostGroup{}}, a.apiCreateGroup)
	r.add(routeDef{Method: PUT, Path: "/groups/{id}", Summary: "Update a host group", Tag: "groups", Perm: PermMonitoring, Req: groupReq{}}, a.apiUpdateGroup)
	r.add(routeDef{Method: DELETE, Path: "/groups/{id}", Summary: "Delete a host group", Tag: "groups", Perm: PermMonitoring}, a.apiDeleteGroup)
	r.add(routeDef{Method: GET, Path: "/tags", Summary: "All tags in use", Tag: "groups", Perm: PermRead}, a.apiListTags)

	// Checks.
	r.add(routeDef{Method: GET, Path: "/checks", Summary: "List checks", Tag: "checks", Perm: PermRead, Resp: []Check{}, Query: []string{"host_id", "type", "status"}}, a.apiListChecks)
	r.add(routeDef{Method: POST, Path: "/checks", Summary: "Create a check", Tag: "checks", Perm: PermMonitoring, Req: checkReq{}, Resp: Check{}}, a.apiCreateCheck)
	r.add(routeDef{Method: GET, Path: "/checks/beats", Summary: "Recent results for every check", Tag: "checks", Perm: PermRead, Query: []string{"limit", "tenant_id"}}, a.apiCheckBeats)
	r.add(routeDef{Method: GET, Path: "/checks/{id}", Summary: "Get a check", Tag: "checks", Perm: PermRead, Resp: Check{}}, a.apiGetCheck)
	r.add(routeDef{Method: PUT, Path: "/checks/{id}", Summary: "Update a check", Tag: "checks", Perm: PermMonitoring, Req: checkReq{}, Resp: Check{}}, a.apiUpdateCheck)
	r.add(routeDef{Method: DELETE, Path: "/checks/{id}", Summary: "Delete a check", Tag: "checks", Perm: PermMonitoring}, a.apiDeleteCheck)
	r.add(routeDef{Method: POST, Path: "/checks/{id}/regenerate-token", Summary: "Issue a new push URL for a push check (the old one stops working)", Tag: "checks", Perm: PermMonitoring, Resp: Check{}}, a.apiRegenerateCheckToken)
	r.add(routeDef{Method: POST, Path: "/checks/{id}/run", Summary: "Run a check now (needs monitoring write access; a run already in progress returns 409)", Tag: "checks", Perm: PermMonitoring}, a.apiRunCheck)
	r.add(routeDef{Method: GET, Path: "/checks/{id}/history", Summary: "Latency and uptime history", Tag: "checks", Perm: PermRead, Query: []string{"start", "end"}}, a.apiCheckHistory)

	// Thresholds.
	r.add(routeDef{Method: GET, Path: "/thresholds/catalog", Summary: "Metrics that accept thresholds", Tag: "thresholds", Perm: PermRead, Resp: []MetricDef{}}, a.apiThresholdCatalog)
	r.add(routeDef{Method: GET, Path: "/thresholds", Summary: "List threshold rules", Tag: "thresholds", Perm: PermRead, Resp: []ThresholdRule{}, Query: []string{"scope", "scope_id"}}, a.apiListThresholds)
	r.add(routeDef{Method: POST, Path: "/thresholds", Summary: "Create or replace a threshold rule", Tag: "thresholds", Perm: PermMonitoring, Req: thresholdReq{}, Resp: ThresholdRule{}}, a.apiUpsertThreshold)
	r.add(routeDef{Method: DELETE, Path: "/thresholds/{id}", Summary: "Delete a threshold rule", Tag: "thresholds", Perm: PermMonitoring}, a.apiDeleteThreshold)

	// Alerts.
	r.add(routeDef{Method: GET, Path: "/alerts", Summary: "List alerts", Tag: "alerts", Perm: PermRead, Resp: []Alert{}, Query: []string{"status", "severity", "host_id", "limit"}}, a.apiListAlerts)
	r.add(routeDef{Method: GET, Path: "/alerts/{id}", Summary: "Alert with event history", Tag: "alerts", Perm: PermRead}, a.apiGetAlert)
	r.add(routeDef{Method: POST, Path: "/alerts/{id}/ack", Summary: "Acknowledge an alert; with expected, also hide it and stop its notifications", Tag: "alerts", Perm: PermAck, Req: ackReq{}}, a.apiAckAlert)
	r.add(routeDef{Method: POST, Path: "/alerts/{id}/unack", Summary: "Remove an acknowledgement or expected mark", Tag: "alerts", Perm: PermAck}, a.apiUnackAlert)
	r.add(routeDef{Method: POST, Path: "/alerts/ack", Summary: "Acknowledge several alerts", Tag: "alerts", Perm: PermAck, Req: bulkAckReq{}}, a.apiBulkAck)
	r.add(routeDef{Method: GET, Path: "/alert-events", Summary: "Alert event timeline", Tag: "alerts", Perm: PermRead, Resp: []AlertEvent{}, Query: []string{"host_id", "limit", "before"}}, a.apiAlertEvents)

	// Maintenance.
	r.add(routeDef{Method: GET, Path: "/maintenance", Summary: "List maintenance windows", Tag: "maintenance", Perm: PermRead, Resp: []MaintenanceWindow{}}, a.apiListMaintenance)
	r.add(routeDef{Method: POST, Path: "/maintenance", Summary: "Create a maintenance window", Tag: "maintenance", Perm: PermMonitoring, Req: maintReq{}, Resp: MaintenanceWindow{}}, a.apiCreateMaintenance)
	r.add(routeDef{Method: PUT, Path: "/maintenance/{id}", Summary: "Update a maintenance window", Tag: "maintenance", Perm: PermMonitoring, Req: maintReq{}}, a.apiUpdateMaintenance)
	r.add(routeDef{Method: DELETE, Path: "/maintenance/{id}", Summary: "Delete a maintenance window", Tag: "maintenance", Perm: PermMonitoring}, a.apiDeleteMaintenance)

	// Notifications.
	r.add(routeDef{Method: GET, Path: "/notification-channels", Summary: "List notification channels", Tag: "notifications", Perm: PermRead, Resp: []NotificationChannel{}}, a.apiListChannels)
	r.add(routeDef{Method: POST, Path: "/notification-channels", Summary: "Create a notification channel", Tag: "notifications", Perm: PermMonitoring, Req: channelReq{}, Resp: NotificationChannel{}}, a.apiCreateChannel)
	r.add(routeDef{Method: PUT, Path: "/notification-channels/{id}", Summary: "Update a notification channel", Tag: "notifications", Perm: PermMonitoring, Req: channelReq{}, Resp: NotificationChannel{}}, a.apiUpdateChannel)
	r.add(routeDef{Method: DELETE, Path: "/notification-channels/{id}", Summary: "Delete a notification channel", Tag: "notifications", Perm: PermMonitoring}, a.apiDeleteChannel)
	r.add(routeDef{Method: POST, Path: "/notification-channels/{id}/test", Summary: "Send a test notification", Tag: "notifications", Perm: PermMonitoring}, a.apiTestChannel)
	r.add(routeDef{Method: POST, Path: "/notification-channels/test", Summary: "Test an unsaved channel config", Tag: "notifications", Perm: PermMonitoring, Req: channelReq{}}, a.apiTestChannelConfig)
	r.add(routeDef{Method: GET, Path: "/notification-log", Summary: "Recent notification deliveries", Tag: "notifications", Perm: PermRead}, a.apiNotificationLog)

	// Jobs.
	r.add(routeDef{Method: GET, Path: "/jobs", Summary: "List jobs", Tag: "jobs", Perm: PermRead, Resp: []Job{}, Query: []string{"host_id", "status", "type", "limit"}}, a.apiListJobs)
	r.add(routeDef{Method: POST, Path: "/jobs", Summary: "Create a job (upgrade, block_ip...)", Tag: "jobs", Perm: PermJobs, Req: JobRequest{}, Resp: Job{}}, a.apiCreateJob)
	r.add(routeDef{Method: POST, Path: "/jobs/bulk", Summary: "Create the same job on several hosts", Tag: "jobs", Perm: PermJobs, Req: bulkJobReq{}}, a.apiBulkJobs)
	r.add(routeDef{Method: GET, Path: "/jobs/{id}", Summary: "Job detail with output", Tag: "jobs", Perm: PermRead, Resp: Job{}}, a.apiGetJob)
	r.add(routeDef{Method: GET, Path: "/jobs/{id}/spec", Summary: "Exact job spec bytes (base64) for offline operator signing", Tag: "jobs", Perm: PermJobs, Resp: JobSpecInfo{}}, a.apiJobSpec)
	r.add(routeDef{Method: POST, Path: "/jobs/{id}/operator-signature", Summary: "Post an operator signature for a job awaiting one", Tag: "jobs", Perm: PermJobs, Req: OperatorSignRequest{}, Resp: Job{}}, a.apiOperatorSignature)
	r.add(routeDef{Method: POST, Path: "/jobs/{id}/cancel", Summary: "Cancel a job that has not started", Tag: "jobs", Perm: PermJobs}, a.apiCancelJob)

	// Vulnerabilities.
	r.add(routeDef{Method: GET, Path: "/vulnerabilities", Summary: "List vulnerability findings", Tag: "vulnerabilities", Perm: PermRead, Resp: []VulnFinding{}, Query: []string{"host_id", "severity", "status", "q", "fixable", "limit", "inactive"}}, a.apiListFindings)
	r.add(routeDef{Method: GET, Path: "/vulnerabilities/kernels", Summary: "Hosts with removable old kernels", Tag: "vulnerabilities", Perm: PermRead, Resp: []fleetKernelHost{}}, a.apiFleetKernels)
	r.add(routeDef{Method: GET, Path: "/vulnerabilities/summary", Summary: "Findings per host and severity", Tag: "vulnerabilities", Perm: PermRead}, a.apiVulnSummary)
	r.add(routeDef{Method: PUT, Path: "/vulnerabilities/{id}", Summary: "Ignore or reopen a finding", Tag: "vulnerabilities", Perm: PermMonitoring, Req: findingUpdate{}}, a.apiUpdateFinding)
	r.add(routeDef{Method: POST, Path: "/vulnerabilities/scan-all", Summary: "Queue scans for all visible hosts", Tag: "vulnerabilities", Perm: PermJobs}, a.apiScanAll)
	r.add(routeDef{Method: GET, Path: "/vulnerabilities/db", Summary: "Vulnerability DB status", Tag: "vulnerabilities", Perm: PermRead}, a.apiVulnDBStatus)
	r.add(routeDef{Method: POST, Path: "/vulnerabilities/db/sync", Summary: "Update the vulnerability DB now", Tag: "vulnerabilities", Perm: PermSettings}, a.apiVulnDBSync)
	r.add(routeDef{Method: POST, Path: "/vulnerabilities/refresh", Summary: "Update the vulnerability DB, then scan all visible hosts", Tag: "vulnerabilities", Perm: PermSettings}, a.apiVulnRefresh)
	r.add(routeDef{Method: GET, Path: "/vulnerabilities/scans", Summary: "Scan history", Tag: "vulnerabilities", Perm: PermRead, Resp: []VulnScan{}, Query: []string{"host_id"}}, a.apiListScans)
	r.add(routeDef{Method: GET, Path: "/vuln-schedules", Summary: "List scan schedules", Tag: "vulnerabilities", Perm: PermRead, Resp: []VulnSchedule{}}, a.apiListVulnSchedules)
	r.add(routeDef{Method: POST, Path: "/vuln-schedules", Summary: "Create a scan schedule", Tag: "vulnerabilities", Perm: PermJobs, Req: vulnScheduleReq{}, Resp: VulnSchedule{}}, a.apiCreateVulnSchedule)
	r.add(routeDef{Method: PUT, Path: "/vuln-schedules/{id}", Summary: "Update a scan schedule", Tag: "vulnerabilities", Perm: PermJobs, Req: vulnScheduleReq{}}, a.apiUpdateVulnSchedule)
	r.add(routeDef{Method: DELETE, Path: "/vuln-schedules/{id}", Summary: "Delete a scan schedule", Tag: "vulnerabilities", Perm: PermJobs}, a.apiDeleteVulnSchedule)

	// Update schedules.
	r.add(routeDef{Method: GET, Path: "/update-schedules", Summary: "List update schedules", Tag: "updates", Perm: PermRead, Resp: []UpdateSchedule{}}, a.apiListUpdateSchedules)
	r.add(routeDef{Method: POST, Path: "/update-schedules", Summary: "Create an update schedule", Tag: "updates", Perm: PermJobs, Req: updateScheduleReq{}, Resp: UpdateSchedule{}}, a.apiCreateUpdateSchedule)
	r.add(routeDef{Method: PUT, Path: "/update-schedules/{id}", Summary: "Update an update schedule", Tag: "updates", Perm: PermJobs, Req: updateScheduleReq{}}, a.apiUpdateUpdateSchedule)
	r.add(routeDef{Method: DELETE, Path: "/update-schedules/{id}", Summary: "Delete an update schedule", Tag: "updates", Perm: PermJobs}, a.apiDeleteUpdateSchedule)

	// Metrics.
	r.add(routeDef{Method: GET, Path: "/metrics/query", Summary: "PromQL range query (tenant-scoped)", Tag: "metrics", Perm: PermRead, Query: []string{"query", "start", "end", "step"}}, a.apiMetricQuery)
	r.add(routeDef{Method: GET, Path: "/metrics/names", Summary: "Metric names", Tag: "metrics", Perm: PermRead}, a.apiMetricNames)

	// Status pages.
	r.add(routeDef{Method: GET, Path: "/status-pages", Summary: "List status pages", Tag: "status pages", Perm: PermRead, Resp: []StatusPage{}}, a.apiListStatusPages)
	r.add(routeDef{Method: POST, Path: "/status-pages", Summary: "Create a status page", Tag: "status pages", Perm: PermMonitoring, Req: statusPageReq{}, Resp: StatusPage{}}, a.apiCreateStatusPage)
	r.add(routeDef{Method: PUT, Path: "/status-pages/{id}", Summary: "Update a status page", Tag: "status pages", Perm: PermMonitoring, Req: statusPageReq{}}, a.apiUpdateStatusPage)
	r.add(routeDef{Method: DELETE, Path: "/status-pages/{id}", Summary: "Delete a status page", Tag: "status pages", Perm: PermMonitoring}, a.apiDeleteStatusPage)
	r.add(routeDef{Method: GET, Path: "/public/status/{slug}", Summary: "Public status page data", Tag: "status pages", Public: true, Query: []string{"token"}}, a.apiPublicStatus)

	// Users, tenants, keys, audit.
	r.add(routeDef{Method: GET, Path: "/users", Summary: "List users", Tag: "users", Perm: PermUsers, Resp: []User{}}, a.apiListUsers)
	r.add(routeDef{Method: POST, Path: "/users", Summary: "Create a user", Tag: "users", Perm: PermUsers, Req: userReq{}, Resp: User{}}, a.apiCreateUser)
	r.add(routeDef{Method: PUT, Path: "/users/{id}", Summary: "Update a user", Tag: "users", Perm: PermUsers, Req: userReq{}}, a.apiUpdateUser)
	r.add(routeDef{Method: DELETE, Path: "/users/{id}", Summary: "Delete a user", Tag: "users", Perm: PermUsers}, a.apiDeleteUser)
	r.add(routeDef{Method: POST, Path: "/users/{id}/reset-2fa", Summary: "Remove a user's second factors", Tag: "users", Perm: PermUsers}, a.apiResetUser2FA)
	r.add(routeDef{Method: GET, Path: "/tenants", Summary: "List tenants", Tag: "tenants", Perm: PermRead, Resp: []Tenant{}}, a.apiListTenants)
	r.add(routeDef{Method: POST, Path: "/tenants", Summary: "Create a tenant", Tag: "tenants", Perm: PermTenants, Req: tenantReq{}, Resp: Tenant{}}, a.apiCreateTenant)
	r.add(routeDef{Method: PUT, Path: "/tenants/{id}", Summary: "Update a tenant", Tag: "tenants", Perm: PermTenants, Req: tenantReq{}}, a.apiUpdateTenant)
	r.add(routeDef{Method: DELETE, Path: "/tenants/{id}", Summary: "Delete a tenant and all its data", Tag: "tenants", Perm: PermTenants}, a.apiDeleteTenant)
	r.add(routeDef{Method: GET, Path: "/api-keys", Summary: "List API keys", Tag: "api keys", Interactive: true, Resp: []APIKey{}}, a.apiListKeys)
	r.add(routeDef{Method: POST, Path: "/api-keys", Summary: "Create an API key (shown once)", Tag: "api keys", Interactive: true, Req: apiKeyReq{}}, a.apiCreateKey)
	r.add(routeDef{Method: DELETE, Path: "/api-keys/{id}", Summary: "Revoke an API key", Tag: "api keys", Interactive: true}, a.apiDeleteKey)
	r.add(routeDef{Method: GET, Path: "/audit", Summary: "Audit log", Tag: "audit", Perm: PermAudit, Resp: []AuditEntry{}, Query: []string{"q", "action", "actor", "limit", "before"}}, a.apiAudit)

	// Settings, branding, server.
	r.add(routeDef{Method: GET, Path: "/settings", Summary: "All settings (secrets redacted)", Tag: "settings", Perm: PermSettings}, a.apiGetSettings)
	r.add(routeDef{Method: PUT, Path: "/settings/{section}", Summary: "Update a settings section", Tag: "settings", Perm: PermSettings}, a.apiPutSettings)
	r.add(routeDef{Method: POST, Path: "/settings/smtp/test", Summary: "Send a test email", Tag: "settings", Perm: PermSettings, Req: testMailReq{}}, a.apiTestSMTP)
	r.add(routeDef{Method: POST, Path: "/settings/ldap/test", Summary: "Test LDAP settings", Tag: "settings", Perm: PermSettings, Req: loginReq{}}, a.apiTestLDAP)
	r.add(routeDef{Method: POST, Path: "/settings/oidc/test", Summary: "Test OIDC discovery", Tag: "settings", Perm: PermSettings}, a.apiTestOIDC)
	r.add(routeDef{Method: POST, Path: "/settings/radius/test", Summary: "Test RADIUS settings", Tag: "settings", Perm: PermSettings, Req: loginReq{}}, a.apiTestRADIUS)
	r.add(routeDef{Method: GET, Path: "/branding", Summary: "Branding for the caller's tenant", Tag: "settings", Perm: PermRead, Resp: Branding{}, Query: []string{"tenant_id"}}, a.apiGetBranding)
	r.add(routeDef{Method: PUT, Path: "/branding", Summary: "Update branding", Tag: "settings", Perm: PermBranding, Req: Branding{}, Query: []string{"tenant_id"}}, a.apiPutBranding)
	r.add(routeDef{Method: GET, Path: "/server/status", Summary: "Server health, storage and version", Tag: "server", Perm: PermRead}, a.apiServerStatus)
	r.add(routeDef{Method: GET, Path: "/server/updates", Summary: "Current version and whether an update exists (release notes and install details for admins)", Tag: "server", Perm: PermRead}, a.apiGetUpdates)
	r.add(routeDef{Method: POST, Path: "/server/updates/check", Summary: "Check GitHub for a new release now", Tag: "server", Perm: PermSettings}, a.apiCheckUpdates)
	r.add(routeDef{Method: POST, Path: "/server/updates/install", Summary: "Download, verify and install the latest release (systemd installs only)", Tag: "server", Perm: PermSettings, Req: installUpdateReq{}}, a.apiInstallUpdate)
	r.add(routeDef{Method: GET, Path: "/server/updates/status", Summary: "Progress of the running or last update", Tag: "server", Perm: PermSettings, Resp: InstallStatus{}}, a.apiUpdateStatus)
	r.add(routeDef{Method: GET, Path: "/server/backup", Summary: "Download a backup (SQLite + PKI + settings)", Tag: "server", Perm: PermSettings}, a.apiBackup)
}
