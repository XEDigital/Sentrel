package app

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strconv"
)

// JSON is a column holding arbitrary JSON that is passed through verbatim.
type JSON json.RawMessage

func (j JSON) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return j, nil
}

func (j *JSON) UnmarshalJSON(b []byte) error {
	*j = append((*j)[:0], b...)
	return nil
}

func (j *JSON) Scan(v any) error {
	switch x := v.(type) {
	case string:
		*j = JSON(x)
	case []byte:
		*j = append(JSON(nil), x...)
	case nil:
		*j = nil
	default:
		return errors.New("JSON: unsupported scan type")
	}
	return nil
}

func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return "null", nil
	}
	return string(j), nil
}

// StrList is a JSON-encoded []string column.
type StrList []string

func (l *StrList) Scan(v any) error {
	var b []byte
	switch x := v.(type) {
	case string:
		b = []byte(x)
	case []byte:
		b = x
	case nil:
		*l = nil
		return nil
	}
	if len(b) == 0 {
		*l = nil
		return nil
	}
	return json.Unmarshal(b, (*[]string)(l))
}

func (l StrList) Value() (driver.Value, error) {
	if l == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]string(l))
	return string(b), err
}

// IntList is a JSON-encoded []int64 column.
type IntList []int64

func (l *IntList) Scan(v any) error {
	var b []byte
	switch x := v.(type) {
	case string:
		b = []byte(x)
	case []byte:
		b = x
	case nil:
		*l = nil
		return nil
	}
	if len(b) == 0 {
		*l = nil
		return nil
	}
	return json.Unmarshal(b, (*[]int64)(l))
}

func (l IntList) Value() (driver.Value, error) {
	if l == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]int64(l))
	return string(b), err
}

type Tenant struct {
	ID        int64  `db:"id" json:"id"`
	Name      string `db:"name" json:"name"`
	Slug      string `db:"slug" json:"slug"`
	Hostname  string `db:"hostname" json:"hostname"`
	Disabled  bool   `db:"disabled" json:"disabled"`
	Notes     string `db:"notes" json:"notes"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
}

type User struct {
	ID            int64   `db:"id" json:"id"`
	TenantID      int64   `db:"tenant_id" json:"tenant_id"`
	Username      string  `db:"username" json:"username"`
	Email         string  `db:"email" json:"email"`
	DisplayName   string  `db:"display_name" json:"display_name"`
	PasswordHash  string  `db:"password_hash" json:"-"`
	Role          string  `db:"role" json:"role"`
	AuthSource    string  `db:"auth_source" json:"auth_source"`
	TOTPSecret    string  `db:"totp_secret" json:"-"`
	TOTPEnabled   bool    `db:"totp_enabled" json:"totp_enabled"`
	RecoveryCodes StrList `db:"recovery_codes" json:"-"`
	WebAuthnID    []byte  `db:"webauthn_id" json:"-"`
	Disabled      bool    `db:"disabled" json:"disabled"`
	MustChangePW  bool    `db:"must_change_pw" json:"must_change_password"`
	Theme         string  `db:"theme" json:"theme"`
	CreatedAt     int64   `db:"created_at" json:"created_at"`
	LastLoginAt   int64   `db:"last_login_at" json:"last_login_at"`
	PasskeyCount  int     `db:"-" json:"passkey_count"`
}

type HostGroup struct {
	ID          int64  `db:"id" json:"id"`
	TenantID    int64  `db:"tenant_id" json:"tenant_id"`
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`
	Color       string `db:"color" json:"color"`
	CreatedAt   int64  `db:"created_at" json:"created_at"`
	HostCount   int    `db:"host_count" json:"host_count"`
}

type Host struct {
	ID                int64   `db:"id" json:"id"`
	TenantID          int64   `db:"tenant_id" json:"tenant_id"`
	Kind              string  `db:"kind" json:"kind"`
	Name              string  `db:"name" json:"name"`
	Address           string  `db:"address" json:"address"`
	GroupID           *int64  `db:"group_id" json:"group_id"`
	Tags              StrList `db:"tags" json:"tags"`
	Notes             string  `db:"notes" json:"notes"`
	AgentID           *string `db:"agent_id" json:"agent_id"`
	CertSerial        string  `db:"cert_serial" json:"-"`
	CertExpiresAt     int64   `db:"cert_expires_at" json:"cert_expires_at"`
	Revoked           bool    `db:"revoked" json:"revoked"`
	AgentVersion      string  `db:"agent_version" json:"agent_version"`
	HostInfo          JSON    `db:"host_info" json:"host_info"`
	State             JSON    `db:"state" json:"state,omitempty"`
	Status            string  `db:"status" json:"status"`
	LastSeenAt        int64   `db:"last_seen_at" json:"last_seen_at"`
	Connected         bool    `db:"connected" json:"connected"`
	RebootRequired    bool    `db:"reboot_required" json:"reboot_required"`
	IntervalSeconds   *int    `db:"interval_seconds" json:"interval_seconds"`
	InventoryInterval *int    `db:"inventory_interval" json:"inventory_interval"`
	RetentionDays     *int    `db:"retention_days" json:"retention_days"`
	AgentOptions      JSON    `db:"agent_options" json:"agent_options"`
	// Effective values (host override, else the global default). Filled by
	// resolveHost after loading; the raw per-host overrides are the Ov* fields.
	AllowUpgrades        bool  `db:"-" json:"allow_upgrades"`
	AllowIPBlock         bool  `db:"-" json:"allow_ip_block"`
	AllowCleanup         bool  `db:"-" json:"allow_cleanup"`
	AutoBlock            bool  `db:"-" json:"auto_block"`
	OvAllowUpgrades      *bool `db:"allow_upgrades" json:"-"`
	OvAllowIPBlock       *bool `db:"allow_ip_block" json:"-"`
	OvAllowCleanup       *bool `db:"allow_cleanup" json:"-"`
	OvAutoBlock          *bool `db:"auto_block" json:"-"`
	AutoRemoveOldKernels bool  `db:"auto_remove_old_kernels" json:"auto_remove_old_kernels"`
	LastAutoKernelAt     int64 `db:"last_auto_kernel_at" json:"last_auto_kernel_at"`
	// Reported by the agent from its local config; the server cannot change it.
	WritePolicy       string  `db:"write_policy" json:"write_policy"`
	OperatorKeys      StrList `db:"operator_keys" json:"-"`
	OperatorKeyIDs    StrList `db:"operator_key_ids" json:"operator_key_ids"`
	SNMPConfig        JSON    `db:"snmp_config" json:"-"`
	SNMPInfo          JSON    `db:"snmp_info" json:"snmp_info"`
	StorageBytes      int64   `db:"storage_bytes" json:"storage_bytes"`
	StorageComputedAt int64   `db:"storage_computed_at" json:"storage_computed_at"`
	CreatedAt         int64   `db:"created_at" json:"created_at"`
	UpdatedAt         int64   `db:"updated_at" json:"updated_at"`

	// Derived fields filled by list endpoints.
	GroupName     string       `db:"-" json:"group_name,omitempty"`
	TenantName    string       `db:"-" json:"tenant_name,omitempty"`
	AlertCount    int          `db:"-" json:"alert_count"`
	AlertSeverity string       `db:"-" json:"alert_severity,omitempty"`
	UpgradeCount  int          `db:"-" json:"upgrade_count"`
	SecurityCount int          `db:"-" json:"security_count"`
	VulnCritical  int          `db:"-" json:"vuln_critical"`
	VulnHigh      int          `db:"-" json:"vuln_high"`
	InMaintenance bool         `db:"-" json:"in_maintenance"`
	Summary       *HostSummary `db:"-" json:"summary,omitempty"`
	Parent        *DepParent   `db:"-" json:"parent,omitempty"`
}

// HostSummary holds the latest headline metrics for list views.
type HostSummary struct {
	CPU    *float64 `json:"cpu"`
	Memory *float64 `json:"memory"`
	Disk   *float64 `json:"disk"` // worst mount
	Load   *float64 `json:"load"`
	Uptime *float64 `json:"uptime"`
}

const hostCols = `h.id, h.tenant_id, h.kind, h.name, h.address, h.group_id, h.tags, h.notes, h.agent_id, h.cert_serial,
 h.cert_expires_at, h.revoked, h.agent_version, h.host_info, h.status, h.last_seen_at, h.connected, h.reboot_required,
 h.interval_seconds, h.inventory_interval, h.retention_days, h.agent_options, h.allow_upgrades, h.allow_ip_block,
 h.allow_cleanup, h.auto_block, h.auto_remove_old_kernels, h.last_auto_kernel_at, h.write_policy, h.operator_keys, h.operator_key_ids, h.snmp_config, h.snmp_info, h.storage_bytes, h.storage_computed_at, h.created_at, h.updated_at`

// AgentOptions are per-host overrides of AgentDefaults (nil = inherit).
type AgentOptions struct {
	TopProcesses            *int     `json:"top_processes,omitempty"`
	CollectServices         *bool    `json:"collect_services,omitempty"`
	CollectPorts            *bool    `json:"collect_ports,omitempty"`
	CollectDocker           *bool    `json:"collect_docker,omitempty"`
	CollectTemperatures     *bool    `json:"collect_temperatures,omitempty"`
	BruteforceEnabled       *bool    `json:"bruteforce_enabled,omitempty"`
	Fail2banEnabled         *bool    `json:"fail2ban_enabled,omitempty"`
	PortscanEnabled         *bool    `json:"portscan_enabled,omitempty"`
	PortscanThresholdPerMin *int     `json:"portscan_threshold_per_min,omitempty"`
	PortscanAllowlist       []string `json:"portscan_allowlist,omitempty"`
	// Security overrides (nil = inherit the global default).
	BruteforceThreshold *int     `json:"bruteforce_threshold,omitempty"`
	BruteforceWindowMin *int     `json:"bruteforce_window_minutes,omitempty"`
	AutoBlockThreshold  *int     `json:"auto_block_threshold,omitempty"`
	AutoBlockMinutes    *int     `json:"auto_block_minutes,omitempty"`
	NeverBlock          []string `json:"never_block,omitempty"`
	RefreshPackageIndex *bool    `json:"refresh_package_index,omitempty"`
	WatchedServices     []string `json:"watched_services,omitempty"`
}

type Check struct {
	ID                  int64    `db:"id" json:"id"`
	TenantID            int64    `db:"tenant_id" json:"tenant_id"`
	HostID              *int64   `db:"host_id" json:"host_id"`
	Name                string   `db:"name" json:"name"`
	Type                string   `db:"type" json:"type"`
	Target              string   `db:"target" json:"target"`
	Config              JSON     `db:"config" json:"config"`
	IntervalSeconds     int      `db:"interval_seconds" json:"interval_seconds"`
	TimeoutSeconds      int      `db:"timeout_seconds" json:"timeout_seconds"`
	FailureThreshold    int      `db:"failure_threshold" json:"failure_threshold"`
	Severity            string   `db:"severity" json:"severity"`
	Enabled             bool     `db:"enabled" json:"enabled"`
	Status              string   `db:"status" json:"status"`
	ConsecutiveFailures int      `db:"consecutive_failures" json:"consecutive_failures"`
	LastMessage         string   `db:"last_message" json:"last_message"`
	LastLatencyMs       float64  `db:"last_latency_ms" json:"last_latency_ms"`
	LastCheckedAt       int64    `db:"last_checked_at" json:"last_checked_at"`
	LastChangeAt        int64    `db:"last_change_at" json:"last_change_at"`
	CreatedAt           int64    `db:"created_at" json:"created_at"`
	// Push checks: the URL token (only shown to users who can edit checks),
	// its lookup hash and the last beat received.
	PushToken     string     `db:"push_token" json:"push_token,omitempty"`
	PushTokenHash string     `db:"push_token_hash" json:"-"`
	LastBeatAt    int64      `db:"last_beat_at" json:"last_beat_at"`
	LastBeatUp    bool       `db:"last_beat_up" json:"-"`
	LastBeatMsg   string     `db:"last_beat_msg" json:"-"`
	HostName      string     `db:"-" json:"host_name,omitempty"`
	Uptime24h     *float64   `db:"-" json:"uptime_24h,omitempty"`
	Parent        *DepParent `db:"-" json:"parent,omitempty"`
}

type ThresholdRule struct {
	ID         int64    `db:"id" json:"id"`
	TenantID   int64    `db:"tenant_id" json:"tenant_id"`
	Scope      string   `db:"scope" json:"scope"`
	ScopeID    int64    `db:"scope_id" json:"scope_id"`
	Metric     string   `db:"metric" json:"metric"`
	LabelMatch string   `db:"label_match" json:"label_match"`
	Warn       *float64 `db:"warn" json:"warn"`
	Crit       *float64 `db:"crit" json:"crit"`
	ForCount   int      `db:"for_count" json:"for_count"`
	Enabled    bool     `db:"enabled" json:"enabled"`
	Notify     bool     `db:"notify" json:"notify"`
	CreatedAt  int64    `db:"created_at" json:"created_at"`
	UpdatedAt  int64    `db:"updated_at" json:"updated_at"`
}

type Alert struct {
	ID             int64    `db:"id" json:"id"`
	TenantID       int64    `db:"tenant_id" json:"tenant_id"`
	HostID         *int64   `db:"host_id" json:"host_id"`
	CheckID        *int64   `db:"check_id" json:"check_id"`
	Key            string   `db:"key" json:"key"`
	Source         string   `db:"source" json:"source"`
	Metric         string   `db:"metric" json:"metric"`
	Labels         string   `db:"labels" json:"labels"`
	Severity       string   `db:"severity" json:"severity"`
	Status         string   `db:"status" json:"status"`
	Title          string   `db:"title" json:"title"`
	Message        string   `db:"message" json:"message"`
	Value          *float64 `db:"value" json:"value"`
	Threshold      *float64 `db:"threshold" json:"threshold"`
	PendingCount   int      `db:"pending_count" json:"pending_count"`
	StartedAt      int64    `db:"started_at" json:"started_at"`
	FiredAt        int64    `db:"fired_at" json:"fired_at"`
	ResolvedAt     int64    `db:"resolved_at" json:"resolved_at"`
	LastEvalAt     int64    `db:"last_eval_at" json:"last_eval_at"`
	AckedBy        string   `db:"acked_by" json:"acked_by"`
	AckedAt        int64    `db:"acked_at" json:"acked_at"`
	AckComment     string   `db:"ack_comment" json:"ack_comment"`
	Flapping       bool     `db:"flapping" json:"flapping"`
	Transitions    IntList  `db:"transitions" json:"-"`
	LastNotifiedAt int64    `db:"last_notified_at" json:"last_notified_at"`
	NotifyCount    int      `db:"notify_count" json:"notify_count"`
	Muted          bool     `db:"muted" json:"muted"`
	HostName       string   `db:"-" json:"host_name,omitempty"`
	InMaintenance  bool     `db:"-" json:"in_maintenance"`
	SuppressedBy   string   `db:"-" json:"suppressed_by,omitempty"` // e.g. "parent web-1 is down"
	stage          int
}

type AlertEvent struct {
	ID        int64  `db:"id" json:"id"`
	TenantID  int64  `db:"tenant_id" json:"tenant_id"`
	AlertID   int64  `db:"alert_id" json:"alert_id"`
	HostID    *int64 `db:"host_id" json:"host_id"`
	Event     string `db:"event" json:"event"`
	Severity  string `db:"severity" json:"severity"`
	Message   string `db:"message" json:"message"`
	Actor     string `db:"actor" json:"actor"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
	Title     string `db:"title" json:"title,omitempty"`
	HostName  string `db:"host_name" json:"host_name,omitempty"`
}

type MaintenanceWindow struct {
	ID              int64   `db:"id" json:"id"`
	TenantID        int64   `db:"tenant_id" json:"tenant_id"`
	Name            string  `db:"name" json:"name"`
	Scope           string  `db:"scope" json:"scope"`
	ScopeIDs        IntList `db:"scope_ids" json:"scope_ids"`
	StartsAt        int64   `db:"starts_at" json:"starts_at"`
	EndsAt          int64   `db:"ends_at" json:"ends_at"`
	Recurrence      string  `db:"recurrence" json:"recurrence"`
	Weekdays        IntList `db:"weekdays" json:"weekdays"`
	StartTime       string  `db:"start_time" json:"start_time"`
	DurationMinutes int     `db:"duration_minutes" json:"duration_minutes"`
	Timezone        string  `db:"timezone" json:"timezone"`
	SuppressAlerts  bool    `db:"suppress_alerts" json:"suppress_alerts"`
	AllowJobs       bool    `db:"allow_jobs" json:"allow_jobs"`
	Enabled         bool    `db:"enabled" json:"enabled"`
	CreatedBy       string  `db:"created_by" json:"created_by"`
	CreatedAt       int64   `db:"created_at" json:"created_at"`
	ActiveNow       bool    `db:"-" json:"active_now"`
	NextStart       int64   `db:"-" json:"next_start"`
	NextEnd         int64   `db:"-" json:"next_end"`
}

type NotificationChannel struct {
	ID            int64   `db:"id" json:"id"`
	TenantID      int64   `db:"tenant_id" json:"tenant_id"`
	Name          string  `db:"name" json:"name"`
	Type          string  `db:"type" json:"type"`
	Config        JSON    `db:"config" json:"config"`
	MinSeverity   string  `db:"min_severity" json:"min_severity"`
	SendResolved  bool    `db:"send_resolved" json:"send_resolved"`
	RepeatMinutes int     `db:"repeat_minutes" json:"repeat_minutes"`
	FilterGroups  IntList `db:"filter_groups" json:"filter_groups"`
	FilterTags    StrList `db:"filter_tags" json:"filter_tags"`
	FilterHosts   IntList `db:"filter_hosts" json:"filter_hosts"`
	Enabled       bool    `db:"enabled" json:"enabled"`
	LastError     string  `db:"last_error" json:"last_error"`
	LastSentAt    int64   `db:"last_sent_at" json:"last_sent_at"`
	CreatedAt     int64   `db:"created_at" json:"created_at"`
}

type Job struct {
	ID             string `db:"id" json:"id"`
	TenantID       int64  `db:"tenant_id" json:"tenant_id"`
	HostID         int64  `db:"host_id" json:"host_id"`
	Type           string `db:"type" json:"type"`
	Params         JSON   `db:"params" json:"params"`
	DryRun         bool   `db:"dry_run" json:"dry_run"`
	Status         string `db:"status" json:"status"`
	Schedule       string `db:"schedule" json:"schedule"`
	RunAfter       int64  `db:"run_after" json:"run_after"`
	ExpiresAt      int64  `db:"expires_at" json:"expires_at"`
	TimeoutSeconds int    `db:"timeout_seconds" json:"timeout_seconds"`
	RequestedBy    string `db:"requested_by" json:"requested_by"`
	ConfirmedBy    string `db:"confirmed_by" json:"confirmed_by"`
	CreatedAt      int64  `db:"created_at" json:"created_at"`
	SentAt         int64  `db:"sent_at" json:"sent_at"`
	StartedAt      int64  `db:"started_at" json:"started_at"`
	FinishedAt     int64  `db:"finished_at" json:"finished_at"`
	ExitCode       *int   `db:"exit_code" json:"exit_code"`
	Error          string `db:"error" json:"error"`
	OperatorKeyID  string `db:"operator_key_id" json:"operator_key_id,omitempty"`
	Output         string `db:"output" json:"output,omitempty"`
	ResultJSON     string `db:"result_json" json:"result_json,omitempty"`
	HostName       string `db:"host_name" json:"host_name,omitempty"`
}

const jobCols = `j.id, j.tenant_id, j.host_id, j.type, j.params, j.dry_run, j.status, j.schedule, j.run_after, j.expires_at,
 j.timeout_seconds, j.requested_by, j.confirmed_by, j.created_at, j.sent_at, j.started_at, j.finished_at, j.exit_code, j.error, j.operator_key_id`

type Package struct {
	TenantID int64  `db:"tenant_id" json:"-"`
	HostID   int64  `db:"host_id" json:"host_id"`
	Name     string `db:"name" json:"name"`
	Version  string `db:"version" json:"version"`
	Arch     string `db:"arch" json:"arch"`
	Type     string `db:"type" json:"type"`
	Source   string `db:"source" json:"source"`
	// SourceVersion is the source package's version (deb), when it differs from Version.
	SourceVersion string `db:"source_version" json:"source_version,omitempty"`
	NewVersion    string `db:"new_version" json:"new_version"`
	Security      bool   `db:"security" json:"security"`
	KB            string `db:"kb" json:"kb"`
	Publisher     string `db:"publisher" json:"publisher"`
}

type InventoryStatus struct {
	TenantID        int64  `db:"tenant_id" json:"-"`
	HostID          int64  `db:"host_id" json:"host_id"`
	PackageManager  string `db:"package_manager" json:"package_manager"`
	InstalledCount  int    `db:"installed_count" json:"installed_count"`
	UpgradableCount int    `db:"upgradable_count" json:"upgradable_count"`
	SecurityCount   int    `db:"security_count" json:"security_count"`
	Error           string `db:"error" json:"error"`
	UpdatedAt       int64  `db:"updated_at" json:"updated_at"`
}

type VulnFinding struct {
	ID           int64   `db:"id" json:"id"`
	TenantID     int64   `db:"tenant_id" json:"tenant_id"`
	HostID       int64   `db:"host_id" json:"host_id"`
	VulnID       string  `db:"vuln_id" json:"vuln_id"`
	Package      string  `db:"package" json:"package"`
	Version      string  `db:"version" json:"version"`
	FixedVersion string  `db:"fixed_version" json:"fixed_version"`
	FixState     string  `db:"fix_state" json:"fix_state"`
	Severity     string  `db:"severity" json:"severity"`
	CVSS         float64 `db:"cvss" json:"cvss"`
	CVSSVector   string  `db:"cvss_vector" json:"cvss_vector"`
	EPSS         float64 `db:"epss" json:"epss"`
	KEV          bool    `db:"kev" json:"kev"`
	Description  string  `db:"description" json:"description"`
	URLs         StrList `db:"urls" json:"urls"`
	Namespace    string  `db:"namespace" json:"namespace"`
	Status       string  `db:"status" json:"status"`
	FirstSeenAt  int64   `db:"first_seen_at" json:"first_seen_at"`
	LastSeenAt   int64   `db:"last_seen_at" json:"last_seen_at"`
	FixedAt      int64   `db:"fixed_at" json:"fixed_at"`
	HostName     string  `db:"host_name" json:"host_name,omitempty"`

	// Filled in by the API from the host's package inventory.
	AvailableVersion string `db:"-" json:"available_version"`
	Upgradable       bool   `db:"-" json:"upgradable"`
	OS               string `db:"-" json:"os"`

	// Kernel remediation (see kernels.go).
	KernelABI   string   `db:"-" json:"kernel_abi"`
	Remediation string   `db:"-" json:"remediation"`
	Inactive    bool     `db:"-" json:"inactive"`
	KernelMeta  []string `db:"-" json:"kernel_meta,omitempty"`
}

type VulnScan struct {
	ID          int64  `db:"id" json:"id"`
	TenantID    int64  `db:"tenant_id" json:"tenant_id"`
	HostID      int64  `db:"host_id" json:"host_id"`
	Status      string `db:"status" json:"status"`
	TriggeredBy string `db:"triggered_by" json:"triggered_by"`
	Packages    int    `db:"packages" json:"packages"`
	Findings    int    `db:"findings" json:"findings"`
	Critical    int    `db:"critical" json:"critical"`
	High        int    `db:"high" json:"high"`
	Medium      int    `db:"medium" json:"medium"`
	Low         int    `db:"low" json:"low"`
	DBBuilt     string `db:"db_built" json:"db_built"`
	Error       string `db:"error" json:"error"`
	StartedAt   int64  `db:"started_at" json:"started_at"`
	FinishedAt  int64  `db:"finished_at" json:"finished_at"`
	HostName    string `db:"host_name" json:"host_name,omitempty"`
}

type VulnSchedule struct {
	ID        int64  `db:"id" json:"id"`
	TenantID  int64  `db:"tenant_id" json:"tenant_id"`
	Scope     string `db:"scope" json:"scope"`
	ScopeID   int64  `db:"scope_id" json:"scope_id"`
	Frequency string `db:"frequency" json:"frequency"`
	Weekday   int    `db:"weekday" json:"weekday"`
	TimeOfDay string `db:"time_of_day" json:"time_of_day"`
	Enabled   bool   `db:"enabled" json:"enabled"`
	LastRunAt int64  `db:"last_run_at" json:"last_run_at"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
}

type UpdateSchedule struct {
	ID           int64  `db:"id" json:"id"`
	TenantID     int64  `db:"tenant_id" json:"tenant_id"`
	Name         string `db:"name" json:"name"`
	Scope        string `db:"scope" json:"scope"`
	ScopeID      int64  `db:"scope_id" json:"scope_id"`
	Frequency    string `db:"frequency" json:"frequency"`
	Weekday      int    `db:"weekday" json:"weekday"`
	MonthDay     int    `db:"month_day" json:"month_day"`
	TimeOfDay    string `db:"time_of_day" json:"time_of_day"`
	SecurityOnly bool   `db:"security_only" json:"security_only"`
	Enabled      bool   `db:"enabled" json:"enabled"`
	LastRunAt    int64  `db:"last_run_at" json:"last_run_at"`
	LastResult   JSON   `db:"last_result" json:"last_result"`
	CreatedAt    int64  `db:"created_at" json:"created_at"`
}

type StatusPage struct {
	ID           int64  `db:"id" json:"id"`
	TenantID     int64  `db:"tenant_id" json:"tenant_id"`
	Slug         string `db:"slug" json:"slug"`
	Title        string `db:"title" json:"title"`
	Description  string `db:"description" json:"description"`
	Public       bool   `db:"public" json:"public"`
	AccessToken  string `db:"access_token" json:"access_token,omitempty"`
	Items        JSON   `db:"items" json:"items"`
	ShowHistory  bool   `db:"show_history" json:"show_history"`
	Announcement string `db:"announcement" json:"announcement"`
	CreatedAt    int64  `db:"created_at" json:"created_at"`
	UpdatedAt    int64  `db:"updated_at" json:"updated_at"`
}

type StatusPageItem struct {
	Type  string `json:"type"` // host, check
	ID    int64  `json:"id"`
	Label string `json:"label"`
}

type AuditEntry struct {
	ID         int64  `db:"id" json:"id"`
	TenantID   int64  `db:"tenant_id" json:"tenant_id"`
	UserID     *int64 `db:"user_id" json:"user_id"`
	Actor      string `db:"actor" json:"actor"`
	Action     string `db:"action" json:"action"`
	TargetType string `db:"target_type" json:"target_type"`
	TargetID   string `db:"target_id" json:"target_id"`
	Details    JSON   `db:"details" json:"details"`
	IP         string `db:"ip" json:"ip"`
	CreatedAt  int64  `db:"created_at" json:"created_at"`
}

type APIKey struct {
	ID         int64   `db:"id" json:"id"`
	TenantID   int64   `db:"tenant_id" json:"tenant_id"`
	UserID     int64   `db:"user_id" json:"user_id"`
	Name       string  `db:"name" json:"name"`
	Prefix     string  `db:"prefix" json:"prefix"`
	KeyHash    string  `db:"key_hash" json:"-"`
	Scopes     StrList `db:"scopes" json:"scopes"`
	ExpiresAt  int64   `db:"expires_at" json:"expires_at"`
	LastUsedAt int64   `db:"last_used_at" json:"last_used_at"`
	CreatedAt  int64   `db:"created_at" json:"created_at"`
	Username   string  `db:"username" json:"username,omitempty"`
}

type EnrollmentToken struct {
	ID         int64   `db:"id" json:"id"`
	TenantID   int64   `db:"tenant_id" json:"tenant_id"`
	TokenHash  string  `db:"token_hash" json:"-"`
	GroupID    *int64  `db:"group_id" json:"group_id"`
	Tags       StrList `db:"tags" json:"tags"`
	HostName   string  `db:"host_name" json:"host_name"`
	CreatedBy  *int64  `db:"created_by" json:"created_by"`
	ExpiresAt  int64   `db:"expires_at" json:"expires_at"`
	UsedAt     int64   `db:"used_at" json:"used_at"`
	UsedByHost *int64  `db:"used_by_host" json:"used_by_host"`
	CreatedAt  int64   `db:"created_at" json:"created_at"`
}

type IPBlock struct {
	ID        int64  `db:"id" json:"id"`
	TenantID  int64  `db:"tenant_id" json:"tenant_id"`
	HostID    int64  `db:"host_id" json:"host_id"`
	IP        string `db:"ip" json:"ip"`
	Reason    string `db:"reason" json:"reason"`
	ExpiresAt int64  `db:"expires_at" json:"expires_at"`
	JobID     string `db:"job_id" json:"job_id"`
	Status    string `db:"status" json:"status"`
	CreatedBy string `db:"created_by" json:"created_by"`
	CreatedAt int64  `db:"created_at" json:"created_at"`
}

type LLDPNeighbor struct {
	TenantID       int64  `db:"tenant_id" json:"-"`
	HostID         int64  `db:"host_id" json:"host_id"`
	LocalPort      string `db:"local_port" json:"local_port"`
	RemoteChassis  string `db:"remote_chassis" json:"remote_chassis"`
	RemotePort     string `db:"remote_port" json:"remote_port"`
	RemotePortDesc string `db:"remote_port_desc" json:"remote_port_desc"`
	RemoteSysName  string `db:"remote_sysname" json:"remote_sysname"`
	RemoteSysDesc  string `db:"remote_sysdesc" json:"remote_sysdesc"`
	RemoteMgmtAddr string `db:"remote_mgmt_addr" json:"remote_mgmt_addr"`
	UpdatedAt      int64  `db:"updated_at" json:"updated_at"`
	RemoteHostID   *int64 `db:"-" json:"remote_host_id,omitempty"`
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func ptr[T any](v T) *T { return &v }
