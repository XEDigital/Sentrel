// Types mirroring the server's JSON (snake_case as served).

import type { HostSettingsMap } from './inherit'

export type Severity = 'warning' | 'critical'

export interface Branding {
  product_name: string
  logo_data_url: string
  favicon_data_url: string
  accent_color: string
  login_text: string
  footer_text: string
}

export interface User {
  id: number
  tenant_id: number
  username: string
  email: string
  display_name: string
  role: string
  auth_source: string
  totp_enabled: boolean
  disabled: boolean
  must_change_password: boolean
  theme: string
  created_at: number
  last_login_at: number
  passkey_count: number
}

export interface Tenant {
  id: number
  name: string
  slug: string
  hostname: string
  disabled: boolean
  notes: string
  created_at: number
}

export interface Me {
  user: User
  permissions: string[]
  tenant: Tenant
  mfa_pending: boolean
  mfa_setup_required: boolean
  mfa_methods: string[]
  csrf_token: string
  branding: Branding
  server_url: string
  version: string
  api_key: boolean
  password_change_required: boolean
}

export interface HostSummary {
  cpu?: number | null
  memory?: number | null
  disk?: number | null
  load?: number | null
  uptime?: number | null
}

export interface HostInfo {
  hostname?: string
  os?: string
  platform?: string
  platform_family?: string
  platform_version?: string
  kernel_version?: string
  arch?: string
  cpu_model?: string
  cpu_cores?: number
  memory_total?: string | number
  boot_time?: string | number
  ip_addresses?: string[]
  virtualization?: string
  os_id?: string
  os_version_id?: string
}

export interface Host {
  parent?: DepParent
  id: number
  tenant_id: number
  kind: 'agent' | 'snmp' | 'target'
  name: string
  address: string
  group_id: number | null
  tags: string[] | null
  notes: string
  agent_id: string | null
  cert_expires_at: number
  revoked: boolean
  agent_version: string
  host_info: HostInfo
  state?: HostState
  status: 'pending' | 'up' | 'down' | 'unknown'
  last_seen_at: number
  connected: boolean
  reboot_required: boolean
  interval_seconds: number | null
  inventory_interval: number | null
  retention_days: number | null
  agent_options: AgentOptions | null
  allow_upgrades: boolean
  allow_cleanup?: boolean
  auto_remove_old_kernels?: boolean
  allow_ip_block: boolean
  auto_block: boolean
  /** How the agent treats jobs that change the host (set locally on the agent). */
  write_policy?: 'server' | 'operator' | 'none'
  operator_key_ids?: string[]
  snmp_info: SNMPInfo | null
  storage_bytes: number
  created_at: number
  group_name?: string
  tenant_name?: string
  alert_count: number
  alert_severity?: string
  upgrade_count: number
  security_count: number
  vuln_critical: number
  vuln_high: number
  in_maintenance: boolean
  summary?: HostSummary | null
}

export interface AgentOptions {
  top_processes?: number
  collect_services?: boolean
  collect_ports?: boolean
  collect_docker?: boolean
  collect_temperatures?: boolean
  bruteforce_enabled?: boolean
  fail2ban_enabled?: boolean
  portscan_enabled?: boolean
  portscan_threshold_per_min?: number
  portscan_allowlist?: string[]
  refresh_package_index?: boolean
  watched_services?: string[]
}

export interface HostDetail extends Host {
  inventory: InventoryStatus | null
  connection: { remote: string; since: number; mtls: boolean } | null
  agent_config: Record<string, unknown> | null
  snmp_config?: Record<string, any>
  latest_agent_version: string
  check_count: number
  open_findings: Record<string, number>
  /** Distinct open CVEs of this host: per severity, total and fixable-now. */
  vuln_counts?: import('./vulns').VulnCounts
  vuln_enabled?: boolean
  inactive_findings?: number
  /** Inheritable security and permission settings with their global defaults. */
  settings?: HostSettingsMap
  /** Addresses that are never blocked (the server itself). */
  never_block_system?: string[]
}

export interface InventoryStatus {
  host_id: number
  package_manager: string
  installed_count: number
  upgradable_count: number
  security_count: number
  error: string
  updated_at: number
}

export interface Disk {
  mountpoint: string
  device?: string
  fstype?: string
  total?: string | number
  used?: string | number
  used_percent?: number
  inodes_total?: string | number
  inodes_used?: string | number
  fill_eta_seconds?: number
  growth_bytes_per_hour?: number
}

export interface HostState {
  ts_ms?: string
  uptime_seconds?: string | number
  disks?: Disk[]
  interfaces?: { name: string; addresses?: string[]; mac?: string; up?: boolean; bytes_sent?: string; bytes_recv?: string; errors_in?: string; errors_out?: string }[]
  services?: { name: string; display_name?: string; state?: string; sub_state?: string; start_type?: string }[]
  ports?: { protocol: string; address?: string; port: number; pid?: number; process?: string }[]
  top_processes?: { pid: number; name?: string; user?: string; cpu_percent?: number; memory_percent?: number; rss?: string | number; cmdline?: string }[]
  containers?: { id: string; name: string; image?: string; state?: string; status?: string; restart_count?: number; cpu_percent?: number; memory_usage?: string | number; memory_limit?: string | number; health?: string }[]
  temperatures?: { sensor: string; celsius: number }[]
  reboot_required?: boolean
  reboot_required_packages?: string[]
  process_count?: number
  collection_errors?: string[]
  docker_available?: boolean
  blocked_ips?: { ip: string; expires_unix?: string; backend?: string }[]
}

export interface SNMPInterface {
  index: number
  name: string
  descr: string
  alias: string
  type: number
  speed_bps: number
  mac: string
  admin_up: boolean
  oper_up: boolean
  in_bps: number
  out_bps: number
  util_percent: number
}

export interface SNMPInfo {
  system?: { descr: string; object_id: string; name: string; location: string; contact: string; uptime_seconds: number }
  profile?: string
  interfaces?: SNMPInterface[]
  errors?: string[]
  last_poll?: number
  last_error?: string
  duration_ms?: number
  metrics?: Record<string, number>
}

export interface HostGroup {
  id: number
  tenant_id: number
  name: string
  description: string
  color: string
  host_count: number
}

/** The host or check a host/check depends on; its alerts are withheld while the parent is down. */
export interface DepParent {
  type: 'host' | 'check'
  id: number
  name: string
  down: boolean
}

export interface Check {
  id: number
  tenant_id: number
  host_id: number | null
  name: string
  type: string
  target: string
  config: Record<string, any>
  interval_seconds: number
  timeout_seconds: number
  failure_threshold: number
  severity: Severity
  enabled: boolean
  status: 'pending' | 'up' | 'down' | 'warning'
  consecutive_failures: number
  last_message: string
  last_latency_ms: number
  last_checked_at: number
  last_change_at: number
  host_name?: string
  uptime_24h?: number
  /** Push checks: URL token (only returned to users who can edit checks) and the last beat. */
  push_token?: string
  last_beat_at?: number
  parent?: DepParent
}

export interface Alert {
  id: number
  tenant_id: number
  host_id: number | null
  check_id: number | null
  key: string
  source: string
  metric: string
  labels: string
  severity: Severity
  status: 'pending' | 'firing' | 'resolved'
  title: string
  message: string
  value: number | null
  threshold: number | null
  pending_count: number
  started_at: number
  fired_at: number
  resolved_at: number
  acked_by: string
  acked_at: number
  ack_comment: string
  flapping: boolean
  muted?: boolean
  last_notified_at: number
  notify_count: number
  host_name?: string
  in_maintenance: boolean
  /** e.g. "parent web-1 is down": notifications are withheld. */
  suppressed_by?: string
}

export interface AlertEvent {
  id: number
  alert_id: number
  host_id: number | null
  event: string
  severity: string
  message: string
  actor: string
  created_at: number
  title?: string
  host_name?: string
}

export interface MetricDef {
  key: string
  name: string
  sample: string
  label_key: string
  unit: string
  lower_is_worse: boolean
  description: string
}

export interface ThresholdRule {
  id: number
  tenant_id: number
  scope: 'global' | 'group' | 'host'
  scope_id: number
  metric: string
  label_match: string
  warn: number | null
  crit: number | null
  for_count: number
  enabled: boolean
  notify?: boolean
}

export interface EffectiveRule {
  rule: ThresholdRule
  origin: 'host' | 'group' | 'tenant' | 'provider'
}

export interface MergedRule {
  metric: MetricDef
  effective: EffectiveRule | null
  label_overrides: EffectiveRule[] | null
  chain: EffectiveRule[] | null
}

export interface MaintenanceWindow {
  id: number
  tenant_id: number
  name: string
  scope: 'all' | 'tenant' | 'group' | 'host'
  scope_ids: number[] | null
  starts_at: number
  ends_at: number
  recurrence: 'none' | 'daily' | 'weekly' | 'monthly'
  weekdays: number[] | null
  start_time: string
  duration_minutes: number
  timezone: string
  suppress_alerts: boolean
  allow_jobs: boolean
  enabled: boolean
  created_by: string
  active_now: boolean
  next_start: number
  next_end: number
}

export interface Channel {
  id: number
  tenant_id: number
  name: string
  type: string
  config: Record<string, any>
  min_severity: Severity
  send_resolved: boolean
  repeat_minutes: number
  filter_groups: number[] | null
  filter_tags: string[] | null
  filter_hosts: number[] | null
  enabled: boolean
  last_error: string
  last_sent_at: number
}

export interface Job {
  id: string
  tenant_id: number
  host_id: number
  type: string
  params: Record<string, string>
  dry_run: boolean
  status: string
  schedule: string
  run_after: number
  expires_at: number
  timeout_seconds: number
  requested_by: string
  confirmed_by: string
  created_at: number
  sent_at: number
  started_at: number
  finished_at: number
  exit_code: number | null
  error: string
  operator_key_id?: string
  output?: string
  result_json?: string
  host_name?: string
}

export interface Package {
  host_id: number
  name: string
  version: string
  arch: string
  type: string
  source: string
  new_version: string
  security: boolean
  kb: string
  publisher: string
}

export type Remediation = 'upgrade' | 'wait' | 'none' | 'remove_old_kernel' | 'reboot' | 'upgrade_kernel'

export interface Finding {
  id: number
  host_id: number
  vuln_id: string
  package: string
  version: string
  fixed_version: string
  available_version?: string
  upgradable?: boolean
  os?: 'linux' | 'windows' | string
  kernel_abi?: string
  remediation?: Remediation
  inactive?: boolean
  kernel_meta?: string[]
  fix_state: string
  severity: string
  cvss: number
  cvss_vector: string
  epss: number
  kev: boolean
  description: string
  urls: string[] | null
  status: string
  first_seen_at: number
  last_seen_at: number
  host_name?: string
}

export interface VulnScan {
  id: number
  host_id: number
  status: string
  triggered_by: string
  packages: number
  findings: number
  critical: number
  high: number
  medium: number
  low: number
  db_built: string
  error: string
  started_at: number
  finished_at: number
  host_name?: string
}

export interface StatusPageItem {
  type: 'host' | 'check'
  id: number
  label: string
}

export interface StatusPage {
  id: number
  tenant_id: number
  slug: string
  title: string
  description: string
  public: boolean
  access_token?: string
  items: StatusPageItem[] | null
  show_history: boolean
  announcement: string
}

export interface APIKey {
  id: number
  tenant_id: number
  user_id: number
  name: string
  prefix: string
  scopes: string[]
  expires_at: number
  last_used_at: number
  created_at: number
  username?: string
}

export interface AuditEntry {
  id: number
  tenant_id: number
  actor: string
  action: string
  target_type: string
  target_id: string
  details: any
  ip: string
  created_at: number
}

export interface Series {
  name: string
  metric: string
  labels: Record<string, string>
  points: [number, number][] | null
}

/** One day of a host's uptime history (GET /hosts/beats). */
export interface HostBeat {
  day: string
  uptime: number | null
}

/** One check result (GET /checks/beats). */
export interface CheckBeat {
  t: number
  ok: boolean
  latency_ms: number | null
}

export interface DiskUsageEntry {
  path: string
  bytes: number
  depth: number
}

export interface DiskUsageFile {
  path: string
  bytes: number
}

export interface DiskUsageReport {
  mount: string
  status: 'none' | 'running' | 'done' | 'failed'
  job_id: string
  created_at: number
  total_bytes: number
  used_bytes: number
  entries: DiskUsageEntry[] | null
  largest_files: DiskUsageFile[] | null
  error: string
}

export interface CleanupTask {
  id: string
  name: string
  description: string
}


export interface InstallPackage {
  os: 'linux' | 'windows'
  arch: 'amd64' | 'arm64'
  format: 'deb' | 'rpm' | 'msi' | 'binary'
  file: string
  size: number
  sha256: string
  url: string
}

/** GET /agents/install-info: how to install an agent from this server. */
export interface InstallInfo {
  version: string
  server_url: string
  server_url_set: boolean
  tls_mode: 'http' | 'selfsigned' | 'acme'
  ca_fingerprint: string
  /** Base64 SHA-256 of the server certificate's SPKI (self-signed mode only). */
  spki_sha256: string
  /** PowerShell that installs the certificate pin check for $p (self-signed mode only). */
  ps_pin_check?: string
  packages: InstallPackage[]
}

export interface EnrolmentToken {
  id: number
  token: string
  expires_at: number
  server_url: string
  ca_fingerprint?: string
  spki_sha256?: string
  tls_mode: string
  commands: Record<string, string>
}

export interface KernelInfo {
  abi: string
  packages: string[]
  running: boolean
  newest: boolean
  removable: boolean
  /** CVEs that exist only in this kernel: removing it resolves them. */
  cve_count: number
  critical: number
  high: number
}

export interface HostKernels {
  running: string
  installed: KernelInfo[]
  reboot_required: boolean
  reboot_pending: boolean
  allow_upgrades: boolean
  write_policy: string
  removable_cves: number
  removable_critical: number
}

export interface FleetKernelHost {
  host_id: number
  host_name: string
  running: string
  removable: { abi: string; cve_count: number; critical: number }[]
  reboot_pending: boolean
  allow_upgrades: boolean
  write_policy: string
  resolves: number
  resolves_critical: number
}

export interface UpdateScheduleSkip { host_id: number; host: string; reason: string }
export interface UpdateSchedule {
  id: number
  tenant_id: number
  name: string
  scope: 'all' | 'tenant' | 'group' | 'host'
  scope_id: number
  frequency: 'daily' | 'weekly' | 'monthly' | 'maintenance'
  weekday: number
  month_day: number
  time_of_day: string
  security_only: boolean
  enabled: boolean
  last_run_at: number
  last_result: { queued?: number; skipped?: UpdateScheduleSkip[] } | null
  created_at: number
}

export interface DiskHealthDevice {
  device: string
  model?: string
  serial?: string
  protocol?: string
  health: 'passed' | 'failed' | 'unknown'
  temperature_c?: number
  power_on_hours?: number
  reallocated_sectors?: number
  pending_sectors?: number
  uncorrectable_sectors?: number
  percentage_used?: number
  media_errors?: number
  error?: string
}

export interface DiskHealthRaid {
  name: string
  level: string
  state: string
  members: number
  working: number
  failed_devices: number
  degraded: boolean
  failed: boolean
  sync_action?: string
  sync_percent?: number
  sync_finish?: string
}

export interface DiskHealthPool {
  name: string
  health: string
  size: string
  alloc: string
}

export interface DiskHealthData {
  smart_available: boolean
  smart_reason?: string
  devices: DiskHealthDevice[]
  raid: DiskHealthRaid[]
  zfs_available: boolean
  zfs_error?: string
  pools: DiskHealthPool[]
  zfs_status?: string
}

export interface DiskHealthResp {
  supported: boolean
  known: boolean
  updated_at: number
  data: DiskHealthData
}
