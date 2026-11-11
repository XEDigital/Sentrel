import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowUpCircle, CalendarClock, ChevronDown, DatabaseZap, ExternalLink, RotateCw, ScanSearch, ShieldCheck, Trash2 } from 'lucide-react'
import { errorMessage, get, post, put } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { ago, bytes, dateTime } from '@/lib/format'
import type { FleetKernelHost, Finding, HostDetail, HostKernels, VulnScan } from '@/lib/types'
import { inactiveText, isKernelRemoval, kernelUpgradePackages, remediationBadge, removalBlocker, showsNotInRepos, summarizeFleet } from '@/lib/kernel'
import { BulkRemoveKernelsDialog, RemoveKernelDialog } from '@/components/RemoveKernel'
import { useTenantFilter } from '@/components/Layout'
import { UpgradeDialog } from './host/Packages'
import { CRIT_HIGH_TITLE, FIXABLE_TITLE, findingKBs, nf, type VulnCounts } from '@/lib/vulns'
import { Badge, Button, Card, Checkbox, Empty, ErrorBox, InfoTip, Input, KV, Loading, Modal, Note, PageHeader, Segmented, Stat, Table, Tabs, Td, Th, useToast } from '@/components/ui'

export function sevTone(s: string): 'crit' | 'warn' | 'info' | 'muted' {
  return s === 'Critical' ? 'crit' : s === 'High' ? 'warn' : s === 'Medium' ? 'info' : 'muted'
}

/** Package names of a finding (grouped findings list several, separated by commas). */
function findingPackages(f: Finding): string[] {
  return f.package.split(',').map((x) => x.trim()).filter(Boolean)
}

/** Packages to hand to the upgrade job for a finding: KB ids on Windows, package names elsewhere. */
function upgradePackages(f: Finding): string[] {
  return f.os === 'windows' ? findingKBs(f) : findingPackages(f)
}

/** A small dropdown for secondary actions. */
function ActionMenu({ label, children }: { label: string; children: (close: () => void) => React.ReactNode }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const off = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', off)
    return () => document.removeEventListener('mousedown', off)
  }, [open])
  return (
    <div ref={ref} className="relative">
      <Button aria-label={label} title={label} aria-haspopup="menu" aria-expanded={open} icon={<ChevronDown className="size-4" />} onClick={() => setOpen(!open)} className="px-2" />
      {open && <div role="menu" className="absolute right-0 z-20 mt-1 flex min-w-44 flex-col gap-1 rounded-xl border border-line bg-panel p-1.5 shadow-pop">{children(() => setOpen(false))}</div>}
    </div>
  )
}

/** Loads the host, then opens the upgrade dialog pre-filled with the given packages. */
function UpgradeLauncher({ hostId, packages, onClose }: { hostId: number; packages: string[]; onClose: () => void }) {
  const host = useQuery({ queryKey: ['host', String(hostId)], queryFn: () => get<HostDetail>(`/hosts/${hostId}`) })
  if (host.error) return <Modal open onClose={onClose} title="Upgrade packages" size="sm"><ErrorBox error={host.error} /></Modal>
  if (!host.data) return <Modal open onClose={onClose} title="Upgrade packages" size="sm"><Loading /></Modal>
  return <UpgradeDialog host={host.data} packages={packages} onClose={onClose} />
}

/** Loads the host, then opens the remove-kernel dialog. */
function RemoveKernelLauncher({ hostId, abi, onClose }: { hostId: number; abi: string; onClose: () => void }) {
  const host = useQuery({ queryKey: ['host', String(hostId)], queryFn: () => get<HostDetail>(`/hosts/${hostId}`) })
  if (host.error) return <Modal open onClose={onClose} title="Remove kernel" size="sm"><ErrorBox error={host.error} /></Modal>
  if (!host.data) return <Modal open onClose={onClose} title="Remove kernel" size="sm"><Loading /></Modal>
  return <RemoveKernelDialog host={host.data} abi={abi} onClose={onClose} />
}

const actionBtn = 'mt-0.5 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium'

/** What the user can do about a finding, shown in the "Fixed in" column. */
function FixCell({ x, onUpgrade, onRemove, canUpgrade }: { x: Finding; onUpgrade: (packages: string[]) => void; onRemove: () => void; canUpgrade: boolean }) {
  const badge = remediationBadge(x)
  const fixed = x.fixed_version ? <span className="text-ok-ink">{x.fixed_version}</span> : null
  if (x.remediation === 'remove_old_kernel') {
    return (
      <span>
        {badge && <Badge tone={badge.tone}>{badge.label}</Badge>}
        {isKernelRemoval(x) && canUpgrade && <div><button onClick={(e) => { e.stopPropagation(); onRemove() }} className={`${actionBtn} bg-accent/12 text-accent hover:bg-accent/20`}><Trash2 className="size-3" />Remove kernel {x.kernel_abi}</button></div>}
      </span>
    )
  }
  if (x.remediation === 'reboot') {
    return <span>{fixed}<div className="mt-0.5 inline-flex items-center gap-1 text-[11px] text-warn"><RotateCw className="size-3" />{badge?.label}</div></span>
  }
  if (x.remediation === 'upgrade_kernel') {
    const meta = kernelUpgradePackages(x)
    return (
      <span>
        {fixed}
        {canUpgrade && meta.length > 0 && <div><button onClick={(e) => { e.stopPropagation(); onUpgrade(meta) }} className={`${actionBtn} bg-ok/12 text-ok-ink hover:bg-ok/20`}><ArrowUpCircle className="size-3" />Upgrade kernel</button></div>}
        <div className="text-[11px] text-muted">then reboot</div>
      </span>
    )
  }
  if (!x.fixed_version) return <span className="text-muted">{x.fix_state || 'no fix'}</span>
  if (x.os === 'windows') {
    const kbs = findingKBs(x)
    return (
      <span>
        <span className="text-ok-ink">{kbs.length ? kbs.join(', ') : x.fixed_version}</span>
        {canUpgrade && kbs.length > 0 && <div><button onClick={(e) => { e.stopPropagation(); onUpgrade(kbs) }} className={`${actionBtn} bg-ok/12 text-ok-ink hover:bg-ok/20`}><ArrowUpCircle className="size-3" />Install update{kbs.length > 1 ? 's' : ` ${kbs[0]}`}</button></div>}
        {kbs.length === 0 && <div className="text-[11px] text-muted">Install it from Packages, Windows Update</div>}
      </span>
    )
  }
  if (x.upgradable) {
    return (
      <span>
        <span className="text-ok-ink">{x.fixed_version}</span>
        {canUpgrade && <div><button onClick={(e) => { e.stopPropagation(); onUpgrade(findingPackages(x)) }} className={`${actionBtn} bg-ok/12 text-ok-ink hover:bg-ok/20`}><ArrowUpCircle className="size-3" />Upgrade to {x.available_version}</button></div>}
      </span>
    )
  }
  return <span><span className="text-ok-ink">{x.fixed_version}</span>{showsNotInRepos(x) && <div className="text-[11px] text-muted">Fix {x.fixed_version} not yet in repositories</div>}</span>
}

export function Vulnerabilities() {
  const [tab, setTab] = useState<'hosts' | 'findings' | 'scans'>('hosts')
  const { tenant } = useTenantFilter()
  const { can } = useAuth()
  const toast = useToast()
  const qc = useQueryClient()
  const sum = useQuery({ queryKey: ['vulns', 'summary', tenant], queryFn: () => get<any>('/vulnerabilities/summary', { tenant_id: tenant ?? undefined }), refetchInterval: 30_000 })
  const db = sum.data?.db
  const enableScanning = async () => {
    try { await put('/settings/vuln', { enabled: true }); toast('Vulnerability scanning enabled; downloading the database'); qc.invalidateQueries() } catch (e) { toast(errorMessage(e), 'crit') }
  }
  const totals: VulnCounts = sum.data?.totals || { critical: 0, high: 0, medium: 0, low: 0, other: 0, total: 0, fixable: 0, kev: 0, inactive: 0 }
  const dbs = useQuery({ queryKey: ['vulns', 'db'], queryFn: () => get<any>('/vulnerabilities/db'), refetchInterval: (q) => (q.state.data?.refresh_pending || q.state.data?.db?.updating ? 3000 : 30_000), enabled: !!sum.data?.enabled })
  const refresh = dbs.data
  const scanLeft = refresh?.refresh_scan_remaining || refresh?.refresh_scan_total || 0
  const phase = refresh?.refresh_pending ? (refresh.refresh_phase === 'scanning' ? `Scanning ${nf(scanLeft)} ${scanLeft === 1 ? 'host' : 'hosts'}…` : 'Updating database…') : ''
  const wasPending = useRef(false)
  useEffect(() => {
    if (wasPending.current && !refresh?.refresh_pending) {
      qc.invalidateQueries({ queryKey: ['vulns'] })
      if (refresh?.refresh_phase === 'failed') toast(`Database update failed: ${refresh.refresh_error}`, 'crit')
      else if (refresh?.refresh_phase === 'done') toast('Database updated and all hosts scanned')
    }
    wasPending.current = !!refresh?.refresh_pending
  }, [refresh?.refresh_pending, refresh?.refresh_phase])  // eslint-disable-line react-hooks/exhaustive-deps
  const startRefresh = async () => {
    try { await post('/vulnerabilities/refresh'); toast('Updating the database, then scanning all hosts'); qc.invalidateQueries({ queryKey: ['vulns'] }) } catch (e) { toast(errorMessage(e), 'crit') }
  }
  const kernels = useQuery({ queryKey: ['vulns', 'kernels', tenant], queryFn: () => get<FleetKernelHost[]>('/vulnerabilities/kernels', { tenant_id: tenant ?? undefined }), refetchInterval: 60_000, enabled: !!sum.data?.enabled })
  const [bulk, setBulk] = useState(false)
  const [removeOne, setRemoveOne] = useState<{ hostId: number; abi: string } | null>(null)
  const fleet = summarizeFleet(kernels.data || [])
  if (sum.data && !sum.data.enabled) {
    return (
      <div>
        <PageHeader title="Vulnerabilities" />
        <Card>
          <Empty title="Vulnerability scanning is turned off" icon={<ShieldCheck className="size-8" />}>
            <p>Scanning matches each host's installed packages against a vulnerability database. Enabling it downloads about 3 GB to the server in the background and works best with 2 GB of RAM or more.</p>
            <div className="mt-4">
              {can('settings') ? <Button variant="primary" icon={<DatabaseZap className="size-4" />} onClick={enableScanning}>Enable vulnerability scanning</Button> : <span>Ask an administrator to enable it in Settings.</span>}
            </div>
          </Empty>
        </Card>
      </div>
    )
  }
  return (
    <div>
      <PageHeader title="Vulnerabilities" info="Installed packages are matched against the Grype vulnerability database. Agents only send package lists; nothing is scanned over the network."
        actions={<>
          {phase && <span className="text-sm text-muted" role="status">{phase}</span>}
          <Link to="/jobs?tab=schedules"><Button icon={<CalendarClock className="size-4" />}>Schedules</Button></Link>
          {can('settings') && <Button variant="primary" icon={<DatabaseZap className="size-4" />} loading={!!refresh?.refresh_pending} onClick={startRefresh}>Update database &amp; scan all</Button>}
          {(can('jobs') || can('settings')) && (
            <ActionMenu label="More actions">
              {(close) => <>
                {can('jobs') && <Button variant="ghost" size="sm" className="justify-start" icon={<ScanSearch className="size-4" />} onClick={async () => { close(); try { const r = await post<any>('/vulnerabilities/scan-all'); toast(`${r.queued} scans queued`) } catch (e) { toast(errorMessage(e), 'crit') } }}>Scan all</Button>}
                {can('settings') && <Button variant="ghost" size="sm" className="justify-start" icon={<DatabaseZap className="size-4" />} disabled={db?.updating || !!refresh?.refresh_pending} onClick={async () => { close(); try { await post('/vulnerabilities/db/sync'); toast('Database update started'); qc.invalidateQueries({ queryKey: ['vulns'] }) } catch (e) { toast(errorMessage(e), 'crit') } }}>Update database only</Button>}
              </>}
            </ActionMenu>
          )}
        </>} />
      {db && !db.available && <Note tone="warn" className="mb-4">{db.updating ? 'Downloading the vulnerability database (about 3 GB uncompressed; first download takes several minutes)…' : `The vulnerability database is not available yet${db.last_error ? `: ${db.last_error}` : ''}.`}</Note>}
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Critical" value={nf(totals.critical)} tone={totals.critical ? 'crit' : 'muted'} sub={`of ${nf(totals.total)} total`}
          info={<>Counts are open CVEs, one per host and CVE (a CVE in several packages counts once), at its highest severity. {nf(totals.total)} total across all severities.{totals.inactive > 0 && <span className="mt-1 block">{inactiveText(totals.total, totals.inactive)} CVEs. Findings in a kernel that is installed but not running are counted but are not exploitable and do not raise alerts by default.</span>}</>} />
        <Stat label="High" value={nf(totals.high)} tone={totals.high ? 'warn' : 'muted'} sub={`${nf(totals.critical + totals.high)} critical/high`} />
        <Stat label="Medium" value={nf(totals.medium)} tone="muted" sub={`${nf(totals.low)} low · ${nf(totals.other)} other`} title={`${nf(totals.other)} negligible or unknown severity`} />
        <Stat label="Fixable now" value={nf(totals.fixable)} sub={`of ${nf(totals.total)} total`} info={FIXABLE_TITLE} />
        <Stat label="Known exploited" value={nf(totals.kev)} tone={totals.kev ? 'crit' : 'muted'} sub="CISA KEV" />
      </div>
      {fleet.hosts > 0 && (
        <Card className="mb-4" title={`${fleet.hosts} ${fleet.hosts === 1 ? 'host has' : 'hosts have'} old kernels installed`}
          subtitle={`Removing them resolves ${fleet.cves} CVEs${fleet.critical ? ` (${fleet.critical} critical)` : ''}`}
          info="The running and the newest kernel are always kept."
          actions={can('jobs') && <Button size="sm" variant="primary" icon={<Trash2 className="size-3.5" />} onClick={() => setBulk(true)}>Remove on all eligible hosts</Button>}>
          <ul className="divide-y divide-line/60 text-sm">
            {(kernels.data || []).filter((h) => h.removable.length > 0).map((h) => {
              const blocked = removalBlocker(h)
              return (
                <li key={h.host_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
                  <Link to={`/hosts/${h.host_id}?tab=vulns`} className="font-medium hover:underline">{h.host_name}</Link>
                  <span className="text-xs text-muted">running {h.running}</span>
                  {h.reboot_pending && <Badge tone="warn">reboot pending</Badge>}
                  <span className="ml-auto flex flex-wrap items-center gap-2">
                    {h.removable.map((r) => (
                      <span key={r.abi} className="inline-flex items-center gap-1.5">
                        <span className="mono text-xs">{r.abi}</span><span className="text-xs text-muted">{r.cve_count} CVEs{r.critical ? `, ${r.critical} critical` : ''}</span>
                        {can('jobs') && <Button size="sm" disabled={blocked === 'read-only agent'} title={blocked === 'read-only agent' ? 'This host is read-only' : blocked ? 'A dry run works; enable remote upgrades to remove' : undefined} onClick={() => setRemoveOne({ hostId: h.host_id, abi: r.abi })}>Remove</Button>}
                      </span>
                    ))}
                  </span>
                </li>
              )
            })}
          </ul>
        </Card>
      )}
      {bulk && <BulkRemoveKernelsDialog hosts={(kernels.data || []).filter((h) => h.removable.length > 0)} onClose={() => { setBulk(false); qc.invalidateQueries({ queryKey: ['vulns'] }) }} />}
      {removeOne && <RemoveKernelLauncher hostId={removeOne.hostId} abi={removeOne.abi} onClose={() => { setRemoveOne(null); qc.invalidateQueries({ queryKey: ['vulns'] }) }} />}
      {db?.available && <p className="mb-3 text-xs text-muted">Database built {dateTime(Date.parse(db.built) / 1000)} · schema {db.schema_version} · {bytes(db.size_bytes)} · checked {ago(Date.parse(db.last_check) / 1000)}{sum.data?.queue ? ` · ${sum.data.queue} scans queued` : ''}{db.updating ? ' · updating…' : ''}</p>}
      <Tabs value={tab} onChange={setTab} className="mb-4" tabs={[{ id: 'hosts', label: 'By host' }, { id: 'findings', label: 'All findings' }, { id: 'scans', label: 'Scan history' }]} />
      {tab === 'hosts' && (
        <Card bodyClass="p-0">
          {sum.isLoading ? <Loading /> : !sum.data?.hosts?.length ? <Empty title="No agent hosts" /> : (
            <Table>
              <thead><tr><Th>Host</Th><Th>Critical</Th><Th>High</Th><Th className="hidden sm:table-cell">Medium</Th><Th className="hidden sm:table-cell">Low</Th><Th className="hidden sm:table-cell"><span title="All severities, including negligible and unknown">Total</span></Th><Th className="hidden md:table-cell" title={FIXABLE_TITLE}>Fixable now</Th><Th className="hidden md:table-cell">KEV</Th><Th>Last scan</Th><Th /></tr></thead>
              <tbody>
                {sum.data.hosts.map((h: any) => (
                  <tr key={h.host_id}>
                    <Td><Link to={`/hosts/${h.host_id}?tab=vulns`} className="font-medium hover:underline">{h.host_name}</Link>{h.inactive > 0 && <div className="text-[11px] text-muted" title="CVEs that only affect a kernel that is installed but not running">{inactiveText(h.total, h.inactive)} CVEs</div>}</Td>
                    <Td>{h.critical ? <Badge tone="crit" title={CRIT_HIGH_TITLE}>{nf(h.critical)}</Badge> : 0}</Td>
                    <Td>{h.high ? <Badge tone="warn" title={CRIT_HIGH_TITLE}>{nf(h.high)}</Badge> : 0}</Td>
                    <Td className="hidden sm:table-cell">{nf(h.medium)}</Td><Td className="hidden sm:table-cell">{nf(h.low)}</Td>
                    <Td className="hidden sm:table-cell">{nf(h.total)}</Td>
                    <Td className="hidden md:table-cell">{nf(h.fixable)}</Td><Td className="hidden md:table-cell">{h.kev ? <Badge tone="crit">{h.kev}</Badge> : 0}</Td>
                    <Td className="text-xs">{h.last_scan ? <span title={h.last_error}>{ago(h.last_scan)} <Badge tone={h.last_status === 'completed' ? 'ok' : h.last_status === 'failed' ? 'crit' : 'muted'}>{h.last_status}</Badge></span> : <span className="text-muted">never</span>}</Td>
                    <Td className="text-right">{can('jobs') && <Button size="sm" variant="ghost" icon={<ScanSearch className="size-3.5" />} onClick={async () => { await post(`/hosts/${h.host_id}/scan`); toast('Scan queued') }} />}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      )}
      {tab === 'findings' && <FindingsTable />}
      {tab === 'scans' && <ScanHistory />}
    </div>
  )
}

export function FindingsTable({ hostId }: { hostId?: number }) {
  const { tenant } = useTenantFilter()
  const { can } = useAuth()
  const toast = useToast()
  const qc = useQueryClient()
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('open')
  // ?fixable=1 (the link from a vulnerability alert) opens on what can be fixed now.
  const [fixable, setFixable] = useState(() => new URLSearchParams(window.location.search).get('fixable') === '1')
  const [kev, setKev] = useState(false)
  const [inactive, setInactive] = useState(true)
  const [removeKernel, setRemoveKernel] = useState<{ hostId: number; abi: string } | null>(null)
  const [q, setQ] = useState('')
  const [open, setOpen] = useState<Finding | null>(null)
  const [upgrade, setUpgrade] = useState<{ hostId: number; packages: string[] } | null>(null)
  const fixable_ = useQuery({ queryKey: ['vulns', 'fixable', hostId], queryFn: () => get<Finding[]>('/vulnerabilities', { host_id: hostId, status: 'open', fixable: 1, limit: 2000 }), enabled: !!hostId })
  const f = useQuery({ queryKey: ['vulns', 'findings', hostId, tenant, sev, status, fixable, kev, q, inactive], queryFn: () => get<Finding[]>('/vulnerabilities', { host_id: hostId, tenant_id: tenant ?? undefined, severity: sev, status, fixable: fixable ? 1 : '', kev: kev ? 1 : '', inactive: inactive ? '' : 0, q, limit: 2000 }) })
  const scans = useQuery({ queryKey: ['vulns', 'scans', hostId], queryFn: () => get<VulnScan[]>('/vulnerabilities/scans', { host_id: hostId }), enabled: !!hostId })
  const last = scans.data?.[0]
  const fixablePkgs = Array.from(new Set((fixable_.data || []).filter((x) => x.upgradable).flatMap(upgradePackages)))
  const winFindings = (fixable_.data || []).some((x) => x.os === 'windows')
  const hostIsWindows = winFindings || (f.data || []).some((x) => x.os === 'windows')
  const canUpgrade = can('jobs')
  return (
    <div className="space-y-3">
      {hostId && (
        <div className="flex flex-wrap items-center gap-3">
          {last ? <span className="text-sm text-muted">Last scan {ago(last.started_at)}: <Badge tone={last.status === 'completed' ? 'ok' : last.status === 'failed' ? 'crit' : 'muted'}>{last.status}</Badge> {last.packages} packages, {nf(last.findings)} open CVEs {last.error && <span className="text-crit">— {last.error}</span>}</span> : <span className="text-sm text-muted">Not scanned yet.</span>}
          {canUpgrade && fixablePkgs.length > 0 && <Button size="sm" variant="primary" icon={<ArrowUpCircle className="size-3.5" />} onClick={() => setUpgrade({ hostId, packages: fixablePkgs })}>Upgrade all fixable ({fixablePkgs.length} {winFindings ? (fixablePkgs.length === 1 ? 'update' : 'updates') : (fixablePkgs.length === 1 ? 'package' : 'packages')})</Button>}
          {can('jobs') && <Button size="sm" icon={<ScanSearch className="size-3.5" />} onClick={async () => { try { const r = await post<any>(`/hosts/${hostId}/scan`); toast(r.queued ? 'Scan queued' : r.message, r.queued ? 'ok' : 'info') } catch (e) { toast(errorMessage(e), 'crit') } }}>Scan now</Button>}
        </div>
      )}
      {hostId && <KernelCard hostId={hostId} onRemove={(abi) => setRemoveKernel({ hostId, abi })} />}
      <Card bodyClass="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-line/70 p-4">
          <Segmented value={sev} onChange={setSev} options={[{ id: 'Critical', label: 'Critical' }, { id: 'Critical,High', label: 'High+' }, { id: 'Critical,High,Medium', label: 'Medium+' }, { id: '', label: 'All severities' }]} />
          <Segmented value={status} onChange={setStatus} options={[{ id: 'open', label: 'Open' }, { id: 'ignored', label: 'Ignored' }, { id: 'fixed', label: 'Fixed' }]} />
          <span title={FIXABLE_TITLE}><Checkbox checked={fixable} onChange={setFixable} label="Fixable now" /></span>
          <Checkbox checked={kev} onChange={setKev} label="Known exploited" />
          <Checkbox checked={inactive} onChange={setInactive} label="Include inactive kernels" />
          <Input placeholder="CVE or package" value={q} onChange={(e) => setQ(e.target.value)} className="w-full sm:w-48" />
          {hostIsWindows && <InfoTip>CVEs on Windows come from the security updates Windows Update has pending, and clear once an update is installed. Third-party applications on Windows are not matched to CVEs.</InfoTip>}
        </div>
        {f.isLoading ? <Loading /> : !f.data?.length ? <Empty title="No findings" icon={<ShieldCheck className="size-8 text-ok" />} /> : (
          <Table>
            <thead><tr><Th>Vulnerability</Th><Th>Severity</Th><Th className="hidden sm:table-cell">CVSS</Th><Th>Package</Th><Th className="hidden md:table-cell">Installed</Th><Th className="hidden md:table-cell">Fixed in</Th><Th className="hidden lg:table-cell">Available</Th>{!hostId && <Th className="hidden lg:table-cell">Host</Th>}<Th className="hidden xl:table-cell">First seen</Th></tr></thead>
            <tbody>
              {f.data.map((x) => (
                <tr key={x.id} className="cursor-pointer" onClick={() => setOpen(x)}>
                  <Td className="mono text-xs">{x.vuln_id} {x.kev && <Badge tone="crit">KEV</Badge>}</Td>
                  <Td><Badge tone={sevTone(x.severity)}>{x.severity}</Badge></Td>
                  <Td className="hidden tabular-nums sm:table-cell">{x.cvss ? x.cvss.toFixed(1) : '–'}</Td>
                  <Td className="mono text-xs" title={x.package}>{x.package.split(', ')[0]}{x.package.includes(', ') && <Badge className="ml-1">+{x.package.split(', ').length - 1}</Badge>}{x.kernel_abi && <div className="text-[11px] text-muted">kernel {x.kernel_abi}{x.inactive ? ' · inactive' : ''}</div>}</Td>
                  <Td className="mono hidden text-xs md:table-cell">{x.version}</Td>
                  <Td className="mono hidden text-xs md:table-cell"><FixCell x={x} canUpgrade={canUpgrade} onUpgrade={(pk) => setUpgrade({ hostId: x.host_id, packages: pk })} onRemove={() => setRemoveKernel({ hostId: x.host_id, abi: x.kernel_abi || '' })} /></Td>
                  <Td className="mono hidden text-xs lg:table-cell">{x.available_version || <span className="text-muted">–</span>}</Td>
                  {!hostId && <Td className="hidden text-xs lg:table-cell">{x.host_name}</Td>}
                  <Td className="hidden text-xs text-muted xl:table-cell">{ago(x.first_seen_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {f.data && f.data.length >= 2000 && <p className="p-3 text-xs text-muted">Showing the first 2000 findings; narrow the filters to see more.</p>}
      </Card>
      {open && <FindingModal f={open} onClose={() => { setOpen(null); f.refetch() }} onUpgrade={canUpgrade ? (pk) => { setOpen(null); setUpgrade({ hostId: open.host_id, packages: pk }) } : undefined} onRemove={canUpgrade ? (abi) => { setOpen(null); setRemoveKernel({ hostId: open.host_id, abi }) } : undefined} />}
      {removeKernel && <RemoveKernelLauncher hostId={removeKernel.hostId} abi={removeKernel.abi} onClose={() => { setRemoveKernel(null); f.refetch(); qc.invalidateQueries({ queryKey: ['kernels'] }) }} />}
      {upgrade && <UpgradeLauncher hostId={upgrade.hostId} packages={upgrade.packages} onClose={() => setUpgrade(null)} />}
    </div>
  )
}

/** Summary of the old kernels on one host, with the action that resolves most of its CVEs. */
function KernelCard({ hostId, onRemove }: { hostId: number; onRemove: (abi: string) => void }) {
  const { can } = useAuth()
  const k = useQuery({ queryKey: ['kernels', hostId], queryFn: () => get<HostKernels>(`/hosts/${hostId}/kernels`) })
  const data = k.data
  if (!data) return null
  const old = data.installed.filter((x) => x.removable)
  if (!old.length && !data.reboot_pending) return null
  const blocked = removalBlocker(data)
  return (
    <Card title="Kernels" subtitle={data.running ? `Running ${data.running}` : undefined}>
      <div className="space-y-2 text-sm">
        {old.map((x) => (
          <div key={x.abi} className="flex flex-wrap items-center gap-2">
            <Badge tone="info">Old kernel (not running)</Badge>
            <span>
              Old kernel <span className="mono">{x.abi}</span> is installed but not running
              {x.cve_count > 0 ? <> — removing it resolves {x.cve_count} CVEs{x.critical ? ` (${x.critical} critical)` : ''}</> : <> — removing it frees disk space</>}.
            </span>
            {can('jobs') && <Button size="sm" variant="primary" icon={<Trash2 className="size-3.5" />} disabled={blocked === 'read-only agent'} title={blocked ? `Dry run only: ${blocked}` : undefined} onClick={() => onRemove(x.abi)}>Remove</Button>}
          </div>
        ))}
        {data.reboot_pending && <div className="flex items-center gap-2"><Badge tone="warn">reboot required</Badge><span>Newer kernel installed — reboot to apply. Findings in the running kernel are fixed once the host restarts.</span></div>}
        {old.length > 0 && blocked && <p className="text-xs text-muted">Removal is unavailable here: {blocked}. {blocked === 'remote upgrades off' ? 'A dry run still works.' : ''}</p>}
      </div>
    </Card>
  )
}

function FindingModal({ f, onClose, onUpgrade, onRemove }: { f: Finding; onClose: () => void; onUpgrade?: (packages: string[]) => void; onRemove?: (abi: string) => void }) {
  const { can } = useAuth()
  const toast = useToast()
  const [reason, setReason] = useState('')
  const setStatus = async (status: string) => {
    try { await put(`/vulnerabilities/${f.id}`, { status, reason }); toast(status === 'ignored' ? 'Finding ignored' : 'Finding reopened'); onClose() } catch (e) { toast(errorMessage(e), 'crit') }
  }
  return (
    <Modal open onClose={onClose} title={f.vuln_id} size="lg" footer={can('monitoring') && (f.status === 'ignored'
      ? <Button onClick={() => setStatus('open')}>Reopen</Button>
      : f.status === 'open' ? <><Input placeholder="Reason (e.g. not reachable, mitigated)" value={reason} onChange={(e) => setReason(e.target.value)} className="w-72" /><Button onClick={() => setStatus('ignored')}>Ignore</Button></> : null)}>
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2"><Badge tone={sevTone(f.severity)}>{f.severity}</Badge>{f.kev && <Badge tone="crit">Known exploited (CISA KEV)</Badge>}<Badge>{f.status}</Badge></div>
        <KV items={[
          [f.os === 'windows' ? 'Updates' : 'Packages', <span key="p" className="mono break-all">{f.os === 'windows' ? f.package : `${f.package} (${f.version})`}</span>],
          ['Fixed in', f.fixed_version || f.fix_state || 'no fix available'],
          ['Available in repositories', f.available_version || '–'],
          ['CVSS', f.cvss ? `${f.cvss.toFixed(1)}  ${f.cvss_vector}` : '–'],
          ['EPSS', f.epss ? `${(f.epss * 100).toFixed(2)}% probability of exploitation in 30 days` : '–'],
          ['Host', f.host_name || `#${f.host_id}`],
          ['First seen', dateTime(f.first_seen_at)],
          ['Last seen', dateTime(f.last_seen_at)],
        ]} />
        {f.os === 'windows' && f.fixed_version && <Note>Install the Windows update {findingKBs(f).join(', ') || f.fixed_version} to resolve this CVE. <InfoTip>Severity comes from Microsoft (MSRC); CVSS and exploit data come from the local vulnerability database when it has the CVE.</InfoTip></Note>}
        {f.inactive && <Note>This only affects a kernel that is installed but not running, so it does not raise alerts by default.</Note>}
        {f.remediation === 'remove_old_kernel' && <Note tone="warn">Kernel {f.kernel_abi} is installed but not running. Remove it to resolve this finding; the fix is a different kernel package, so it never appears as an upgrade.</Note>}
        {f.remediation === 'reboot' && <Note tone="warn">A newer kernel is already installed. Reboot the host to run it.</Note>}
        {f.remediation === 'upgrade_kernel' && <Note tone="warn">Upgrade the kernel meta-package ({kernelUpgradePackages(f).join(', ') || 'linux-generic'}), then reboot the host.</Note>}
        {showsNotInRepos(f) && <Note tone="warn">Fix {f.fixed_version} is not yet in the repositories{f.available_version ? ` (latest available: ${f.available_version})` : ''}. It will be offered once the distribution publishes it.</Note>}
        {isKernelRemoval(f) && onRemove && <Button variant="primary" icon={<Trash2 className="size-4" />} onClick={() => onRemove(f.kernel_abi || '')}>Remove kernel {f.kernel_abi}</Button>}
        {f.remediation === 'upgrade_kernel' && onUpgrade && kernelUpgradePackages(f).length > 0 && <Button variant="primary" icon={<ArrowUpCircle className="size-4" />} onClick={() => onUpgrade(kernelUpgradePackages(f))}>Upgrade kernel</Button>}
        {f.upgradable && onUpgrade && <Button variant="primary" icon={<ArrowUpCircle className="size-4" />} onClick={() => onUpgrade(upgradePackages(f))}>{f.os === 'windows' ? `Install update ${findingKBs(f).join(', ')}` : `Upgrade to ${f.available_version}`}</Button>}
        {f.description && <p className="whitespace-pre-line text-sm">{f.description}</p>}
        {!!f.urls?.length && <ul className="space-y-1 text-sm">{f.urls.map((u) => <li key={u}><a href={u} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 break-all text-accent hover:underline">{u}<ExternalLink className="size-3" /></a></li>)}</ul>}
      </div>
    </Modal>
  )
}

function ScanHistory() {
  const s = useQuery({ queryKey: ['vulns', 'scans'], queryFn: () => get<VulnScan[]>('/vulnerabilities/scans'), refetchInterval: 15_000 })
  return (
    <Card bodyClass="p-0">
      {!s.data?.length ? <Empty title="No scans yet" /> : (
        <Table>
          <thead><tr><Th>Host</Th><Th>Status</Th><Th>Trigger</Th><Th className="hidden sm:table-cell">Packages</Th><Th>Findings</Th><Th className="hidden md:table-cell">Started</Th><Th className="hidden lg:table-cell">Duration</Th></tr></thead>
          <tbody>{s.data.map((x) => (
            <tr key={x.id}>
              <Td><Link to={`/hosts/${x.host_id}?tab=vulns`} className="hover:underline">{x.host_name}</Link></Td>
              <Td><Badge tone={x.status === 'completed' ? 'ok' : x.status === 'failed' ? 'crit' : 'muted'}>{x.status}</Badge>{x.error && <div className="max-w-xs truncate text-xs text-muted" title={x.error}>{x.error}</div>}</Td>
              <Td className="text-xs">{x.triggered_by}</Td>
              <Td className="hidden sm:table-cell">{x.packages}</Td>
              <Td className="text-xs">{x.findings} {x.critical > 0 && <Badge tone="crit">{x.critical} crit</Badge>} {x.high > 0 && <Badge tone="warn">{x.high} high</Badge>}</Td>
              <Td className="hidden text-xs md:table-cell">{dateTime(x.started_at)}</Td>
              <Td className="hidden text-xs lg:table-cell">{x.finished_at ? `${x.finished_at - x.started_at}s` : '…'}</Td>
            </tr>
          ))}</tbody>
        </Table>
      )}
    </Card>
  )
}
