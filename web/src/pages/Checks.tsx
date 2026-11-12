import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, ArrowLeft, Pencil, Play, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { del, errorMessage, get, post, put } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { ago, dateTime, LOCALE } from '@/lib/format'
import type { Check, Host } from '@/lib/types'
import { BeatBar, type Beat, checkBeatsToBeats, checkSuccessRate, useCheckBeats } from '@/components/BeatBar'
import { Chart, RangePicker, rangeSeconds, type RangeId } from '@/components/Chart'
import { useTenantFilter } from '@/components/Layout'
import { DependsOn, depBody, depValueOf } from '@/components/DependsOn'
import { Badge, Button, Card, CodeBlock, CopyButton, Empty, ErrorBox, Field, Input, KV, Loading, Modal, PageHeader, Select, StatusDot, Table, Td, Th, Toggle, UptimePill, cx, statusTone, useConfirm, useSort, useToast } from '@/components/ui'

export const checkTypes: { id: string; label: string; agent?: boolean; target: string; hint: string }[] = [
  { id: 'ping', label: 'Ping (ICMP)', target: 'Host or IP', hint: 'e.g. 192.168.1.1' },
  { id: 'tcp', label: 'TCP port', target: 'host:port', hint: 'e.g. db.internal:5432' },
  { id: 'http', label: 'HTTP(S)', target: 'URL', hint: 'https://example.com/health' },
  { id: 'cert', label: 'TLS certificate expiry', target: 'host[:port]', hint: 'example.com:443' },
  { id: 'dns', label: 'DNS record', target: 'Name', hint: 'example.com' },
  { id: 'push', label: 'Push (heartbeat)', target: 'URL', hint: '' },
  { id: 'service', label: 'Service running (agent)', agent: true, target: 'Service name', hint: 'systemd unit or Windows service, e.g. nginx' },
  { id: 'process', label: 'Process exists (agent)', agent: true, target: 'Process name', hint: 'e.g. postgres' },
  { id: 'port', label: 'Port listening (agent)', agent: true, target: 'Port', hint: 'e.g. 443' },
  { id: 'container', label: 'Container running (agent)', agent: true, target: 'Container name', hint: 'Docker container name or ID prefix' },
]

export function Checks() {
  const { can } = useAuth()
  return (
    <div>
      <PageHeader title="Checks" info="Server-side probes (ping, TCP, HTTP, certificates, DNS), push checks that wait for your job to call in, and agent-evaluated checks (services, processes, ports, containers)." />
      <ChecksTable canCreate={can('monitoring')} />
    </div>
  )
}

export function ChecksTable({ hostId, hostKind, tenantId, canCreate = true }: { hostId?: number; hostKind?: string; tenantId?: number; canCreate?: boolean }) {
  const { can } = useAuth()
  const { tenant } = useTenantFilter()
  const qc = useQueryClient()
  const toast = useToast()
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [params, setParams] = useSearchParams()
  const createRequested = !hostId && params.get('new') === '1' && canCreate && can('monitoring')
  const [editing, setEditing] = useState<Partial<Check> | null>(null)
  const editorInitial = editing ?? (createRequested ? { host_id: null, type: 'ping', tenant_id: tenantId } : null)
  const closeEditor = () => {
    setEditing(null)
    if (!hostId && params.get('new') === '1') {
      const next = new URLSearchParams(params)
      next.delete('new')
      setParams(next, { replace: true })
    }
    qc.invalidateQueries({ queryKey: ['checks'] })
  }
  const checks = useQuery({ queryKey: ['checks', hostId ?? 'all', tenant], queryFn: () => get<Check[]>('/checks', { host_id: hostId, tenant_id: hostId ? undefined : tenant ?? undefined }), refetchInterval: 30_000 })
  const beats = useCheckBeats(40, hostId ? undefined : tenant)
  const rows = useMemo(() => (checks.data || []).filter((c) => (!status || c.status === status) && (!q || c.name.toLowerCase().includes(q.toLowerCase()) || c.target.toLowerCase().includes(q.toLowerCase()) || (c.host_name || '').toLowerCase().includes(q.toLowerCase()))), [checks.data, q, status])
  const { sorted, th } = useSort(rows, { key: 'status', dir: 'desc' }, {
    status: (c) => (c.status === 'down' ? 3 : c.status === 'warning' ? 2 : c.status === 'pending' ? 1 : 0),
    name: (c) => c.name.toLowerCase(), latency: (c) => c.last_latency_ms, uptime: (c) => c.uptime_24h ?? -1, checked: (c) => c.last_checked_at,
  })
  return (
    <Card bodyClass="p-0">
      <div className="flex flex-wrap items-center gap-2 border-b border-line/70 p-4">
        <Input placeholder="Filter checks" value={q} onChange={(e) => setQ(e.target.value)} className="w-full sm:w-64" />
        <div className="w-36"><Select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Any status</option><option value="up">Up</option><option value="down">Down</option><option value="warning">Warning</option><option value="pending">Pending</option>
        </Select></div>
        <div className="flex-1" />
        {canCreate && can('monitoring') && <Button variant="primary" size="sm" icon={<Plus className="size-3.5" />} onClick={() => setEditing({ host_id: hostId ?? null, type: hostKind === 'agent' ? 'service' : 'ping', tenant_id: tenantId })}>Add check</Button>}
      </div>
      {checks.isLoading ? <Loading /> : sorted.length === 0 ? <Empty title="No checks" icon={<Activity className="size-8" />}>Checks alert when something stops responding or a service stops running.</Empty> : (
        <Table>
          <thead><tr>
            <Th {...th('status')}>Status</Th><Th {...th('name')}>Check</Th><Th className="hidden md:table-cell">Type</Th>
            {!hostId && <Th className="hidden lg:table-cell">Host</Th>}
            <Th {...th('latency')} className="hidden sm:table-cell">Latency</Th><Th className="hidden md:table-cell">Recent results</Th><Th {...th('uptime')} className="hidden md:table-cell">Uptime</Th>
            <Th className="hidden xl:table-cell">Last result</Th><Th {...th('checked')} className="hidden lg:table-cell">Checked</Th><Th />
          </tr></thead>
          <tbody>
            {sorted.map((c) => (
              <tr key={c.id} className={cx(!c.enabled && 'opacity-50')}>
                <Td><div className="flex items-center gap-2"><StatusDot status={c.status} pulse /><Badge tone={statusTone(c.status)}>{c.enabled ? c.status : 'disabled'}</Badge></div></Td>
                <Td><Link to={`/checks/${c.id}`} className="font-medium hover:underline">{c.name}</Link>{c.type === 'push' ? <div className="text-xs text-muted">{c.last_beat_at ? `last beat ${ago(c.last_beat_at)}` : 'waiting for first beat'}</div> : <div className="mono max-w-xs truncate text-xs text-muted">{c.target}</div>}</Td>
                <Td className="hidden text-xs md:table-cell">{checkTypes.find((t) => t.id === c.type)?.label || c.type}</Td>
                {!hostId && <Td className="hidden text-xs lg:table-cell">{c.host_id ? <Link to={`/hosts/${c.host_id}`} className="hover:underline">{c.host_name}</Link> : <span className="text-muted">–</span>}</Td>}
                <Td className="hidden text-xs tabular-nums sm:table-cell">{c.last_latency_ms ? `${c.last_latency_ms.toFixed(1)} ms` : '–'}</Td>
                <Td className="hidden w-[260px] md:table-cell"><BeatBar beats={checkBeatsToBeats(beats.data?.[String(c.id)])} count={40} height={24} /></Td>
                <Td className="hidden md:table-cell"><UptimePill value={c.uptime_24h ?? checkSuccessRate(beats.data?.[String(c.id)])} title="24h uptime" /></Td>
                <Td className="hidden max-w-sm truncate text-xs text-muted xl:table-cell" title={c.last_message}>{c.last_message}</Td>
                <Td className="hidden text-xs text-muted lg:table-cell">{ago(c.last_checked_at)}</Td>
                <Td className="whitespace-nowrap text-right">
                  {can('monitoring') && <Button size="sm" variant="ghost" icon={<Play className="size-3.5" />} title="Run now" onClick={async () => {
                    try { const r = await post<any>(`/checks/${c.id}/run`); toast(`${c.name}: ${r.up ? 'up' : 'down'} — ${r.message}`, r.up ? 'ok' : 'crit'); qc.invalidateQueries({ queryKey: ['checks'] }) } catch (e) { toast(errorMessage(e), 'crit') }
                  }} />}
                  {can('monitoring') && <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" />} onClick={() => setEditing(c)} />}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {editorInitial && <CheckEditor initial={editorInitial} hostKind={hostKind} onClose={closeEditor} />}
    </Card>
  )
}

export function CheckEditor({ initial, onClose, hostKind }: { initial: Partial<Check>; onClose: () => void; hostKind?: string }) {
  const toast = useToast()
  const confirm = useConfirm()
  const { info } = useAuth()
  const { tenant } = useTenantFilter()
  const hosts = useQuery({ queryKey: ['hosts', 'all'], queryFn: () => get<Host[]>('/hosts') })
  const [c, setC] = useState<Partial<Check>>({
    name: '', type: 'ping', target: '', interval_seconds: 60, timeout_seconds: 10, failure_threshold: 3, severity: 'critical', enabled: true, config: {}, ...initial,
    tenant_id: initial.tenant_id ?? tenant ?? 0,
  })
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const [parent, setParent] = useState(depValueOf(initial.parent))
  const t = checkTypes.find((x) => x.id === c.type)!
  const pushBase = (info?.server_url || window.location.origin).replace(/\/+$/, '')
  const pushURL = c.push_token ? `${pushBase}/api/push/${c.push_token}` : ''
  const regenerate = async () => {
    if (!c.id || !(await confirm({ title: 'Regenerate URL', danger: true, confirmLabel: 'Regenerate', body: <p>The current URL stops working immediately. Update every job that calls it.</p> }))) return
    try { const k = await post<Check>(`/checks/${c.id}/regenerate-token`); setC({ ...c, push_token: k.push_token }); toast('New URL issued') } catch (e) { setErr(e) }
  }
  const cfg = c.config || {}
  const setCfg = (patch: Record<string, unknown>) => setC({ ...c, config: { ...cfg, ...patch } })
  const host = hosts.data?.find((h) => h.id === c.host_id)
  const agentHost = host?.kind === 'agent' || hostKind === 'agent'
  const save = async () => {
    setBusy(true)
    setErr(null)
    try {
      const body = { ...c, name: c.name || (c.type === 'push' ? 'Heartbeat' : `${t.label.split(' (')[0]} ${c.target}`), ...depBody(parent) }
      if (c.id) await put(`/checks/${c.id}`, body)
      else await post('/checks', body)
      toast(c.id ? 'Check updated' : 'Check created')
      onClose()
    } catch (e) {
      setErr(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal open onClose={onClose} title={c.id ? `Edit ${c.name}` : 'Add check'} size="lg"
      footer={<>
        {c.id && <DeleteCheck id={c.id} name={c.name || ''} onDone={onClose} />}
        <div className="flex-1" />
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={busy} onClick={save}>Save</Button>
      </>}>
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Type" info={t.agent ? "Agent checks are evaluated each time the host reports." : undefined}>
            <Select value={c.type} onChange={(e) => setC({ ...c, type: e.target.value, config: {}, ...(c.id ? {} : e.target.value === 'push' ? { interval_seconds: 3600, failure_threshold: 1 } : { interval_seconds: 60, failure_threshold: 3 }) })}>
              {checkTypes.filter((x) => !x.agent || agentHost || !c.host_id).map((x) => <option key={x.id} value={x.id} disabled={x.agent && !agentHost}>{x.label}</option>)}
            </Select>
          </Field>
          <Field label="Attach to host" info={t.agent ? "Required: agent checks are evaluated from the host." : "Optional: groups the check with a host."}>
            <Select value={c.host_id ?? ''} onChange={(e) => setC({ ...c, host_id: e.target.value ? Number(e.target.value) : null })}>
              <option value="">None</option>
              {hosts.data?.map((h) => <option key={h.id} value={h.id}>{h.name} ({h.kind})</option>)}
            </Select>
          </Field>
          {c.type !== 'push' && <Field label={t.target} hint={t.hint} className="sm:col-span-2" required><Input className="mono" value={c.target} onChange={(e) => setC({ ...c, target: e.target.value })} /></Field>}
          <Field label="Name"><Input value={c.name} placeholder={c.type === 'push' ? 'Heartbeat' : `${t.label.split(' (')[0]} ${c.target}`} onChange={(e) => setC({ ...c, name: e.target.value })} /></Field>
          <Field label="Severity when failing">
            <Select value={c.severity} onChange={(e) => setC({ ...c, severity: e.target.value as any })}><option value="critical">Critical</option><option value="warning">Warning</option></Select>
          </Field>
        </div>

        {c.type === 'push' && (
          <div className="space-y-3 rounded-xl border border-line/70 bg-panel-2/40 p-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Expected every (seconds)" info="The check goes down when no beat arrives within the interval plus the grace period."><Input type="number" min={10} value={c.interval_seconds} onChange={(e) => setC({ ...c, interval_seconds: Number(e.target.value) })} /></Field>
              <Field label="Grace (seconds)" info="Extra time allowed after the interval. Default 300."><Input type="number" min={0} value={cfg.grace_seconds ?? ''} placeholder="300" onChange={(e) => setCfg({ grace_seconds: Number(e.target.value) || 0 })} /></Field>
            </div>
            {pushURL ? (
              <>
                <Field label="Push URL" info="Anyone with this URL can report for this check, so keep it private. Add ?status=down&msg=... to report a failure explicitly. Requests are limited to 60 a minute.">
                  <div className="flex items-center gap-1"><Input readOnly className="mono" value={pushURL} onFocus={(e) => e.currentTarget.select()} /><CopyButton text={pushURL} /></div>
                </Field>
                <CodeBlock code={`# success\ncurl -fsS -m 10 --retry 3 ${pushURL}\n\n# failure with a message\ncurl -fsS -m 10 "${pushURL}?status=down&msg=backup+failed"\n\n# cron: report after the job succeeds\n0 3 * * * /usr/local/bin/backup.sh && curl -fsS -m 10 ${pushURL}`} />
                {c.id && <Button size="sm" icon={<RefreshCw className="size-3.5" />} onClick={regenerate}>Regenerate URL</Button>}
              </>
            ) : <p className="text-xs text-muted">{c.id ? 'The URL is only shown to users who can edit checks.' : 'The URL is generated when you save.'}</p>}
          </div>
        )}
        {c.type === 'http' && (
          <div className="grid gap-3 rounded-xl border border-line/70 bg-panel-2/40 p-4 sm:grid-cols-2">
            <Field label="Method"><Select value={cfg.method || 'GET'} onChange={(e) => setCfg({ method: e.target.value })}>{['GET', 'HEAD', 'POST', 'PUT'].map((m) => <option key={m}>{m}</option>)}</Select></Field>
            <Field label="Expected status" hint="e.g. 200, 2xx, 200-299,301"><Input value={cfg.expect_status || ''} placeholder="2xx/3xx" onChange={(e) => setCfg({ expect_status: e.target.value })} /></Field>
            <Field label="Keyword" info="Must appear in the response body."><Input value={cfg.keyword || ''} onChange={(e) => setCfg({ keyword: e.target.value })} /></Field>
            <Field label="Max latency (ms)" info="Fail if the response is slower."><Input type="number" value={cfg.max_latency_ms || ''} onChange={(e) => setCfg({ max_latency_ms: Number(e.target.value) || 0 })} /></Field>
            <Toggle checked={!!cfg.keyword_absent} onChange={(v) => setCfg({ keyword_absent: v })} label="Fail if keyword IS present" />
            <Toggle checked={!!cfg.keyword_regex} onChange={(v) => setCfg({ keyword_regex: v })} label="Keyword is a regex" />
            <Toggle checked={cfg.follow_redirects !== false} onChange={(v) => setCfg({ follow_redirects: v })} label="Follow redirects" />
            <Toggle checked={!!cfg.ignore_tls} onChange={(v) => setCfg({ ignore_tls: v })} label="Ignore TLS errors" />
            <Toggle checked={!!cfg.check_cert} onChange={(v) => setCfg({ check_cert: v })} label="Also alert on certificate expiry" />
            <div />
            <Field label="Basic auth user"><Input value={cfg.basic_user || ''} onChange={(e) => setCfg({ basic_user: e.target.value })} /></Field>
            <Field label="Basic auth password" hint={cfg.basic_password_set ? 'Stored; leave blank to keep' : undefined}><Input type="password" value={cfg.basic_password || ''} onChange={(e) => setCfg({ basic_password: e.target.value })} /></Field>
            {(cfg.method === 'POST' || cfg.method === 'PUT') && <Field label="Body" className="sm:col-span-2"><Input value={cfg.body || ''} onChange={(e) => setCfg({ body: e.target.value })} /></Field>}
          </div>
        )}
        {c.type === 'ping' && <Field label="Packets per check"><Input type="number" min={1} max={10} value={cfg.count || 3} onChange={(e) => setCfg({ count: Number(e.target.value) })} /></Field>}
        {(c.type === 'cert' || cfg.check_cert) && (
          <div className="grid gap-3 sm:grid-cols-4">
            <Field label="Warn at (days)"><Input type="number" value={cfg.warn_days || 30} onChange={(e) => setCfg({ warn_days: Number(e.target.value) })} /></Field>
            <Field label="Re-notify at"><Input type="number" value={cfg.notice_days || 14} onChange={(e) => setCfg({ notice_days: Number(e.target.value) })} /></Field>
            <Field label="Critical at"><Input type="number" value={cfg.crit_days || 7} onChange={(e) => setCfg({ crit_days: Number(e.target.value) })} /></Field>
            {c.type === 'cert' && <Field label="SNI name"><Input value={cfg.server_name || ''} onChange={(e) => setCfg({ server_name: e.target.value })} /></Field>}
            {c.type === 'cert' && <div className="sm:col-span-4"><Toggle checked={!!cfg.allow_invalid} onChange={(v) => setCfg({ allow_invalid: v })} label="Only check expiry (accept untrusted chains)" /></div>}
          </div>
        )}
        {c.type === 'dns' && (
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label="Record type"><Select value={cfg.record_type || 'A'} onChange={(e) => setCfg({ record_type: e.target.value })}>{['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'].map((r) => <option key={r}>{r}</option>)}</Select></Field>
            <Field label="Resolver (optional)"><Input value={cfg.resolver || ''} placeholder="system" onChange={(e) => setCfg({ resolver: e.target.value })} /></Field>
            <Field label="Expected value (optional)"><Input value={cfg.expect || ''} onChange={(e) => setCfg({ expect: e.target.value })} /></Field>
          </div>
        )}
        {c.type === 'service' && <Field label="Expected state" info="Default: running / active."><Input value={cfg.state || ''} placeholder="running" onChange={(e) => setCfg({ state: e.target.value })} /></Field>}
        {c.type === 'process' && <Toggle checked={!!cfg.regex} onChange={(v) => setCfg({ regex: v })} label="Process name is a regex" />}
        {c.type === 'port' && <Field label="Protocol"><Select value={cfg.protocol || 'tcp'} onChange={(e) => setCfg({ protocol: e.target.value })}><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field>}
        {c.type === 'container' && <Toggle checked={!!cfg.require_healthy} onChange={(v) => setCfg({ require_healthy: v })} label="Require Docker health status “healthy”" />}

        <div className="grid gap-3 sm:grid-cols-3">
          {!t.agent && c.type !== 'push' && <Field label="Interval (seconds)"><Input type="number" min={10} value={c.interval_seconds} onChange={(e) => setC({ ...c, interval_seconds: Number(e.target.value) })} /></Field>}
          {!t.agent && c.type !== 'push' && <Field label="Timeout (seconds)"><Input type="number" min={1} max={120} value={c.timeout_seconds} onChange={(e) => setC({ ...c, timeout_seconds: Number(e.target.value) })} /></Field>}
          <Field label="Alert after N failures" info={c.type === 'push' ? 'Consecutive missed or failed beats before alerting.' : 'Consecutive failures before alerting; suppresses flapping.'}><Input type="number" min={1} value={c.failure_threshold} onChange={(e) => setC({ ...c, failure_threshold: Number(e.target.value) })} /></Field>
          <DependsOn value={parent} onChange={setParent} tenantId={c.tenant_id ?? 0} self={{ type: 'check', id: c.id }} />
        </div>
        <Toggle checked={c.enabled !== false} onChange={(v) => setC({ ...c, enabled: v })} label="Enabled" />
        <ErrorBox error={err} />
      </div>
    </Modal>
  )
}

function DeleteCheck({ id, name, onDone }: { id: number; name: string; onDone: () => void }) {
  const confirm = useConfirm()
  const toast = useToast()
  return (
    <Button variant="ghost" className="text-crit" icon={<Trash2 className="size-4" />} onClick={async () => {
      if (!(await confirm({ title: 'Delete check', danger: true, confirmLabel: 'Delete', body: <p>Delete <b>{name}</b> and its history?</p> }))) return
      try { await del(`/checks/${id}`); toast('Check deleted'); onDone() } catch (e) { toast(errorMessage(e), 'crit') }
    }}>Delete</Button>
  )
}

export function UptimeBars({ days, total = 90, height = 32, fill }: { days: { day: string; percent: number; up_seconds: number; down_seconds: number }[]; total?: number; height?: number; fill?: boolean }) {
  const map = new Map(days.map((d) => [d.day, d]))
  const beats: Beat[] = Array.from({ length: total }, (_, i) => {
    const day = new Date(Date.now() - (total - 1 - i) * 86400_000).toISOString().slice(0, 10)
    const v = map.get(day)
    const p = v ? v.percent : -1
    return {
      status: p < 0 ? 'none' : p >= 99 ? 'up' : p >= 90 ? 'warn' : 'down',
      label: new Date(day + 'T00:00:00').toLocaleDateString(LOCALE, { weekday: 'short', day: 'numeric', month: 'short' }),
      detail: p < 0 ? 'No data' : `${p.toFixed(2)}% uptime`,
    }
  })
  return <BeatBar beats={beats} count={total} height={height} fill={fill} />
}

export function CheckDetail() {
  const { id = '' } = useParams()
  const [range, setRange] = useState<RangeId>('24h')
  const [editing, setEditing] = useState(false)
  const { can } = useAuth()
  const qc = useQueryClient()
  const nav = useNavigate()
  const c = useQuery({ queryKey: ['check', id], queryFn: () => get<Check>(`/checks/${id}`), refetchInterval: 30_000 })
  const h = useQuery({ queryKey: ['check-history', id, range], queryFn: () => get<any>(`/checks/${id}/history`, { start: `${rangeSeconds(range)}s` }), refetchInterval: 60_000 })
  if (c.isLoading) return <Loading />
  if (c.error) return <ErrorBox error={c.error} />
  const k = c.data!
  return (
    <div>
      <PageHeader back={<Link to="/checks" className="mb-1 inline-flex items-center gap-1 text-xs text-muted hover:text-fg"><ArrowLeft className="size-3" />Checks</Link>}
        title={<span className="flex items-center gap-2"><StatusDot status={k.status} pulse />{k.name}</span>}
        subtitle={k.type === 'push' ? 'Push (heartbeat) check' : <span className="mono">{k.target}</span>}
        actions={<>
          <RangePicker value={range} onChange={setRange} />
          {can('monitoring') && <Button icon={<Pencil className="size-4" />} onClick={() => setEditing(true)}>Edit</Button>}
        </>} />
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="Response time"><Chart series={h.data?.latency ? [{ name: 'latency', metric: 'latency', labels: {}, points: h.data.latency }] : []} unit="ms" height={220} /></Card>
          <Card title="Availability (90 days)" subtitle={h.data?.uptime_percent >= 0 ? `${h.data.uptime_percent.toFixed(3)}% uptime` : 'collecting'}>
            <UptimeBars days={h.data?.uptime_days || []} />
          </Card>
        </div>
        <Card title="Details" className="h-full">
          <KV items={[
            ['Status', <Badge key="s" tone={statusTone(k.status)}>{k.status}</Badge>],
            ['Type', checkTypes.find((t) => t.id === k.type)?.label],
            ['Host', k.host_id ? <Link key="h" to={`/hosts/${k.host_id}`} className="text-accent hover:underline">{k.host_name}</Link> : '–'],
            ...(k.type === 'push' ? [['Last beat', k.last_beat_at ? ago(k.last_beat_at) : 'none yet'] as [string, string]] : []),
            ...(k.parent ? [['Depends on', <span key="p" className="flex items-center gap-1.5"><Link to={`/${k.parent.type === 'host' ? 'hosts' : 'checks'}/${k.parent.id}`} className="text-accent hover:underline">{k.parent.name}</Link>{k.parent.down && <Badge tone="crit">down</Badge>}</span>] as [string, React.ReactNode]] : []),
            ['Last result', k.last_message],
            ['Latency', k.last_latency_ms ? `${k.last_latency_ms.toFixed(1)} ms` : '–'],
            ['Consecutive failures', `${k.consecutive_failures} (alerts at ${k.failure_threshold})`],
            ['Checked', ago(k.last_checked_at)],
            ['State since', dateTime(k.last_change_at)],
            ['Interval', k.type === 'push' ? `every ${k.interval_seconds}s, grace ${k.config?.grace_seconds || 300}s` : `${k.interval_seconds}s, timeout ${k.timeout_seconds}s`],
            ['Severity', k.severity],
            ...(h.data?.cert_days !== undefined ? [['Certificate', `${Math.floor(h.data.cert_days)} days left`] as [string, string]] : []),
          ]} />
        </Card>
      </div>
      {editing && <CheckEditor initial={k} onClose={() => { setEditing(false); qc.invalidateQueries({ queryKey: ['check', id] }); qc.invalidateQueries({ queryKey: ['checks'] }); get(`/checks/${id}`).catch(() => nav('/checks')) }} />}
    </div>
  )
}
