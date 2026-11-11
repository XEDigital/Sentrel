import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, ArrowRight, BellOff, BellRing, CheckCircle2 } from 'lucide-react'
import { errorMessage, get, post } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { ago, dateTime, duration } from '@/lib/format'
import type { Alert, AlertEvent } from '@/lib/types'
import { useTenantFilter } from '@/components/Layout'
import { DISK_ALERT_METRICS, StorageForAlert } from './host/DiskUsage'
import { Badge, Button, Card, Checkbox, Empty, ErrorBox, Field, Input, KV, Loading, Modal, MutedBadge, PageHeader, Segmented, SeverityBadge, StatusDot, Table, Td, Th, Textarea, useToast } from '@/components/ui'

export function Alerts() {
  const { can } = useAuth()
  return (
    <div>
      <PageHeader title="Alerts" subtitle="Alerts raised by your monitoring rules and vulnerability policy."
        info="Host update, reboot and CVE inventory counts are not separate alerts. Security-update and reboot rules must be enabled to raise alerts; vulnerability alerts follow the configured severity, fixability and inactive-kernel policy. Acknowledge an alert to stop its notifications until it clears; tick “This is expected” to also move it out of the active list for as long as you want. Alerts clear by themselves when the problem goes away."
        actions={can('monitoring') && <Link to="/thresholds" className="rounded-lg border border-line bg-panel px-3 py-2 text-sm font-medium hover:border-accent">Configure alert rules</Link>} />
      <AlertsTable />
    </div>
  )
}

export function AlertsTable({ hostId }: { hostId?: number }) {
  const { tenant } = useTenantFilter()
  const { can } = useAuth()
  const qc = useQueryClient()
  const toast = useToast()
  const nav = useNavigate()
  const [status, setStatus] = useState<'active' | 'expected' | 'resolved' | 'all'>('active')
  const [sev, setSev] = useState('')
  const [q, setQ] = useState('')
  const [sel, setSel] = useState<Set<number>>(new Set())
  const [ackOpen, setAckOpen] = useState(false)
  const alerts = useQuery({ queryKey: ['alerts', status, sev, hostId, tenant], queryFn: () => get<Alert[]>('/alerts', { status, severity: sev, host_id: hostId, tenant_id: tenant ?? undefined, limit: 500 }), refetchInterval: 30_000 })
  const rows = (alerts.data || []).filter((a) => !q || a.title.toLowerCase().includes(q.toLowerCase()) || a.message.toLowerCase().includes(q.toLowerCase()))
  const ackable = rows.filter((a) => sel.has(a.id) && a.status === 'firing' && !a.acked_by)
  const unexpect = async (a: Alert) => {
    try { await post(`/alerts/${a.id}/unack`); toast('No longer marked as expected'); qc.invalidateQueries({ queryKey: ['alerts'] }) } catch (e) { toast(errorMessage(e), 'crit') }
  }
  return (
    <Card bodyClass="p-0">
      <div className="flex flex-wrap items-center gap-2 border-b border-line/70 p-4">
        <Segmented value={status} onChange={(v) => { setStatus(v); setSel(new Set()) }} options={[{ id: 'active', label: 'Active' }, { id: 'expected', label: 'Expected' }, { id: 'resolved', label: 'Resolved' }, { id: 'all', label: 'All fired' }]} />
        <Segmented value={sev} onChange={setSev} options={[{ id: '', label: 'Any' }, { id: 'critical', label: 'Critical' }, { id: 'warning', label: 'Warning' }]} />
        <Input placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} className="w-full sm:w-56" />
        <div className="flex-1" />
        {can('ack') && ackable.length > 0 && <Button size="sm" variant="primary" icon={<BellOff className="size-3.5" />} onClick={() => setAckOpen(true)}>Acknowledge {ackable.length}</Button>}
      </div>
      {alerts.isLoading ? <Loading /> : rows.length === 0 ? (
        <Empty title={status === 'active' ? 'No active alerts' : status === 'expected' ? 'Nothing is marked as expected' : 'No alerts'} icon={<CheckCircle2 className="size-8 text-ok" />}>{status === 'expected' && 'Alerts you acknowledge with “This is expected” are kept here, out of the active list, until you undo it.'}</Empty>
      ) : (
        <Table>
          <thead><tr>
            {status === 'active' && can('ack') && <Th className="w-8"><Checkbox checked={sel.size > 0 && sel.size === rows.length} onChange={(v) => setSel(v ? new Set(rows.map((a) => a.id)) : new Set())} /></Th>}
            <Th>Severity</Th><Th>Alert</Th>{!hostId && <Th className="hidden md:table-cell">Host</Th>}<Th className="hidden sm:table-cell">State</Th><Th>Since</Th><Th className="hidden lg:table-cell">Duration</Th>{status === 'expected' && can('ack') && <Th />}
          </tr></thead>
          <tbody>
            {rows.map((a) => {
              const start = a.fired_at || a.started_at
              const end = a.resolved_at || Date.now() / 1000
              return (
                <tr key={a.id} className="cursor-pointer hover:bg-panel-2/50" onClick={(e) => { if (!(e.target as HTMLElement).closest('a, button, input, label')) nav(`/alerts/${a.id}`) }}>
                  {status === 'active' && can('ack') && <Td><Checkbox checked={sel.has(a.id)} onChange={(v) => { const s = new Set(sel); if (v) s.add(a.id); else s.delete(a.id); setSel(s) }} /></Td>}
                  <Td><div className="flex items-center gap-2"><StatusDot status={a.status === 'resolved' ? 'up' : a.severity === 'critical' ? 'down' : 'warning'} pulse={a.status === 'firing' && !a.acked_by} /><SeverityBadge severity={a.severity} /></div></Td>
                  <Td><Link to={`/alerts/${a.id}`} className="font-medium hover:underline">{a.title}</Link><div className="max-w-xl truncate text-xs text-muted">{a.message}</div></Td>
                  {!hostId && <Td className="hidden text-xs md:table-cell">{a.host_id ? <Link to={`/hosts/${a.host_id}`} className="hover:underline">{a.host_name}</Link> : <Badge>{a.source}</Badge>}</Td>}
                  <Td className="hidden sm:table-cell">
                    <div className="flex flex-wrap gap-1">
                      <Badge tone={a.status === 'firing' ? 'crit' : a.status === 'pending' ? 'warn' : 'ok'}>{a.status}{a.status === 'pending' ? ` ${a.pending_count}` : ''}</Badge>
                      {a.expected ? <Badge tone="maint" title={a.ack_comment}>expected</Badge> : a.acked_by && <Badge tone="info" title={a.ack_comment}>acknowledged</Badge>}
                      {a.flapping && <Badge tone="warn">flapping</Badge>}
                      {a.in_maintenance && <Badge tone="maint">maintenance</Badge>}
                      {a.suppressed_by && <Badge title="Notifications are withheld while the parent is down">suppressed: {a.suppressed_by}</Badge>}
                      {a.muted && <MutedBadge />}
                    </div>
                  </Td>
                  <Td className="text-xs text-muted" title={dateTime(start)}>{ago(start)}</Td>
                  <Td className="hidden text-xs text-muted lg:table-cell">{duration(end - start)}</Td>
                  {status === 'expected' && can('ack') && <Td className="text-right"><Button size="sm" variant="ghost" icon={<BellRing className="size-3.5" />} onClick={() => unexpect(a)}>No longer expected</Button></Td>}
                </tr>
              )
            })}
          </tbody>
        </Table>
      )}
      {ackOpen && <AckDialog ids={ackable.map((a) => a.id)} onClose={() => { setAckOpen(false); setSel(new Set()); qc.invalidateQueries({ queryKey: ['alerts'] }) }} onDone={(n, expected) => toast(expected ? `${n} alert(s) marked as expected` : `${n} alert(s) acknowledged`)} />}
    </Card>
  )
}

/** The one action on an alert: acknowledge it, with a note, optionally as expected. */
export function AckDialog({ ids, onClose, onDone }: { ids: number[]; onClose: () => void; onDone: (n: number, expected: boolean) => void }) {
  const [comment, setComment] = useState('')
  const [expected, setExpected] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<unknown>(null)
  return (
    <Modal open onClose={onClose} title={ids.length === 1 ? 'Acknowledge alert' : `Acknowledge ${ids.length} alerts`} size="sm"
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} onClick={async () => {
        setBusy(true)
        try { const r = await post<{ acked: number }>('/alerts/ack', { ids, comment, expected }); onDone(r.acked, expected); onClose() } catch (e) { setErr(e) } finally { setBusy(false) }
      }}>Acknowledge</Button></>}>
      <p className="mb-3 text-sm text-muted">Notifications stop until the alert clears. It clears by itself when the problem goes away.</p>
      <Field label="Note (optional)" info="Shown on the alert and in its history.">
        <Textarea autoFocus value={comment} onChange={(e) => setComment(e.target.value)} placeholder={expected ? 'Only switched on when needed' : 'Investigating: disk cleanup in progress'} />
      </Field>
      <div className="mt-4">
        <Checkbox checked={expected} onChange={setExpected} label="This is expected" />
        <p className="ml-6 mt-1 text-xs text-muted">Also moves the alert out of the active list, to the Expected tab, and keeps it quiet every time it comes back, until you undo it. For example a machine that is only switched on when needed.</p>
      </div>
      <ErrorBox error={err} className="mt-2" />
    </Modal>
  )
}

const eventTone: Record<string, 'ok' | 'warn' | 'crit' | 'info' | 'muted' | 'maint'> = {
  fired: 'crit', resolved: 'ok', acked: 'info', unacked: 'muted', expected: 'maint', escalated: 'crit', flapping: 'warn', flapping_stopped: 'ok', notified: 'muted', silenced: 'maint',
}

const UPDATE_METRICS = ['security_updates', 'reboot_required', 'old_kernels', 'kernel_reboot_pending']
const SECURITY_METRICS = ['bruteforce', 'portscan']
const GRAPH_METRICS = ['cpu', 'memory', 'swap', 'load', 'temperature', 'net_errors', 'if_util']

/** Where to go to deal with an alert: the page that shows, or fixes, its cause. */
export function alertNextStep(a: Alert): { label: string; to: string } | null {
  if (a.check_id) return { label: 'Open check', to: `/checks/${a.check_id}` }
  if (!a.host_id) return null
  const host = `/hosts/${a.host_id}`
  if (a.source === 'vuln') return { label: 'Fix vulnerabilities', to: `${host}?tab=vulns&fixable=1` }
  if (UPDATE_METRICS.includes(a.metric)) return { label: 'Review updates', to: `${host}?tab=packages` }
  if (SECURITY_METRICS.includes(a.metric)) return { label: 'Open security', to: `${host}?tab=security` }
  if (GRAPH_METRICS.includes(a.metric)) return { label: 'View metrics', to: `${host}?tab=metrics` }
  return { label: 'Open host', to: host }
}

export function AlertDetail() {
  const { id = '' } = useParams()
  const { can } = useAuth()
  const qc = useQueryClient()
  const toast = useToast()
  const [ack, setAck] = useState(false)
  const nav = useNavigate()
  const d = useQuery({ queryKey: ['alert', id], queryFn: () => get<{ alert: Alert; events: AlertEvent[] }>(`/alerts/${id}`), refetchInterval: 30_000 })
  if (d.isLoading) return <Loading />
  if (d.error) return <ErrorBox error={d.error} />
  const { alert: a, events } = d.data!
  const next = alertNextStep(a)
  const act = async (path: string, msg: string) => {
    try { await post(`/alerts/${a.id}/${path}`); toast(msg); qc.invalidateQueries({ queryKey: ['alert', id] }) } catch (e) { toast(errorMessage(e), 'crit') }
  }
  return (
    <div>
      <PageHeader back={<Link to="/alerts" className="mb-1 inline-flex items-center gap-1 text-xs text-muted hover:text-fg"><ArrowLeft className="size-3" />Alerts</Link>}
        title={a.title} subtitle={a.message}
        actions={<>
          {can('ack') && (a.expected ? <Button icon={<BellRing className="size-4" />} onClick={() => act('unack', 'No longer marked as expected')}>No longer expected</Button>
          : a.status === 'resolved' ? null
            : a.acked_by ? <Button icon={<BellRing className="size-4" />} onClick={() => act('unack', 'Acknowledgement removed')}>Unacknowledge</Button>
              : <Button variant="primary" icon={<BellOff className="size-4" />} onClick={() => setAck(true)}>Acknowledge</Button>)}
          {next && a.status !== 'resolved' && <Button icon={<ArrowRight className="size-4" />} onClick={() => nav(next.to)}>{next.label}</Button>}
        </>} />
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Details" className="h-full">
          <KV items={[
            ['Status', <span key="s" className="flex flex-wrap gap-1"><Badge tone={a.status === 'firing' ? 'crit' : a.status === 'pending' ? 'warn' : 'ok'}>{a.status}</Badge>{a.expected && <Badge tone="maint">expected</Badge>}{a.flapping && <Badge tone="warn">flapping</Badge>}{a.in_maintenance && <Badge tone="maint">in maintenance</Badge>}{a.suppressed_by && <Badge title="Notifications are withheld while the parent is down">suppressed: {a.suppressed_by}</Badge>}{a.muted && <MutedBadge />}</span>],
            ['Severity', <SeverityBadge key="v" severity={a.severity} />],
            ['Source', a.source + (a.metric ? ` · ${a.metric}` : '') + (a.labels ? ` · ${a.labels}` : '')],
            ['Host', a.host_id ? <Link key="h" to={`/hosts/${a.host_id}`} className="text-accent hover:underline">{a.host_name}</Link> : '–'],
            ['Check', a.check_id ? <Link key="c" to={`/checks/${a.check_id}`} className="text-accent hover:underline">view check</Link> : '–'],
            ['Value', a.value !== null ? `${a.value?.toFixed(2)}${a.threshold !== null ? ` (threshold ${a.threshold})` : ''}` : '–'],
            ['Started', dateTime(a.started_at)],
            ['Fired', dateTime(a.fired_at)],
            ['Resolved', a.resolved_at ? dateTime(a.resolved_at) : '–'],
            [a.expected ? 'Marked as expected' : 'Acknowledged', a.acked_by ? `${a.acked_by}, ${ago(a.acked_at)}${a.ack_comment ? ` — “${a.ack_comment}”` : ''}` : 'no'],
            ['Notifications', a.expected ? 'None while marked as expected' : a.muted ? <span key="n" className="inline-flex items-center gap-1.5"><BellOff className="size-3.5 text-muted" />Disabled for this rule (alert is shown here only)</span> : `${a.notify_count} sent${a.last_notified_at ? `, last ${ago(a.last_notified_at)}` : ''}`],
          ]} />
        </Card>
        <Card title="Timeline" className="h-full xl:col-span-2" bodyClass="p-0">
          {events.length === 0 ? <Empty title="No events" /> : (
            <ol className="divide-y divide-line/60">
              {events.map((e) => (
                <li key={e.id} className="flex items-start gap-3 px-5 py-3">
                  <Badge tone={eventTone[e.event] || 'muted'} className="mt-0.5 w-24 justify-center">{e.event.replace('_', ' ')}</Badge>
                  <div className="min-w-0 flex-1 text-sm">{e.message}{e.actor && <span className="text-muted"> — {e.actor}</span>}</div>
                  <span className="shrink-0 text-xs text-muted" title={dateTime(e.created_at)}>{ago(e.created_at)}</span>
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>
      {a.host_id && a.labels && DISK_ALERT_METRICS.includes(a.metric) && <StorageForAlert hostId={a.host_id} mount={a.labels} />}
      {ack && <AckDialog ids={[a.id]} onClose={() => { setAck(false); qc.invalidateQueries({ queryKey: ['alert', id] }) }} onDone={(_n, expected) => toast(expected ? 'Alert marked as expected' : 'Alert acknowledged')} />}
    </div>
  )
}
