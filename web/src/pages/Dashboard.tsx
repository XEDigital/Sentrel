import { Link, useNavigate } from 'react-router'
import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, ArrowRight, Bell, BellOff, Plus, Server, ShieldAlert, Wrench } from 'lucide-react'
import { get } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { ago, plural } from '@/lib/format'
import type { Alert, AlertEvent, Check, Host } from '@/lib/types'
import { FIXABLE_TITLE, nf } from '@/lib/vulns'
import { BeatBar, checkBeatsToBeats, hostBeatsToBeats, useCheckBeats, useHostBeats } from '@/components/BeatBar'
import { useTenantFilter } from '@/components/Layout'
import { AllClear, Badge, Button, Card, Empty, Loading, MutedBadge, PageHeader, SeverityBadge, Stat, StatusDot, StatusPill, cx, useToast } from '@/components/ui'
import { AckDialog } from './Alerts'
import { hostStatusLabel, MiniMeter } from './Hosts'

interface Dash {
  hosts: { total: number; up: number; down: number; pending: number; maintenance: number; down_expected?: number }
  alerts: { critical: number; warning: number; acked: number; expected?: number }
  checks: { total: number; up: number; down: number; warning: number }
  upgrades_pending: number
  security_updates: number
  reboot_required: number
  vulnerabilities: Record<string, number>
  vulnerabilities_inactive?: number
  vulnerabilities_total?: number
  vulnerabilities_fixable?: number
  vuln_enabled?: boolean
  recent_events: AlertEvent[]
  firing_alerts: Alert[]
}

type Tone = 'ok' | 'crit' | 'warn' | 'maint'

const tileStyle: Record<Tone, { ring: string; text: string; dot: string; label: string }> = {
  ok: { ring: 'from-ok/12', text: 'text-ok-ink', dot: 'bg-ok-fill', label: 'Up' },
  crit: { ring: 'from-crit/12', text: 'text-crit-ink', dot: 'bg-crit-fill', label: 'Down' },
  warn: { ring: 'from-warn/14', text: 'text-warn-ink', dot: 'bg-warn-fill', label: 'Alerting' },
  maint: { ring: 'from-maint/12', text: 'text-maint-ink', dot: 'bg-maint', label: 'Maintenance' },
}

/** One card summarising everything monitored: counts per state and a proportion bar. */
function HealthCard({ parts, total }: { parts: { tone: Tone; value: number; title: string; onClick: () => void }[]; total: string }) {
  const sum = parts.reduce((n, p) => n + p.value, 0)
  return (
    <div className="flex h-full flex-col rounded-md border border-line bg-panel p-4">
      <div className="flex items-center justify-between gap-2 text-xs font-medium text-muted">
        <span>Infrastructure health</span>
        <span className="truncate">{total}</span>
      </div>
      <div className="mt-1.5 grid grid-cols-4 gap-2">
        {parts.map((p) => {
          const t = tileStyle[p.tone]
          return (
            <button key={p.tone} type="button" onClick={p.onClick} title={p.title} className="-mx-1.5 rounded-lg px-1.5 py-0.5 text-left hover:bg-panel-2">
              <div className={cx('text-3xl font-semibold tabular-nums tracking-tight', p.value === 0 ? 'text-muted/50' : t.text)}>{p.value}</div>
              <div className="flex items-center gap-1.5 text-xs text-muted"><span className={cx('size-1.5 rounded-full', t.dot)} />{t.label}</div>
            </button>
          )
        })}
      </div>
      <div className="mt-auto pt-3">
        <div className="flex h-1.5 gap-0.5 overflow-hidden rounded-full bg-panel-2">
          {sum > 0 && parts.map((p) => p.value > 0 && <div key={p.tone} className={tileStyle[p.tone].dot} style={{ width: `${(p.value / sum) * 100}%` }} />)}
        </div>
      </div>
    </div>
  )
}

export function Dashboard() {
  const { tenant } = useTenantFilter()
  const { can } = useAuth()
  const nav = useNavigate()
  const qc = useQueryClient()
  const toast = useToast()
  const [acking, setAcking] = useState<Alert | null>(null)
  const d = useQuery({ queryKey: ['dashboard', tenant], queryFn: () => get<Dash>('/dashboard', { tenant_id: tenant ?? undefined }), refetchInterval: 30_000 })
  const hosts = useQuery({ queryKey: ['hosts', 'grid', tenant], queryFn: () => get<Host[]>('/hosts', { tenant_id: tenant ?? undefined }), refetchInterval: 30_000 })
  const checks = useQuery({ queryKey: ['checks', 'all', tenant], queryFn: () => get<Check[]>('/checks', { host_id: undefined, tenant_id: tenant ?? undefined }), refetchInterval: 30_000 })
  const hostBeats = useHostBeats(30, tenant)
  const checkBeats = useCheckBeats(40, tenant)
  if (d.isLoading) return <Loading />
  const x = d.data
  if (!x) return null
  const v = x.vulnerabilities || {}

  const allHosts = hosts.data || []
  const problemHosts = allHosts.filter((h) => !h.revoked && !h.in_maintenance && !(h.status === 'down' && h.down_expected) && (h.status === 'down' || !!h.alert_severity))
    .sort((a, b) => (b.status === 'down' ? 2 : b.alert_severity === 'critical' ? 1 : 0) - (a.status === 'down' ? 2 : a.alert_severity === 'critical' ? 1 : 0))
  const warnHosts = allHosts.filter((h) => !h.in_maintenance && h.status !== 'down' && !!h.alert_severity).length
  const problemChecks = (checks.data || []).filter((c) => c.enabled && (c.status === 'down' || c.status === 'warning'))
    .sort((a, b) => (b.status === 'down' ? 1 : 0) - (a.status === 'down' ? 1 : 0))
  const warnTotal = (hosts.data ? warnHosts : 0) + x.checks.warning
  const upHosts = hosts.data ? allHosts.filter((h) => h.status === 'up' && !h.alert_severity && !h.in_maintenance).length : x.hosts.up

  return (
    <div className="space-y-5">
      <PageHeader title="Overview" subtitle="Your infrastructure at a glance. Start with what needs attention."
        actions={<>
          {(x.alerts.critical + x.alerts.warning > 0) && <Button variant="primary" icon={<Bell className="size-4" />} onClick={() => nav('/alerts')}>Review alerts</Button>}
          {can('hosts') && <Button icon={<Plus className="size-4" />} onClick={() => nav('/hosts/new')}>Add host</Button>}
        </>} />

      <div className={cx('grid grid-cols-2 gap-3 sm:gap-4', x.vuln_enabled ? 'sm:grid-cols-3' : 'sm:grid-cols-2')}>
        <div className="col-span-2 sm:col-span-full">
          <HealthCard total={`${plural(x.hosts.total, 'host')} · ${plural(x.checks.total, 'check')}${x.hosts.pending ? ` · ${x.hosts.pending} pending` : ''}${x.hosts.down_expected ? ` · ${x.hosts.down_expected} down (expected)` : ''}`} parts={[
            { tone: 'ok', value: upHosts + x.checks.up, title: `${plural(upHosts, 'host')} · ${plural(x.checks.up, 'check')}`, onClick: () => nav('/hosts?status=up') },
            { tone: 'crit', value: x.hosts.down + x.checks.down, title: `${plural(x.hosts.down, 'host')} · ${plural(x.checks.down, 'check')}`, onClick: () => nav(x.hosts.down ? '/hosts?status=down' : '/checks') },
            { tone: 'warn', value: warnTotal, title: `${plural(hosts.data ? warnHosts : 0, 'host')} · ${plural(x.checks.warning, 'check')}`, onClick: () => nav('/alerts') },
            { tone: 'maint', value: x.hosts.maintenance, title: `${plural(x.hosts.maintenance, 'host')} in a maintenance window`, onClick: () => nav('/maintenance') },
          ]} />
        </div>
        <Stat label="Active alerts" icon={<Bell />} value={x.alerts.critical + x.alerts.warning} tone={x.alerts.critical ? 'crit' : x.alerts.warning ? 'warn' : 'muted'}
          sub={`${x.alerts.critical} critical · ${x.alerts.warning} warning${x.alerts.acked ? ` · ${x.alerts.acked} acknowledged` : ''}${x.alerts.expected ? ` · ${x.alerts.expected} expected` : ''}`} onClick={() => nav('/alerts')} />
        <Stat label="Updates pending" icon={<Wrench />} value={x.upgrades_pending} tone={x.security_updates ? 'warn' : 'muted'} sub={`${x.security_updates} security${x.reboot_required ? ` · ${x.reboot_required} need a reboot` : ''}`} onClick={() => nav('/hosts?sort=updates')} />
        {x.vuln_enabled && <div className="col-span-2 sm:col-span-1"><Stat label="Critical vulnerabilities" icon={<ShieldAlert />} value={nf(v.critical ?? 0)} tone={v.critical ? 'crit' : v.high ? 'warn' : 'muted'} title={FIXABLE_TITLE} sub={`${nf(v.high ?? 0)} high · ${nf(x.vulnerabilities_fixable ?? 0)} fixable`} onClick={() => nav('/vulnerabilities')} /></div>}
      </div>

        <Card className="h-full" title="Active alerts" subtitle="Issues that need investigation." actions={<Link to="/alerts" className="text-xs font-medium text-accent hover:underline">View all</Link>} bodyClass="p-0">
          {x.firing_alerts.length === 0 ? (
            <AllClear title="All quiet" />
          ) : (
            <ul className="divide-y divide-line/60">
              {x.firing_alerts.slice(0, 12).map((a) => (
                <li key={a.id} className="flex flex-wrap items-center gap-3 px-5 py-4">
                  <StatusDot status={a.severity === 'critical' ? 'down' : 'warning'} pulse={!a.acked_by} />
                  <div className="min-w-0 flex-1 basis-56 sm:basis-auto">
                    <Link to={`/alerts/${a.id}`} className="block text-sm font-medium hover:text-accent">{a.title}</Link>
                    <div className="mt-1 line-clamp-2 text-xs text-muted">{a.message}</div>
                  </div>
                  <div className="hidden shrink-0 items-center gap-2 sm:flex">
                    {a.muted && <MutedBadge />}
                    {a.in_maintenance && <Badge tone="maint">maintenance</Badge>}
                    {a.flapping && <Badge tone="warn">flapping</Badge>}
                    {a.acked_by ? <Badge title={a.ack_comment}>acked by {a.acked_by}</Badge> : <SeverityBadge severity={a.severity} />}
                    <span className="w-16 text-right text-xs text-muted">{ago(a.fired_at)}</span>
                  </div>
                  {!a.acked_by && can('ack') && <Button className="ml-auto shrink-0" size="sm" variant="ghost" icon={<BellOff className="size-3.5" />} onClick={() => setAcking(a)}>Acknowledge</Button>}
                </li>
              ))}
            </ul>
          )}
        </Card>


      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="h-full" title="Hosts needing attention" bodyClass="p-0"
          actions={<Link to="/hosts" className="text-xs font-medium text-accent hover:underline">All hosts</Link>}>
          {hosts.isLoading ? <Loading /> : problemHosts.length === 0 ? (
            <AllClear title="All hosts healthy" />
          ) : (
            <ul className="divide-y divide-line/60">
              {problemHosts.slice(0, 8).map((h) => {
                const st = hostStatusLabel(h)
                return (
                  <li key={h.id}>
                    <Link to={`/hosts/${h.id}`} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3 hover:bg-panel-2/50">
                      <StatusPill tone={st.tone} label={st.label} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-semibold">{h.name}</div>
                        <div className="truncate text-xs text-muted">{h.status === 'down' ? `Last seen ${ago(h.last_seen_at)}` : `${h.alert_count} active alert${h.alert_count === 1 ? '' : 's'}`}</div>
                      </div>
                      <div className="hidden w-40 sm:block"><BeatBar beats={hostBeatsToBeats(hostBeats.data?.[String(h.id)])} count={14} height={20} /></div>
                    </Link>
                  </li>
                )
              })}
            </ul>
          )}
        </Card>

        <Card className="h-full" title="Checks needing attention" subtitle={problemChecks.length ? `${problemChecks.length} failing` : undefined} bodyClass="p-0"
          actions={<Link to="/checks" className="text-xs font-medium text-accent hover:underline">All checks</Link>}>
          {checks.isLoading ? <Loading /> : problemChecks.length === 0 ? (
            (checks.data?.length ?? 0) === 0 ? <Empty title="No service checks yet">Add a check to monitor a website, port or endpoint.<Link to="/checks" className="mt-2 block font-medium text-accent hover:underline">Set up checks →</Link></Empty> : <AllClear title="All checks passing" />
          ) : (
            <ul className="divide-y divide-line/60">
              {problemChecks.slice(0, 8).map((c) => (
                <li key={c.id}>
                  <Link to={`/checks/${c.id}`} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3 hover:bg-panel-2/50">
                    <StatusPill status={c.status} label={c.status} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-semibold">{c.name}</div>
                      <div className="truncate text-xs text-muted" title={c.last_message}>{c.last_message || c.target}</div>
                    </div>
                    <div className="hidden w-40 sm:block"><BeatBar beats={checkBeatsToBeats(checkBeats.data?.[String(c.id)])} count={20} height={20} /></div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Host overview" bodyClass="p-4">
        {hosts.isLoading ? <Loading /> : !allHosts.length ? (
          <Empty title="No hosts yet">{can('hosts') && <Link to="/hosts/new" className="text-accent hover:underline">Add your first host</Link>}</Empty>
        ) : (
          <div className="grid grid-cols-[repeat(auto-fill,minmax(250px,1fr))] gap-3">
            {allHosts.map((h) => <HostTile key={h.id} h={h} />)}
          </div>
        )}
      </Card>
      <nav aria-label="Overview shortcuts" className="grid gap-3 sm:grid-cols-3">
        {[
          { to: '/hosts', title: 'Explore hosts', hint: 'Health, metrics and inventory', icon: <Server className="size-5" /> },
          { to: '/checks', title: 'Service checks', hint: 'Availability and response times', icon: <Activity className="size-5" /> },
          { to: '/jobs', title: 'Jobs & updates', hint: 'Review scheduled work and results', icon: <Wrench className="size-5" /> },
        ].map((item) => <Link key={item.to} to={item.to} className="group flex items-center gap-3 rounded-md border border-line bg-panel px-4 py-3 hover:border-accent/40">
          <span className="rounded-lg bg-accent/8 p-2 text-accent">{item.icon}</span>
          <span className="min-w-0 flex-1"><span className="block text-sm font-semibold">{item.title}</span><span className="block text-xs text-muted">{item.hint}</span></span>
          <ArrowRight className="size-4 shrink-0 text-muted group-hover:text-accent" />
        </Link>)}
      </nav>
        <Card className="h-full" title="Recent activity" subtitle="The five most recent alert events" actions={<Link to="/alerts" className="text-xs font-medium text-accent hover:underline">View alerts</Link>} bodyClass="p-0">
          {x.recent_events.length === 0 ? <Empty title="No events yet" /> : (
            <ul className="divide-y divide-line/60">
              {x.recent_events.slice(0, 5).map((e) => (
                <li key={e.id} className="px-5 py-3">
                  <div className="flex items-center gap-2 text-xs">
                    <Badge tone={e.event === 'resolved' ? 'ok' : e.event === 'acked' ? 'info' : e.event === 'silenced' ? 'maint' : e.severity === 'critical' ? 'crit' : 'warn'}>{e.event}</Badge>
                    <span className="text-muted">{ago(e.created_at)}</span>
                    {e.actor && <span className="text-muted">by {e.actor}</span>}
                  </div>
                  <Link to={`/alerts/${e.alert_id}`} className="mt-1 block truncate text-sm hover:text-accent">{e.title}</Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

      {acking && <AckDialog ids={[acking.id]} onClose={() => { setAcking(null); qc.invalidateQueries({ queryKey: ['dashboard'] }); qc.invalidateQueries({ queryKey: ['hosts'] }) }} onDone={(_n, expected) => toast(expected ? 'Alert marked as expected' : 'Alert acknowledged')} />}
    </div>
  )
}

function HostTile({ h }: { h: Host }) {
  const s = h.summary
  const st = hostStatusLabel(h)
  const edge = h.in_maintenance ? 'bg-maint' : h.status === 'down' && h.down_expected ? 'bg-unknown-fill' : h.status === 'down' || h.alert_severity === 'critical' ? 'bg-crit-fill' : h.alert_severity === 'warning' ? 'bg-warn-fill' : h.status === 'up' ? 'bg-ok-fill' : 'bg-unknown-fill'
  return (
    <Link to={`/hosts/${h.id}`} className="group relative block overflow-hidden rounded-md border border-line/70 bg-panel p-3.5 pl-4 transition-[transform,box-shadow] duration-150 hover:-translate-y-px hover:shadow-pop">
      <span className={cx('absolute inset-y-0 left-0 w-1', edge)} />
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-sm font-semibold">{h.name}</span>
        <StatusDot status={h.in_maintenance ? 'maintenance' : st.tone === 'warn' ? 'warning' : st.tone === 'crit' ? 'down' : h.status} pulse />
      </div>
      <div className="mt-0.5 truncate text-[11px] text-muted">{h.kind === 'agent' ? h.host_info?.platform || 'agent' : h.kind}{h.alert_count > 0 ? ` · ${h.alert_count} alert${h.alert_count === 1 ? '' : 's'}` : ''}</div>
      <div className="mt-3 flex items-center gap-2">
        <MiniMeter label="CPU" value={s?.cpu} />
        <MiniMeter label="Mem" value={s?.memory} />
        <MiniMeter label="Disk" value={s?.disk} />
      </div>
    </Link>
  )
}
