import { useEffect, useState, type ReactNode } from 'react'
import { useParams, useSearchParams } from 'react-router'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowDown, ArrowUp, ExternalLink, Globe, Pencil, Plus, Trash2, Upload, X } from 'lucide-react'
import { del, errorMessage, get, post, put } from '@/lib/api'
import { applyBranding, applyTheme, getThemePref } from '@/lib/auth'
import { useAuth } from '@/lib/auth'
import type { Branding, Check, Host, StatusMetricKind, StatusPage, StatusPageItem } from '@/lib/types'
import { useTenantFilter, Logo } from '@/components/Layout'
import { Badge, Button, Card, CodeBlock, Empty, ErrorBox, Field, Input, Loading, Modal, PageHeader, Select, Table, Td, Textarea, Th, Toggle, cx, useConfirm, useToast } from '@/components/ui'
import { LOCALE } from '@/lib/format'
import { UptimeBars } from './Checks'
import { BalancedGrid, HostMetrics, LineChart, STATUS_ICONS, StatusIcon, type ChartSeries, type PublicMetric } from '@/components/StatusDash'

export function StatusPages() {
  const { can } = useAuth()
  const { tenant } = useTenantFilter()
  const qc = useQueryClient()
  const confirm = useConfirm()
  const [edit, setEdit] = useState<Partial<StatusPage> | null>(null)
  const pages = useQuery({ queryKey: ['status-pages', tenant], queryFn: () => get<StatusPage[]>('/status-pages', { tenant_id: tenant ?? undefined }) })
  const link = (p: StatusPage) => `${location.origin}/status/${p.slug}${p.public ? '' : `?token=${p.access_token}`}`
  return (
    <div>
      <PageHeader title="Status pages" info="Public or token-protected pages showing up/down and 90-day uptime for chosen hosts and checks."
        actions={can('monitoring') && <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEdit({ tenant_id: tenant ?? 0 })}>New status page</Button>} />
      <Card bodyClass="p-0">
        {pages.isLoading ? <Loading /> : !pages.data?.length ? <Empty title="No status pages" icon={<Globe className="size-8" />} /> : (
          <Table>
            <thead><tr><Th>Page</Th><Th>Access</Th><Th>Items</Th><Th className="hidden md:table-cell">Link</Th><Th /></tr></thead>
            <tbody>{pages.data.map((p) => (
              <tr key={p.id}>
                <Td className="font-medium"><div className="flex items-center gap-2.5"><StatusIcon icon={p.icon} className="size-7" /><div>{p.title}{p.layout === 'wall' && <Badge className="ml-2">wall display</Badge>}<div className="mono text-xs font-normal text-muted">/status/{p.slug}</div></div></div></Td>
                <Td>{p.public ? <Badge tone="ok">public</Badge> : <Badge tone="warn">token</Badge>}</Td>
                <Td>{p.items?.length || 0}</Td>
                <Td className="hidden md:table-cell"><a href={link(p)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-accent hover:underline">open <ExternalLink className="size-3" /></a></Td>
                <Td className="whitespace-nowrap text-right">{can('monitoring') && <>
                  <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" />} onClick={() => setEdit(p)} />
                  <Button size="sm" variant="ghost" icon={<Trash2 className="size-3.5" />} onClick={async () => {
                    if (!(await confirm({ title: 'Delete status page', danger: true, confirmLabel: 'Delete', body: <p>Delete <b>{p.title}</b>? The link stops working.</p> }))) return
                    await del(`/status-pages/${p.id}`); qc.invalidateQueries({ queryKey: ['status-pages'] })
                  }} />
                </>}</Td>
              </tr>
            ))}</tbody>
          </Table>
        )}
      </Card>
      {edit && <StatusEditor initial={edit} onClose={() => { setEdit(null); qc.invalidateQueries({ queryKey: ['status-pages'] }) }} />}
    </div>
  )
}

function StatusEditor({ initial, onClose }: { initial: Partial<StatusPage>; onClose: () => void }) {
  const toast = useToast()
  const hosts = useQuery({ queryKey: ['hosts', 'all'], queryFn: () => get<Host[]>('/hosts') })
  const checks = useQuery({ queryKey: ['checks', 'all'], queryFn: () => get<Check[]>('/checks') })
  const [p, setP] = useState<Partial<StatusPage>>({ slug: '', title: '', description: '', public: true, items: [], show_history: true, announcement: '', icon: '', layout: 'list', show_overview: false, theme: 'auto', ...initial })
  const [pick, setPick] = useState('')
  const [err, setErr] = useState<unknown>(null)
  const items = p.items || []
  const move = (i: number, d: number) => { const a = [...items]; const [x] = a.splice(i, 1); a.splice(i + d, 0, x); setP({ ...p, items: a }) }
  const add = () => {
    if (!pick) return
    const [type, id] = pick.split(':')
    const label = type === 'host' ? hosts.data?.find((h) => h.id === Number(id))?.name : checks.data?.find((c) => c.id === Number(id))?.name
    setP({ ...p, items: [...items, { type: type as StatusPageItem['type'], id: Number(id), label: label || '' }] })
    setPick('')
  }
  const allKinds = METRIC_KINDS.map(([k]) => k)
  /** Adds every host not yet on the page; with `withMetrics`, every host on the page also shows all metrics. */
  const addAllHosts = (withMetrics: boolean) => {
    const have = new Set(items.filter((it) => it.type === 'host').map((it) => it.id))
    const more = (hosts.data || []).filter((h) => !have.has(h.id) && (p.id ? h.tenant_id === p.tenant_id : !p.tenant_id || h.tenant_id === p.tenant_id))
    const next = [...items, ...more.map((h) => ({ type: 'host' as const, id: h.id, label: h.name }))]
    setP({ ...p, items: withMetrics ? next.map((it) => it.type === 'host' ? { ...it, metrics: allKinds } : it) : next })
  }
  const addAllChecks = () => {
    const have = new Set(items.filter((it) => it.type === 'check').map((it) => it.id))
    const more = (checks.data || []).filter((c) => !have.has(c.id) && (p.id ? c.tenant_id === p.tenant_id : !p.tenant_id || c.tenant_id === p.tenant_id))
    setP({ ...p, items: [...items, ...more.map((c) => ({ type: 'check' as const, id: c.id, label: c.name }))] })
  }
  const toggleMetric = (i: number, m: StatusMetricKind) => {
    const a = [...items]
    const cur = a[i].metrics || []
    a[i] = { ...a[i], metrics: cur.includes(m) ? cur.filter((x) => x !== m) : [...cur, m] }
    setP({ ...p, items: a })
  }
  const hostItems = items.filter((it) => it.type === 'host')
  const allOn = hostItems.length > 0 && hostItems.every((it) => METRIC_KINDS.every(([k]) => it.metrics?.includes(k)))
  const setAllMetrics = (on: boolean) => setP({ ...p, items: items.map((it) => it.type === 'host' ? { ...it, metrics: on ? METRIC_KINDS.map(([k]) => k) : [] } : it) })
  const uploadIcon = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    e.target.value = ''
    if (!f) return
    if (f.size > 500_000) { toast('Image must be under 500 KB', 'crit'); return }
    const r = new FileReader()
    r.onload = () => setP((cur) => ({ ...cur, icon: String(r.result) }))
    r.readAsDataURL(f)
  }
  const save = async (regen = false) => {
    setErr(null)
    try {
      const body = { ...p, regenerate_token: regen }
      if (p.id) await put(`/status-pages/${p.id}`, body)
      else await post('/status-pages', body)
      toast('Status page saved')
      onClose()
    } catch (e) { setErr(e) }
  }
  return (
    <Modal open onClose={onClose} title={p.id ? 'Edit status page' : 'New status page'} size="lg"
      footer={<>{p.id && !p.public && <Button onClick={() => save(true)}>Regenerate token</Button>}<div className="flex-1" /><Button onClick={onClose}>Cancel</Button><Button variant="primary" onClick={() => save()}>Save</Button></>}>
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Title" required><Input value={p.title} onChange={(e) => setP({ ...p, title: e.target.value, slug: p.id ? p.slug : e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') })} /></Field>
          <Field label="URL slug" hint={`${location.origin}/status/${p.slug || '…'}`}><Input value={p.slug} onChange={(e) => setP({ ...p, slug: e.target.value })} /></Field>
          <Field label="Description" className="sm:col-span-2"><Input value={p.description} onChange={(e) => setP({ ...p, description: e.target.value })} /></Field>
          <Field label="Announcement banner (optional)" className="sm:col-span-2"><Textarea value={p.announcement} onChange={(e) => setP({ ...p, announcement: e.target.value })} placeholder="Scheduled maintenance Saturday 02:00–04:00 UTC" /></Field>
        </div>
        <Field label="Icon" hint="Shown next to the title. The first option keeps the logo from Branding.">
          <div className="flex flex-wrap gap-2">
            <button type="button" title="Default (Branding logo)" aria-label="Default" aria-pressed={!p.icon} onClick={() => setP({ ...p, icon: '' })}
              className={cx(ICON_CELL, !p.icon ? ICON_ON : ICON_OFF)}><Logo className="size-5" /></button>
            {Object.entries(STATUS_ICONS).map(([name, I]) => (
              <button key={name} type="button" title={name} aria-label={name} aria-pressed={p.icon === `preset:${name}`} onClick={() => setP({ ...p, icon: `preset:${name}` })}
                className={cx(ICON_CELL, p.icon === `preset:${name}` ? 'border-accent bg-accent text-accent-fg ring-2 ring-accent/30' : ICON_OFF)}><I className="size-5" /></button>
            ))}
            {p.icon?.startsWith('data:') && <span title="Uploaded image" className={cx(ICON_CELL, ICON_ON, 'overflow-hidden p-1')}><img src={p.icon} alt="" className="size-full object-contain" /></span>}
            <label title="Upload an image" className={cx(ICON_CELL, ICON_OFF, 'w-auto cursor-pointer gap-1.5 px-3 text-xs')}>
              <Upload className="size-4" /> Upload<input type="file" accept="image/png,image/jpeg,image/svg+xml,image/webp" className="hidden" onChange={uploadIcon} />
            </label>
          </div>
        </Field>
        <Field label="Theme" hint="Applies to this page only, whatever theme the viewer uses elsewhere.">
          <Select value={p.theme || 'auto'} onChange={(e) => setP({ ...p, theme: e.target.value as StatusPage['theme'] })}>
            <option value="auto">Viewer's choice</option><option value="light">Light</option><option value="dark">Dark</option>
          </Select>
        </Field>
        <div className="space-y-2">
          <Toggle checked={!!p.public} onChange={(v) => setP({ ...p, public: v })} label="Public" info="When off, only people with the secret link can view the page." />
          <Toggle checked={!!p.show_history} onChange={(v) => setP({ ...p, show_history: v })} label="Show 90-day history" />
          <Toggle checked={p.layout === 'wall'} onChange={(v) => setP({ ...p, layout: v ? 'wall' : 'list' })} label="Wall display" info="A full-width grid of tiles with a clock, made for a screen on the wall. It refreshes every 15 seconds." />
          <Toggle checked={!!p.show_overview} onChange={(v) => setP({ ...p, show_overview: v })} label="Overview graphs" info="Adds graphs of CPU, memory and network with a line for every host on the page. Anyone who can open the page sees them." />
        </div>
        {!p.public && p.access_token && <CodeBlock code={`${location.origin}/status/${p.slug}?token=${p.access_token}`} />}
        <Field label="Items">
          <div className="space-y-2">
            {items.map((it, i) => (
              <div key={it.type + it.id}>
                <div className="flex items-center gap-2">
                  <Badge>{it.type}</Badge>
                  <Input className="h-8 flex-1" value={it.label} onChange={(e) => { const a = [...items]; a[i] = { ...it, label: e.target.value }; setP({ ...p, items: a }) }} />
                  <Button size="sm" variant="ghost" disabled={i === 0} icon={<ArrowUp className="size-3.5" />} onClick={() => move(i, -1)} />
                  <Button size="sm" variant="ghost" disabled={i === items.length - 1} icon={<ArrowDown className="size-3.5" />} onClick={() => move(i, 1)} />
                  <Button size="sm" variant="ghost" icon={<X className="size-3.5" />} onClick={() => setP({ ...p, items: items.filter((_, j) => j !== i) })} />
                </div>
                {it.type === 'host' && (
                  <div className="mt-1 ml-12 flex flex-wrap items-center gap-1 text-[11px] text-muted">
                    <span className="mr-1">Show</span>
                    <button type="button" aria-pressed={allKinds.every((k) => it.metrics?.includes(k))} onClick={() => { const a = [...items]; a[i] = { ...it, metrics: allKinds.every((k) => it.metrics?.includes(k)) ? [] : allKinds }; setP({ ...p, items: a }) }}
                      className={cx('rounded-full border px-2 py-0.5 font-medium', allKinds.every((k) => it.metrics?.includes(k)) ? 'border-accent bg-accent/10 text-accent' : 'border-line hover:border-accent/50')}>All</button>
                    {METRIC_KINDS.map(([k, label]) => (
                      <button key={k} type="button" aria-pressed={!!it.metrics?.includes(k)} onClick={() => toggleMetric(i, k)}
                        className={cx('rounded-full border px-2 py-0.5', it.metrics?.includes(k) ? 'border-accent bg-accent/10 text-accent' : 'border-line hover:border-accent/50')}>{label}</button>
                    ))}
                  </div>
                )}
              </div>
            ))}
            <div className="flex gap-2">
              <div className="flex-1"><Select value={pick} onChange={(e) => setPick(e.target.value)}>
                <option value="">Add a host or check…</option>
                <optgroup label="Hosts">{hosts.data?.map((h) => <option key={h.id} value={`host:${h.id}`}>{h.name}</option>)}</optgroup>
                <optgroup label="Checks">{checks.data?.map((c) => <option key={c.id} value={`check:${c.id}`}>{c.name}</option>)}</optgroup>
              </Select></div>
              <Button onClick={add} disabled={!pick}>Add</Button>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => addAllHosts(true)}>Add all hosts with all metrics</Button>
              <Button size="sm" onClick={() => addAllHosts(false)}>Add all hosts</Button>
              <Button size="sm" onClick={addAllChecks}>Add all checks</Button>
              {hostItems.length > 0 && <Button size="sm" onClick={() => setAllMetrics(!allOn)}>{allOn ? 'Hide metrics on all hosts' : 'Show all metrics on all hosts'}</Button>}
            </div>
            {hostItems.some((it) => it.metrics?.length) && <p className="text-xs text-muted">Selected metrics are visible to anyone who can open the page: the current value and the last hour.</p>}
          </div>
        </Field>
        <ErrorBox error={err} />
      </div>
    </Modal>
  )
}

const ICON_CELL = 'flex size-9 shrink-0 items-center justify-center rounded-lg border transition-colors'
const ICON_OFF = 'border-line bg-panel-2/50 text-muted hover:border-accent/60 hover:text-fg'
const ICON_ON = 'border-accent bg-accent/10 ring-2 ring-accent/30'

const METRIC_KINDS: [StatusMetricKind, string][] = [['cpu', 'CPU'], ['memory', 'Memory'], ['network', 'Network'], ['disk', 'Disk']]

interface PublicOverview {
  hosts_up: number; hosts_total: number; hosts_expected: number
  checks_up: number; checks_total: number; checks_expected: number
  charts: { key: string; series: ChartSeries[] }[]
}
type PublicItem = { label: string; type: string; status: string; uptime_percent: number; days?: any[]; metrics?: PublicMetric[] }

interface PublicData {
  title: string
  description: string
  announcement: string
  overall: string
  items: PublicItem[]
  branding: Branding
  updated_at: number
  icon?: string
  layout?: 'list' | 'wall'
  theme?: 'auto' | 'light' | 'dark'
  overview?: PublicOverview
}

const statusText: Record<string, string> = { operational: 'Operational', degraded: 'Degraded', down: 'Outage', maintenance: 'Maintenance', expected: 'Off (expected)', unknown: 'Unknown' }
const statusColor: Record<string, string> = { operational: 'bg-ok', degraded: 'bg-warn', down: 'bg-crit', maintenance: 'bg-maint', expected: 'bg-muted', unknown: 'bg-muted' }
const statusInk: Record<string, string> = { operational: 'text-ok-ink', degraded: 'text-warn-ink', down: 'text-crit-ink', maintenance: 'text-maint-ink', expected: 'text-muted', unknown: 'text-muted' }
const overallText = (o: string) => o === 'operational' ? 'All systems operational' : o === 'down' ? 'Some systems are down' : o === 'degraded' ? 'Degraded performance' : 'Maintenance in progress'
const chartTitle: Record<string, string> = { cpu: 'CPU', memory: 'Memory', network: 'Network (in + out)' }

export function PublicStatus() {
  const { slug = '' } = useParams()
  const [params] = useSearchParams()
  const [live, setLive] = useState(false)
  const d = useQuery({ queryKey: ['public-status', slug], queryFn: () => get<PublicData>(`/public/status/${slug}`, { token: params.get('token') || '' }), refetchInterval: live ? 15_000 : 60_000 })
  // The link's ?theme= wins, then the page's own setting, then the viewer's stored theme. It is
  // re-applied when data arrives: the app shell sets the stored theme after this page first renders.
  const urlTheme = params.get('theme')
  const pageTheme = d.data?.theme
  useEffect(() => {
    applyTheme(urlTheme === 'dark' || urlTheme === 'light' ? urlTheme : pageTheme === 'dark' || pageTheme === 'light' ? pageTheme : getThemePref())
    // Leaving the page gives the app its own theme back.
    return () => applyTheme(getThemePref())
  }, [urlTheme, pageTheme, d.data])
  useEffect(() => { if (d.data) { applyBranding(d.data.branding); document.title = `${d.data.title} — status` } }, [d.data])
  // Pages with graphs or the wall layout refresh more often.
  const wantsLive = !!d.data && (d.data.layout === 'wall' || !!d.data.overview || d.data.items.some((it) => it.metrics?.length))
  useEffect(() => { setLive(wantsLive) }, [wantsLive])
  if (d.isLoading) return <Loading />
  if (d.error && !d.data) return <div className="flex min-h-full items-center justify-center p-6"><ErrorBox error={errorMessage(d.error) === 'not found' ? 'Status page not found' : d.error} /></div>
  const x = d.data!
  const b = x.branding
  const logo = <StatusIcon icon={x.icon} fallback={b.logo_data_url ? <img src={b.logo_data_url} alt="" className="h-9 max-w-[180px] object-contain" /> : <Logo />} />
  const footer = <>Updated {new Date(x.updated_at * 1000).toLocaleString(LOCALE)} · {b.footer_text || `Powered by ${b.product_name || 'Sentrel'}`}</>
  if (x.layout === 'wall') return <WallStatus x={x} logo={logo} footer={footer} />
  return (
    <div className="min-h-full bg-bg">
      <div className="mx-auto max-w-3xl px-4 py-10">
        <div className="mb-8 flex items-center gap-3">
          {logo}
          <div><h1 className="text-xl font-semibold">{x.title}</h1>{x.description && <p className="text-sm text-muted">{x.description}</p>}</div>
        </div>
        {x.announcement && <div className="mb-4 rounded-2xl border border-info/30 bg-info/10 p-4 text-sm whitespace-pre-line">{x.announcement}</div>}
        <div className={cx('mb-6 flex items-center gap-3 rounded-2xl p-5 text-white shadow-card', statusColor[x.overall])}>
          <span className="text-lg font-semibold">{overallText(x.overall)}</span>
          {x.overview && <span className="ml-auto text-sm font-medium text-white/90">{countsText(x.items)}</span>}
        </div>
        {x.overview && <Overview o={x.overview} className="mb-6" min={300} />}
        <Card bodyClass="p-0">
          <ul className="divide-y divide-line/60">
            {x.items.map((it, i) => (
              <li key={i} className="p-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-medium">{it.label}</span>
                  <span className="flex items-center gap-2 text-sm"><span className={cx('size-2.5 rounded-full', statusColor[it.status])} />{statusText[it.status] || it.status}</span>
                </div>
                {!!it.metrics?.length && <HostMetrics metrics={it.metrics} className="mt-3" />}
                {it.days && (
                  <div className="mt-3">
                    <UptimeBars days={it.days} />
                    <div className="mt-1 flex justify-between text-[11px] text-muted"><span>90 days ago</span><span>{it.uptime_percent >= 0 ? `${it.uptime_percent.toFixed(2)}% uptime` : ''}</span><span>Today</span></div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </Card>
        <p className="mt-6 text-center text-xs text-muted">{footer}</p>
      </div>
    </div>
  )
}

const panel = 'rounded-xl border border-line/70 bg-panel p-4 shadow-card'

/** How many of the page's hosts and checks are up, ignoring those that are off as expected. */
function counts(items: PublicItem[]) {
  const of = (type: string) => {
    const all = items.filter((it) => it.type === type)
    const expected = all.filter((it) => it.status === 'expected').length
    return { up: all.filter((it) => it.status === 'operational').length, total: all.length - expected, expected }
  }
  return { hosts: of('host'), checks: of('check') }
}

function countsText(items: PublicItem[]) {
  const c = counts(items)
  return [c.hosts.total > 0 && `${c.hosts.up}/${c.hosts.total} hosts up`, c.checks.total > 0 && `${c.checks.up}/${c.checks.total} checks up`].filter(Boolean).join(' · ')
}

/** A compact count for the wall header, such as "Hosts 12/12". */
function CountChip({ label, c }: { label: string; c: { up: number; total: number; expected: number } }) {
  if (c.total + c.expected === 0) return null
  const ok = c.up >= c.total
  return (
    <div className="flex items-center gap-2 rounded-full border border-line/70 bg-panel px-3.5 py-1.5 text-sm shadow-card"
      title={c.expected > 0 ? `${c.expected} more off as expected` : undefined}>
      <span className={cx('size-2 rounded-full', ok ? 'bg-ok' : 'bg-crit')} />
      <span className="text-muted">{label}</span>
      <span className="font-semibold tabular-nums">{c.up}<span className="font-normal text-muted"> / {c.total}</span></span>
    </div>
  )
}

/**
 * A chart per metric with a line for every host. CPU and memory zoom to the
 * range the hosts cover and network is logarithmic, so the lines spread over
 * the chart instead of bunching at one edge. The cards share the row equally.
 */
function Overview({ o, className, min = 340 }: { o: PublicOverview; className?: string; min?: number }) {
  if (!o.charts.length) return null
  return (
    <div className={cx('grid gap-3', className)} style={{ gridTemplateColumns: `repeat(auto-fit, minmax(min(100%, ${min}px), 1fr))` }}>
      {o.charts.map((c) => (
        <div key={c.key} className={panel}>
          <div className="mb-2 flex items-baseline justify-between"><h2 className="text-sm font-semibold">{chartTitle[c.key] || c.key}</h2>
            <span className="text-[11px] text-muted">last hour, per host{c.key === 'network' ? ', log scale' : ''}</span></div>
          <LineChart series={c.series} height={130} percent={c.key !== 'network'} scale={c.key === 'network' ? 'log' : 'fit'} />
        </div>
      ))}
    </div>
  )
}

function Clock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t) }, [])
  return (
    <div className="text-right leading-tight">
      <div className="text-3xl font-semibold tabular-nums">{now.toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit' })}</div>
      <div className="text-xs text-muted">{now.toLocaleDateString(LOCALE, { weekday: 'long', day: 'numeric', month: 'long' })}</div>
    </div>
  )
}

/** One item on the wall: name, state, metrics where chosen, and uptime across the full width. */
function WallTile({ it }: { it: PublicItem }) {
  return (
    <div className={cx('relative flex flex-col overflow-hidden rounded-xl border bg-panel p-4 pl-5 shadow-card', it.status === 'down' ? 'border-crit/60' : 'border-line/70')}>
      <span className={cx('absolute inset-y-0 left-0 w-1.5', statusColor[it.status])} />
      <div className="flex items-center justify-between gap-3">
        <span className="truncate text-base font-semibold">{it.label}</span>
        <span className={cx('flex shrink-0 items-center gap-1.5 text-sm font-medium', statusInk[it.status])}>
          <span className={cx('size-2.5 rounded-full', statusColor[it.status], it.status === 'down' && 'animate-pulse')} />{statusText[it.status] || it.status}
        </span>
      </div>
      {!!it.metrics?.length && <HostMetrics metrics={it.metrics} className="mt-3" />}
      <div className="mt-auto pt-3">
        {it.days && <UptimeBars days={it.days} total={30} height={16} fill />}
        <div className="mt-1 flex justify-between text-[11px] text-muted"><span>{it.days ? 'Last 30 days' : ''}</span><span>{it.uptime_percent >= 0 ? `${it.uptime_percent.toFixed(2)}% uptime over 90 days` : ''}</span></div>
      </div>
    </div>
  )
}

/** Full-width layout for a screen on the wall: everything at a glance. */
function WallStatus({ x, logo, footer }: { x: PublicData; logo: ReactNode; footer: ReactNode }) {
  // Tiles with metrics are taller, so they get their own rows; the rest pack into a denser grid.
  const rich = x.items.filter((it) => it.metrics?.length)
  const plain = x.items.filter((it) => !it.metrics?.length)
  return (
    <div className="min-h-full bg-bg p-4 lg:p-6">
      <div className="mb-4 flex flex-wrap items-center gap-4">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          {logo}
          <div className="min-w-0"><h1 className="truncate text-2xl font-semibold">{x.title}</h1>{x.description && <p className="truncate text-sm text-muted">{x.description}</p>}</div>
        </div>
        <CountChip label="Hosts" c={counts(x.items).hosts} />
        <CountChip label="Checks" c={counts(x.items).checks} />
        <div className={cx('flex items-center gap-2.5 rounded-full px-4 py-2 text-sm font-semibold text-white shadow-card', statusColor[x.overall])}>
          <span className={cx('size-2.5 rounded-full bg-white', x.overall !== 'operational' && 'animate-pulse')} />
          {overallText(x.overall)}
        </div>
        <Clock />
      </div>
      {x.announcement && <div className="mb-4 rounded-xl border border-info/30 bg-info/10 p-3 text-sm whitespace-pre-line">{x.announcement}</div>}
      {x.overview && <Overview o={x.overview} className="mb-3" />}
      {rich.length > 0 && <BalancedGrid min={400} className="mb-3">{rich.map((it, i) => <WallTile key={i} it={it} />)}</BalancedGrid>}
      {plain.length > 0 && <BalancedGrid min={260}>{plain.map((it, i) => <WallTile key={i} it={it} />)}</BalancedGrid>}
      <p className="mt-5 text-center text-xs text-muted">{footer}</p>
    </div>
  )
}
