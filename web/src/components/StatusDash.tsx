import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  Activity, ArrowDown, ArrowUp, Box, Building2, Cloud, Cpu, Database, Gamepad2, Globe, HardDrive, HeartPulse, House, Layers, Lock, Monitor,
  Music, Network, RadioTower, Rocket, Satellite, Server, Shield, Terminal, Wifi, Zap, type LucideIcon,
} from 'lucide-react'
import { bits, LOCALE } from '@/lib/format'
import { cx } from './ui'

/** Built-in status page icons. The names match the server's allowlist. */
export const STATUS_ICONS: Record<string, LucideIcon> = {
  activity: Activity, server: Server, home: House, globe: Globe, cloud: Cloud, shield: Shield, cpu: Cpu, network: Network,
  monitor: Monitor, database: Database, zap: Zap, rocket: Rocket, heart: HeartPulse, wifi: Wifi, 'hard-drive': HardDrive,
  radio: RadioTower, gamepad: Gamepad2, music: Music, lock: Lock, building: Building2, layers: Layers, box: Box,
  terminal: Terminal, satellite: Satellite,
}

/** A status page's own icon: a preset, an uploaded image, or `fallback` when none is set. */
export function StatusIcon({ icon, fallback, className }: { icon?: string; fallback?: ReactNode; className?: string }) {
  if (icon?.startsWith('preset:')) {
    const I = STATUS_ICONS[icon.slice(7)]
    if (I) return <span className={cx('flex size-9 shrink-0 items-center justify-center rounded-lg bg-accent text-accent-fg', className)}><I className="size-[60%]" /></span>
  }
  if (icon?.startsWith('data:image/')) return <img src={icon} alt="" className={cx('size-9 shrink-0 rounded-lg object-contain', className)} />
  return <>{fallback}</>
}

export interface PublicMetric { key: string; value: number; points: [number, number][] }
export interface ChartSeries { label: string; points: [number, number][] }

const pctText = (v: number) => `${v.toFixed(v >= 99.95 ? 0 : 1)}%`
const netText = (v: number) => bits(v * 8)
const timeText = (t: number) => new Date(t * 1000).toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit' })

/**
 * Series colours in a fixed order, for light and dark surfaces. A page can hold
 * more hosts than there are hues, so the ninth line onwards reuses the hues
 * with a dashed stroke, then a dotted one: identity is hue plus stroke style.
 */
const SERIES = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948']
const SERIES_DARK = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#22a322', '#9085e9', '#e66767']
const DASH = [undefined, '5 3', '1.5 3']
const seriesStyle = (i: number, dark: boolean) => ({ color: (dark ? SERIES_DARK : SERIES)[i % 8], dash: DASH[Math.floor(i / 8) % 3] })
const isDark = () => document.documentElement.classList.contains('dark')

/** A ring gauge for a percentage. The arc turns amber at 80% and red at 90%; the number is always shown. */
export function Gauge({ label, value, size = 76 }: { label: string; value: number; size?: number }) {
  const r = 42, sweep = 270, c = 2 * Math.PI * r, arc = (sweep / 360) * c
  const v = Math.max(0, Math.min(100, value))
  const tone = v >= 90 ? 'text-crit' : v >= 80 ? 'text-warn' : 'text-accent'
  return (
    <div className="flex min-w-0 flex-col items-center" title={`${label} ${pctText(value)}`}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg viewBox="0 0 100 100" className="size-full -rotate-[225deg]" aria-hidden>
          <circle cx="50" cy="50" r={r} fill="none" strokeWidth="9" strokeLinecap="round" className="stroke-line/70" strokeDasharray={`${arc} ${c}`} />
          <circle cx="50" cy="50" r={r} fill="none" strokeWidth="9" strokeLinecap="round" stroke="currentColor" className={cx('transition-[stroke-dasharray] duration-700', tone)}
            strokeDasharray={`${(v / 100) * arc} ${c}`} />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center pt-0.5 font-semibold tabular-nums" style={{ fontSize: size * 0.21 }}>{pctText(value)}</div>
      </div>
      <div className="-mt-2.5 text-[11px] text-muted">{label}</div>
    </div>
  )
}

/**
 * A line chart of the last hour with one line per series. Hovering shows a
 * crosshair and every series' value at that time; hovering a legend entry
 * picks out its line.
 */
export function LineChart({ series, height = 120, percent, legend = true, area, scale = 'zero' }: {
  series: ChartSeries[]; height?: number; percent?: boolean; legend?: boolean; area?: boolean
  /**
   * zero: from 0 to the peak (or to 100%). fit: zoomed to the range the data
   * covers, so close lines separate. log: logarithmic, so lines that differ
   * by orders of magnitude are all readable. fit and log label both ends.
   */
  scale?: 'zero' | 'fit' | 'log'
}) {
  const box = useRef<HTMLDivElement>(null)
  const [hover, setHover] = useState<{ x: number; t: number } | null>(null)
  const [pick, setPick] = useState<number | null>(null)
  const dark = isDark()
  const fmt = percent ? pctText : netText
  const { t0, t1, lo, hi } = useMemo(() => {
    let t0 = Infinity, t1 = -Infinity, peak = 0, low = Infinity, lowPos = Infinity
    for (const s of series) for (const [t, v] of s.points) {
      if (t < t0) t0 = t; if (t > t1) t1 = t; if (v > peak) peak = v; if (v < low) low = v; if (v > 0 && v < lowPos) lowPos = v
    }
    if (scale === 'log') {
      const lo = Math.max(1, (isFinite(lowPos) ? lowPos : 1) * 0.9)
      return { t0, t1, lo, hi: Math.max(lo * 2, peak * 1.1) }
    }
    if (scale === 'fit' && isFinite(low)) {
      const span = Math.max(peak - low, percent ? 4 : Math.max(1, peak * 0.05))
      const mid = (peak + low) / 2
      let lo = Math.max(0, mid - span * 0.6), hi = mid + span * 0.6
      if (percent && hi > 100) { lo = Math.max(0, lo - (hi - 100)); hi = 100 }
      return { t0, t1, lo, hi }
    }
    return { t0, t1, lo: 0, hi: percent ? 100 : Math.max(1, peak) * 1.15 }
  }, [series, percent, scale])
  if (!series.length || !(t1 > t0)) return <div style={{ height }} className="flex items-center justify-center text-xs text-muted">Collecting data…</div>
  const W = 1000
  const px = (t: number) => ((t - t0) / (t1 - t0)) * W
  const frac = (v: number) => scale === 'log'
    ? (Math.log10(Math.max(v, lo)) - Math.log10(lo)) / (Math.log10(hi) - Math.log10(lo))
    : (Math.min(Math.max(v, lo), hi) - lo) / (hi - lo)
  const py = (v: number) => height - 2 - frac(v) * (height - 5)
  const path = (pts: [number, number][]) => pts.map(([t, v], i) => `${i ? 'L' : 'M'}${px(t).toFixed(1)},${py(v).toFixed(1)}`).join(' ')
  const nearest = (pts: [number, number][], t: number) => {
    let best: [number, number] | null = null
    for (const p of pts) if (!best || Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p
    return best && Math.abs(best[0] - t) <= 150 ? best : null
  }
  const onMove = (e: React.MouseEvent) => {
    const r = box.current?.getBoundingClientRect()
    if (!r || !r.width) return
    const x = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width))
    setHover({ x, t: t0 + x * (t1 - t0) })
  }
  const rows = hover ? series.map((s, i) => ({ i, label: s.label, p: nearest(s.points, hover.t) })).filter((r) => r.p).sort((a, b) => b.p![1] - a.p![1]) : []
  return (
    <div>
      <div ref={box} className="relative cursor-crosshair" style={{ height }} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        <svg viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none" className="absolute inset-0 size-full" aria-hidden>
          {[0.25, 0.5, 0.75].map((f) => { const y = height - 2 - f * (height - 5); return <line key={f} x1="0" x2={W} y1={y} y2={y} className="stroke-line/50" strokeWidth="1" vectorEffect="non-scaling-stroke" /> })}
          {series.map((s, i) => {
            const st = seriesStyle(i, dark)
            const d = path(s.points)
            return (
              <g key={i} opacity={pick !== null && pick !== i ? 0.15 : 1}>
                {area && <path d={`${d} L${px(s.points[s.points.length - 1][0]).toFixed(1)},${height} L${px(s.points[0][0]).toFixed(1)},${height} Z`} fill={st.color} opacity="0.12" />}
                <path d={d} fill="none" stroke={st.color} strokeWidth={pick === i ? 3 : 2} strokeDasharray={st.dash} vectorEffect="non-scaling-stroke" strokeLinejoin="round" strokeLinecap="round" />
              </g>
            )
          })}
        </svg>
        {legend && <span className="pointer-events-none absolute left-0 top-0 rounded bg-panel/80 px-0.5 text-[10px] text-muted">{fmt(scale === 'zero' && !percent ? hi / 1.15 : hi)}</span>}
        {legend && scale !== 'zero' && <span className="pointer-events-none absolute bottom-0 left-0 rounded bg-panel/80 px-0.5 text-[10px] text-muted">{fmt(lo)}</span>}
        {hover && rows.length > 0 && <>
          <div className="pointer-events-none absolute inset-y-0 w-px bg-muted/60" style={{ left: `${hover.x * 100}%` }} />
          <div className={cx('pointer-events-none absolute top-0 z-30 min-w-[150px] rounded-lg border border-line bg-panel px-2.5 py-2 text-xs shadow-pop', hover.x > 0.55 ? '-translate-x-full' : '')}
            style={{ left: `calc(${hover.x * 100}% + ${hover.x > 0.55 ? -10 : 10}px)` }}>
            <div className="mb-1 text-[11px] text-muted">{timeText(rows[0].p![0])}</div>
            {rows.map((r) => (
              <div key={r.i} className="flex items-center justify-between gap-3 leading-5">
                <span className="flex min-w-0 items-center gap-1.5"><Swatch i={r.i} dark={dark} /><span className="truncate">{r.label}</span></span>
                <span className="font-semibold tabular-nums">{fmt(r.p![1])}</span>
              </div>
            ))}
          </div>
        </>}
      </div>
      <div className="mt-1 flex justify-between text-[10px] text-muted"><span>{timeText(t0)}</span><span>{timeText(t1)}</span></div>
      {legend && series.length > 1 && (
        <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5">
          {series.map((s, i) => (
            <span key={i} onMouseEnter={() => setPick(i)} onMouseLeave={() => setPick(null)} className={cx('flex cursor-default items-center gap-1.5 text-[11px] text-muted', pick === i && 'text-fg')}>
              <Swatch i={i} dark={dark} />{s.label}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

/** The legend key for series `i`: a short stroke in its colour and dash. */
function Swatch({ i, dark }: { i: number; dark: boolean }) {
  const st = seriesStyle(i, dark)
  return <svg width="14" height="6" className="shrink-0" aria-hidden><line x1="1" x2="13" y1="3" y2="3" stroke={st.color} strokeWidth="2.5" strokeDasharray={st.dash} strokeLinecap="round" /></svg>
}

/** A host's metrics in one row: ring gauges for CPU, memory and disk, and network traffic over the last hour. */
export function HostMetrics({ metrics, className }: { metrics: PublicMetric[]; className?: string }) {
  const get = (k: string) => metrics.find((m) => m.key === k)
  const rings = ([['cpu', 'CPU'], ['memory', 'Memory'], ['disk', 'Disk']] as const).filter(([k]) => get(k))
  const rx = get('net_rx'), tx = get('net_tx')
  const net = [rx && { label: 'In', points: rx.points }, tx && { label: 'Out', points: tx.points }].filter(Boolean) as ChartSeries[]
  return (
    <div className={cx('flex items-center gap-4', className)}>
      {rings.length > 0 && <div className={cx('flex shrink-0 gap-2', !net.length && 'flex-1 justify-around')}>{rings.map(([k, label]) => <Gauge key={k} label={label} value={get(k)!.value} />)}</div>}
      {net.length > 0 && (
        <div className="min-w-0 flex-1">
          <div className="mb-1 flex items-center justify-between gap-2 text-[11px]">
            <span className="text-muted">Net</span>
            <span className="flex gap-2 whitespace-nowrap font-semibold tabular-nums">
              {rx && <span className="flex items-center gap-0.5" title="Received"><ArrowDown className="size-3" style={{ color: seriesStyle(0, isDark()).color }} />{netText(rx.value)}</span>}
              {tx && <span className="flex items-center gap-0.5" title="Sent"><ArrowUp className="size-3" style={{ color: seriesStyle(rx ? 1 : 0, isDark()).color }} />{netText(tx.value)}</span>}
            </span>
          </div>
          <LineChart series={net} height={44} legend={false} area />
        </div>
      )}
    </div>
  )
}

/**
 * Lays tiles out in rows that always fill the width: it works out how many
 * fit per row, then spreads the tiles evenly so no row is left part-empty
 * (13 tiles at four per row become rows of 4, 3, 3 and 3).
 */
export function BalancedGrid({ children, min, className }: { children: ReactNode[]; min: number; className?: string }) {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(0)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(() => setWidth(el.clientWidth))
    ro.observe(el)
    setWidth(el.clientWidth)
    return () => ro.disconnect()
  }, [])
  const n = children.length
  const maxCols = Math.max(1, Math.floor((width + 12) / (min + 12)))
  const rowCount = Math.ceil(n / maxCols)
  const base = Math.floor(n / rowCount), extra = n % rowCount
  const rows: ReactNode[][] = []
  for (let r = 0, i = 0; r < rowCount; r++) { const k = base + (r < extra ? 1 : 0); rows.push(children.slice(i, i + k)); i += k }
  return (
    <div ref={ref} className={cx('space-y-3', className)}>
      {width > 0 && rows.map((row, r) => <div key={r} className="grid gap-3" style={{ gridTemplateColumns: `repeat(${row.length}, minmax(0, 1fr))` }}>{row}</div>)}
    </div>
  )
}
