import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { get } from '@/lib/api'
import type { CheckBeat, HostBeat } from '@/lib/types'
import { LOCALE } from '@/lib/format'
import { cx } from './ui'

export type BeatStatus = 'up' | 'warn' | 'down' | 'maint' | 'none'

export interface Beat {
  status: BeatStatus
  /** First tooltip line (day or time). */
  label: string
  /** Second tooltip line (value). */
  detail?: string
}

const fill: Record<BeatStatus, string> = {
  up: 'bg-ok-fill',
  warn: 'bg-warn-fill',
  down: 'bg-crit-fill',
  maint: 'bg-maint',
  none: 'bg-unknown-fill/70',
}

/**
 * A row of small rounded vertical pills coloured by status, with a hover tooltip.
 * Beats are right-aligned (newest on the right); when `count` is larger than the
 * data, the left side is padded with empty slots.
 */
export function BeatBar({ beats, count, height = 28, className, fill: stretch }: { beats: Beat[]; count?: number; height?: number; className?: string; /** Stretch the beats to the full width instead of capping each at 10px. */ fill?: boolean }) {
  const [hover, setHover] = useState<number | null>(null)
  const n = count ?? beats.length
  const shown = beats.slice(-n)
  const pad = Math.max(0, n - shown.length)
  const slots: (Beat | null)[] = [...Array<null>(pad).fill(null), ...shown]
  const at = hover !== null ? slots[hover] : null
  return (
    <div className={cx('relative min-w-0', className)} onMouseLeave={() => setHover(null)}>
      <div className="flex items-stretch gap-[2px]" style={{ height }} role="img" aria-label={`Status history, ${shown.length} entries`}>
        {slots.map((b, i) => (
          <span key={i} onMouseEnter={() => setHover(i)}
            className={cx('min-w-[2px] flex-1 rounded-full transition-[transform,opacity] duration-100', fill[b?.status ?? 'none'], hover === i ? 'scale-y-110 opacity-100' : hover !== null ? 'opacity-80' : '')}
            style={stretch ? undefined : { maxWidth: 10 }} />
        ))}
      </div>
      {hover !== null && at && (
        <div className="pointer-events-none absolute bottom-full z-30 mb-2 -translate-x-1/2 whitespace-nowrap rounded-lg bg-slate-900 px-2.5 py-1.5 text-center text-xs text-white shadow-pop dark:border dark:border-line dark:bg-panel-2"
          style={{ left: `${Math.min(88, Math.max(12, ((hover + 0.5) / slots.length) * 100))}%` }}>
          <div className="font-medium">{at.label}</div>
          {at.detail && <div className="text-white/70">{at.detail}</div>}
        </div>
      )}
    </div>
  )
}

// ---------- Data adapters ----------

export function hostBeatsToBeats(days: HostBeat[] | undefined): Beat[] {
  return (days || []).map((d) => {
    const u = d.uptime
    const status: BeatStatus = u === null || u === undefined ? 'none' : u >= 99 ? 'up' : u >= 90 ? 'warn' : 'down'
    const day = new Date(d.day + 'T00:00:00').toLocaleDateString(LOCALE, { weekday: 'short', day: 'numeric', month: 'short' })
    return { status, label: day, detail: u === null || u === undefined ? 'No data' : `${u.toFixed(2)}% uptime` }
  })
}

export function checkBeatsToBeats(results: CheckBeat[] | undefined): Beat[] {
  return (results || []).map((r) => ({
    status: r.ok ? 'up' : 'down',
    label: new Date(r.t * 1000).toLocaleString(LOCALE, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    detail: `${r.ok ? 'OK' : 'Failed'}${r.latency_ms !== null && r.latency_ms !== undefined ? ` · ${r.latency_ms.toFixed(r.latency_ms < 10 ? 1 : 0)} ms` : ''}`,
  }))
}

/** Average uptime over the days that have data, or null when none do. */
export function averageUptime(days: HostBeat[] | undefined): number | null {
  const v = (days || []).map((d) => d.uptime).filter((x): x is number => x !== null && x !== undefined)
  if (!v.length) return null
  return v.reduce((a, b) => a + b, 0) / v.length
}

/** Share of successful results, as a percentage. */
export function checkSuccessRate(results: CheckBeat[] | undefined): number | null {
  if (!results?.length) return null
  return (results.filter((r) => r.ok).length * 100) / results.length
}

// ---------- Queries ----------

export function useHostBeats(days = 30, tenant?: number | null) {
  return useQuery({
    queryKey: ['host-beats', days, tenant ?? null],
    queryFn: () => get<Record<string, HostBeat[]>>('/hosts/beats', { days, tenant_id: tenant ?? undefined }),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })
}

export function useCheckBeats(limit = 40, tenant?: number | null) {
  return useQuery({
    queryKey: ['check-beats', limit, tenant ?? null],
    queryFn: () => get<Record<string, CheckBeat[]>>('/checks/beats', { limit, tenant_id: tenant ?? undefined }),
    refetchInterval: 30_000,
    staleTime: 15_000,
  })
}
