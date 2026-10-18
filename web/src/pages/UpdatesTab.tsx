import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ArrowUpCircle, Check, CheckCircle2, ExternalLink, Loader2, RefreshCw } from 'lucide-react'
import { get, post, put } from '@/lib/api'
import { ago, dateTime } from '@/lib/format'
import {
  STEPS, installHelp, isActivePhase, isFinalPhase, phaseLabel, stepIndex, updateView,
  type InstallStatus, type UpdateInfo,
} from '@/lib/updates'
import { ReleaseNotes } from '@/components/ReleaseNotes'
import { Badge, Button, Card, CodeBlock, ErrorBox, KV, Loading, Note, SettingRow, Toggle, cx, useConfirm, useToast } from '@/components/ui'

/** Settings -> Updates: version check, release notes and the one-click installer. */
export function UpdatesTab() {
  const qc = useQueryClient()
  const toast = useToast()
  const confirm = useConfirm()
  const info = useQuery({ queryKey: ['updates'], queryFn: () => get<UpdateInfo>('/server/updates'), refetchInterval: 5 * 60_000 })
  const [watching, setWatching] = useState(false)
  const [busy, setBusy] = useState<'check' | 'install' | 'toggle' | null>(null)
  const [err, setErr] = useState<unknown>(null)
  const seenActive = useRef(false)
  const status = useQuery({
    queryKey: ['update-status'], queryFn: () => get<InstallStatus>('/server/updates/status'),
    refetchInterval: (q) => (watching || isActivePhase(q.state.data?.phase) ? 1500 : 10_000),
    retry: false, enabled: !!info.data?.method,
  })
  const st = status.data
  const active = isActivePhase(st?.phase)
  const reconnecting = status.isError && watching

  // Pick up an install that is already running (page reload, second admin).
  useEffect(() => {
    if (active) { seenActive.current = true; setWatching(true) }
  }, [active])

  // Reload into the new version as soon as the server reports it.
  useEffect(() => {
    if (!watching || !st?.version) return
    if (st.phase === 'failed' || st.phase === 'rolled_back') { setWatching(false); qc.invalidateQueries({ queryKey: ['updates'] }); return }
    const target = st.version
    const t = setInterval(async () => {
      try {
        const r = await fetch('/api/v1/public/info', { headers: { Accept: 'application/json' }, cache: 'no-store' })
        const v = (await r.json())?.version
        if (v && v === target) { clearInterval(t); setTimeout(() => window.location.reload(), 800) }
      } catch { /* the server is restarting */ }
    }, 2000)
    return () => clearInterval(t)
  }, [watching, st?.version, st?.phase, qc])

  if (info.isLoading) return <Loading />
  if (info.error) return <ErrorBox error={info.error} />
  const u = info.data!

  const saveToggles = async (patch: { check_enabled?: boolean; install_enabled?: boolean }) => {
    setBusy('toggle'); setErr(null)
    try {
      await put('/settings/updates', { check_enabled: u.check_enabled, install_enabled: u.install_enabled, ...patch })
      await qc.invalidateQueries({ queryKey: ['updates'] })
      qc.invalidateQueries({ queryKey: ['settings'] })
      toast('Update settings saved', 'ok')
    } catch (e) { setErr(e) } finally { setBusy(null) }
  }
  const checkNow = async () => {
    setBusy('check'); setErr(null)
    try { qc.setQueryData(['updates'], await post<UpdateInfo>('/server/updates/check')) }
    catch (e) { setErr(e) } finally { setBusy(null) }
  }
  const install = async () => {
    const ok = await confirm({
      title: `Install Sentrel ${u.latest}?`, danger: true, confirmLabel: 'Install update', typeToConfirm: u.hostname || 'sentrel',
      body: (
        <div className="space-y-2">
          <p>This downloads Sentrel {u.latest}, verifies its Ed25519 signature and checksum, replaces the server binary and restarts the server. The UI is unavailable for a few seconds, and agents reconnect on their own.</p>
          <p>If the new version does not become healthy within 90 seconds, the previous version is restored automatically. Take a backup first if you have not recently.</p>
        </div>
      ),
    })
    if (!ok) return
    setBusy('install'); setErr(null)
    try {
      const r = await post<InstallStatus>('/server/updates/install', { version: u.latest, confirm: true })
      qc.setQueryData(['update-status'], r)
      seenActive.current = true
      setWatching(true)
    } catch (e) { setErr(e) } finally { setBusy(null) }
  }

  const disabledByHost = u.check_forced_off
  const { showProgress, showInstall } = updateView(u, st, watching)
  const showHelp = u.update_available && u.method && u.method !== 'systemd'

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
      <div className="min-w-0 space-y-4">
        {err != null && <ErrorBox error={err} />}

        <Card
          title={u.update_available ? `Sentrel ${u.latest} is available` : 'Sentrel is up to date'}
          info="Every release lists its checksums in a file signed with the Sentrel release key. The server verifies that signature, then a separate root-owned updater verifies it again with the key built into the installed binary before it swaps anything. Downgrades are refused, and a version that does not start healthy is rolled back."
          actions={u.html_url ? <a href={u.html_url} target="_blank" rel="noopener noreferrer"><Button size="sm" variant="ghost" icon={<ExternalLink className="size-3.5" />}>Release on GitHub</Button></a> : undefined}>
          <div className="flex flex-wrap items-center gap-3">
            <div className={cx('grid size-11 shrink-0 place-items-center rounded-xl', u.update_available ? 'bg-ok/12 text-ok' : 'bg-panel-2 text-muted')}>
              {u.update_available ? <ArrowUpCircle className="size-6" /> : <CheckCircle2 className="size-6" />}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                <span className="text-muted">Current <b className="mono text-fg">{u.current}</b></span>
                {u.latest && <span className="text-muted">Latest <b className="mono text-fg">{u.latest}</b></span>}
                {!!u.published_at && <span className="text-muted">Published {dateTime(u.published_at)}</span>}
              </div>
            </div>
            {showInstall && (
              <Button variant="primary" loading={busy === 'install'} onClick={install} icon={<ArrowUpCircle className="size-4" />}>Install update</Button>
            )}
          </div>
          {u.update_available && u.method === 'systemd' && !u.can_install && u.install_blocked && (
            <Note tone="warn" className="mt-4">{u.install_blocked}</Note>
          )}
        </Card>

        {showProgress && st && <Progress st={st} reconnecting={reconnecting} watching={watching} />}

        {showHelp && (
          <Card title={installHelp(u.method, u.latest || '').title} info={<>One-click updates need the systemd install from <code className="mono">install-server.sh</code>.{u.method === 'docker' && ' Containers are updated by replacing the image, not from inside.'}{u.method === 'package' && ' Packages are owned by your package manager, which keeps its own database consistent.'}</>}>
            <div className="space-y-3 text-sm">
              {installHelp(u.method, u.latest || '').steps.map((s, i) => (
                <div key={i} className="space-y-1.5"><p>{s.text}</p>{s.code && <CodeBlock code={s.code} />}</div>
              ))}
            </div>
          </Card>
        )}

        {u.update_available && (
          <Card title={`What is new in ${u.latest}`} bodyClass="p-5 max-h-[28rem] overflow-y-auto scrollbar-thin">
            <ReleaseNotes text={u.notes || ''} />
          </Card>
        )}
      </div>

      <div className="min-w-0 space-y-4">
        <Card title="Update checks" actions={<Button size="sm" loading={busy === 'check'} disabled={!u.check_enabled} onClick={checkNow} icon={<RefreshCw className="size-3.5" />}>Check now</Button>}>
          <div className="-my-2 divide-y divide-line/60">
            {disabledByHost && <div className="py-2"><Note tone="warn">Update checks are disabled by the administrator of this host (<code className="mono">SENTREL_DISABLE_UPDATE_CHECK</code>).</Note></div>}
            <SettingRow label="Check for new releases" info="Every 6 hours the server asks GitHub for the latest release. It sends a User-Agent of Sentrel/<version> and nothing else about this install.">
              <Toggle checked={u.check_enabled} disabled={disabledByHost || busy === 'toggle'} onChange={(v) => saveToggles({ check_enabled: v })} />
            </SettingRow>
            {u.install_forced_off && <div className="py-2"><Note tone="warn">One-click updates are disabled by the administrator of this host (<code className="mono">SENTREL_DISABLE_SELF_UPDATE</code>).</Note></div>}
            <SettingRow label="Allow one-click updates" info="Lets an administrator install a signed release from this page (systemd installs only).">
              <Toggle checked={!!u.install_enabled && !u.install_forced_off} disabled={!!u.install_forced_off || busy === 'toggle'} onChange={(v) => saveToggles({ install_enabled: v })} />
            </SettingRow>
            <div className="py-3">
              <KV items={[
                ['Last check', u.last_check ? ago(u.last_check) : 'never'],
                ['Last error', u.last_error ? <span key="e" className="text-crit-ink">{u.last_error}</span> : 'none'],
                ['Install method', <Badge key="m" tone={u.method === 'systemd' ? 'ok' : 'muted'}>{methodLabel(u.method)}</Badge>],
              ]} />
            </div>
          </div>
        </Card>
      </div>
    </div>
  )
}

function methodLabel(m?: string) {
  switch (m) {
    case 'systemd': return 'systemd (install-server.sh)'
    case 'docker': return 'Docker'
    case 'package': return 'deb / rpm package'
    default: return 'manual'
  }
}

function Progress({ st, reconnecting, watching }: { st: InstallStatus; reconnecting: boolean; watching: boolean }) {
  const final = isFinalPhase(st.phase)
  const idx = stepIndex(st.phase)
  const rolling = st.phase === 'rolling_back'
  const bad = st.phase === 'failed' || st.phase === 'rolled_back' || rolling
  const stalled = st.phase === 'waiting_for_updater' && st.requested_at && Date.now() / 1000 - st.requested_at > 120
  return (
    <Card title={final ? (st.phase === 'done' ? 'Update installed' : st.phase === 'rolled_back' ? 'Update rolled back' : 'Update failed') : `Updating to ${st.version ?? ''}`}
      subtitle={final && st.finished_at ? dateTime(st.finished_at) : undefined}>
      {!final && (
        <ol className="space-y-2.5">
          {STEPS.map((s, i) => {
            const done = i < idx, cur = i === idx
            return (
              <li key={s.id} className="flex items-center gap-3 text-sm">
                <span className={cx('grid size-6 shrink-0 place-items-center rounded-full border text-[11px]',
                  done && 'border-ok/40 bg-ok/12 text-ok', cur && !bad && 'border-accent/40 bg-accent/12 text-accent', cur && bad && 'border-warn/40 bg-warn/12 text-warn', !done && !cur && 'border-line text-muted')}>
                  {done ? <Check className="size-3.5" /> : cur ? <Loader2 className="size-3.5 animate-spin" /> : i + 1}
                </span>
                <span className={cx(cur ? 'font-medium' : done ? 'text-fg' : 'text-muted')}>{s.label}</span>
              </li>
            )
          })}
        </ol>
      )}
      <div className={cx('space-y-2 text-sm', !final && 'mt-4')}>
        <p className={cx('flex items-center gap-2', bad && 'text-warn-ink')}>
          {bad ? <AlertTriangle className="size-4 shrink-0" /> : st.phase === 'done' ? <CheckCircle2 className="size-4 shrink-0 text-ok" /> : <Loader2 className="size-4 shrink-0 animate-spin text-accent" />}
          {phaseLabel(st.phase)}
        </p>
        {reconnecting && <p className="text-xs text-muted">The server is restarting. This page reloads automatically when the new version answers.</p>}
        {stalled && <Note tone="warn">The updater has not started. Check that <code className="mono">sentrel-updater.path</code> is active: <code className="mono">systemctl status sentrel-updater.path</code>.</Note>}
        {st.message && final && <p className={cx(st.phase === 'done' ? 'text-muted' : 'text-warn-ink')}>{st.message}</p>}
        {st.phase === 'done' && watching && <p className="text-xs text-muted">Reloading into the new version…</p>}
      </div>
    </Card>
  )
}

