// Pure helpers for the update notification UI: visibility rules for the pill
// and banner, install progress phases, and a small release-notes parser.
//
// Release notes come from GitHub and are untrusted. The parser never produces
// HTML: it returns plain data that React renders as text nodes (which React
// escapes), and only http(s) links become anchors.

export interface UpdateAsset { name: string; url: string; size: number }

export interface UpdateInfo {
  current: string
  latest?: string
  update_available: boolean
  check_enabled: boolean
  // Administrator-only fields.
  install_enabled?: boolean
  check_forced_off?: boolean
  install_forced_off?: boolean
  last_check?: number
  last_error?: string
  method?: 'systemd' | 'docker' | 'package' | 'manual'
  repo?: string
  hostname?: string
  published_at?: number
  html_url?: string
  notes?: string
  tag?: string
  assets?: UpdateAsset[]
  can_install?: boolean
  install_blocked?: string
}

export interface InstallStatus {
  phase: string
  version?: string
  message?: string
  from?: string
  started_at?: number
  finished_at?: number
  requested_at?: number
  rolled_back?: boolean
}

/** The sidebar pill is for administrators only. */
export function showPill(info: UpdateInfo | undefined, isAdmin: boolean): boolean {
  return isAdmin && !!info?.update_available && !!info.latest
}

export const dismissKey = (version: string) => `sentrel-update-dismissed:${version}`

type Store = Pick<Storage, 'getItem' | 'setItem'>
function defaultStore(): Store | null {
  try { return typeof localStorage === 'undefined' ? null : localStorage } catch { return null }
}

export function isDismissed(version: string, store: Store | null = defaultStore()): boolean {
  try { return store?.getItem(dismissKey(version)) === '1' } catch { return false }
}

export function dismiss(version: string, store: Store | null = defaultStore()): void {
  try { store?.setItem(dismissKey(version), '1') } catch { /* private mode, blocked storage */ }
}

/** One dismissible banner per version, administrators only. */
export function showBanner(info: UpdateInfo | undefined, isAdmin: boolean, store: Store | null = defaultStore()): boolean {
  return showPill(info, isAdmin) && !isDismissed(info!.latest!, store)
}

// ---------- install progress ----------

export const STEPS: { id: string; label: string }[] = [
  { id: 'downloading', label: 'Download' },
  { id: 'verifying', label: 'Verify signature' },
  { id: 'waiting_for_updater', label: 'Hand over to updater' },
  { id: 'installing', label: 'Install' },
  { id: 'restarting', label: 'Restart' },
  { id: 'checking', label: 'Health check' },
]

const ACTIVE = new Set([...STEPS.map((s) => s.id), 'rolling_back'])
export const isActivePhase = (p?: string) => !!p && ACTIVE.has(p)
export const isFinalPhase = (p?: string) => p === 'done' || p === 'failed' || p === 'rolled_back'

const bare = (v?: string) => (v ?? '').replace(/^v/, '')

/**
 * What the Updates page shows. A finished attempt (installed, failed or rolled
 * back) is shown for a day, but only while it is about the latest release: once
 * a newer one is out, "updated to 0.9.8" is old news. The install button
 * depends only on nothing running, so it stays available to retry a failed
 * update or to install a newer release.
 */
export function updateView(u: Pick<UpdateInfo, 'latest' | 'update_available'> & { can_install?: boolean }, st: InstallStatus | undefined, watching: boolean, nowSec = Date.now() / 1000) {
  const running = watching || isActivePhase(st?.phase)
  const recent = !!st?.finished_at && nowSec - st.finished_at < 24 * 3600
  const aboutLatest = !!st?.version && !!u.latest && bare(st.version) === bare(u.latest)
  return {
    showProgress: running || (isFinalPhase(st?.phase) && recent && aboutLatest),
    showInstall: !!u.update_available && !!u.can_install && !running,
  }
}

/** Index of the current step, or STEPS.length once finished. */
export function stepIndex(phase?: string): number {
  if (phase === 'done') return STEPS.length
  const i = STEPS.findIndex((s) => s.id === phase)
  return i < 0 ? 0 : i
}

export function phaseLabel(phase?: string): string {
  switch (phase) {
    case 'downloading': return 'Downloading the release…'
    case 'verifying': return 'Verifying the signature and checksum…'
    case 'waiting_for_updater': return 'Waiting for the updater to start…'
    case 'installing': return 'Installing the new binary…'
    case 'restarting': return 'Restarting the server…'
    case 'checking': return 'Waiting for the new version to become healthy…'
    case 'rolling_back': return 'The new version is unhealthy; restoring the previous one…'
    case 'done': return 'Update installed'
    case 'rolled_back': return 'Update rolled back'
    case 'failed': return 'Update failed'
    default: return ''
  }
}

// ---------- release notes ----------

export type Inline =
  | { t: 'text'; text: string }
  | { t: 'b'; text: string }
  | { t: 'code'; text: string }
  | { t: 'link'; text: string; href: string }

export type Block =
  | { t: 'h'; level: 1 | 2 | 3; inline: Inline[] }
  | { t: 'p'; inline: Inline[] }
  | { t: 'ul'; items: Inline[][] }
  | { t: 'ol'; items: Inline[][] }

const safeHref = (u: string) => /^https?:\/\/[^\s<>"']+$/i.test(u)

const INLINE = /\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)|(https?:\/\/[^\s<>)\]]+)/g

export function parseInline(s: string): Inline[] {
  const out: Inline[] = []
  let last = 0
  for (const m of s.matchAll(INLINE)) {
    const i = m.index ?? 0
    if (i > last) out.push({ t: 'text', text: s.slice(last, i) })
    if (m[1] !== undefined) out.push({ t: 'b', text: m[1] })
    else if (m[2] !== undefined) out.push({ t: 'code', text: m[2] })
    else if (m[3] !== undefined) out.push(safeHref(m[4]) ? { t: 'link', text: m[3], href: m[4] } : { t: 'text', text: m[0] })
    else if (m[5] !== undefined) out.push(safeHref(m[5]) ? { t: 'link', text: m[5], href: m[5] } : { t: 'text', text: m[0] })
    last = i + m[0].length
  }
  if (last < s.length) out.push({ t: 'text', text: s.slice(last) })
  return out
}

export function parseNotes(src: string): Block[] {
  const blocks: Block[] = []
  let para: string[] = []
  let list: { kind: 'ul' | 'ol'; items: Inline[][] } | null = null
  const flushPara = () => { if (para.length) { blocks.push({ t: 'p', inline: parseInline(para.join(' ')) }); para = [] } }
  const flushList = () => { if (list) { blocks.push({ t: list.kind, items: list.items }); list = null } }
  for (const raw of src.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.trimEnd()
    const h = /^(#{1,6})\s+(.*)$/.exec(line)
    const ul = /^\s*[-*+]\s+(.*)$/.exec(line)
    const ol = /^\s*\d+[.)]\s+(.*)$/.exec(line)
    if (!line.trim()) { flushPara(); flushList() }
    else if (h) { flushPara(); flushList(); blocks.push({ t: 'h', level: Math.min(h[1].length, 3) as 1 | 2 | 3, inline: parseInline(h[2]) }) }
    else if (ul || ol) {
      flushPara()
      const kind = ul ? 'ul' : 'ol'
      if (list && list.kind !== kind) flushList()
      if (!list) list = { kind, items: [] }
      list.items.push(parseInline((ul || ol)![1]))
    } else { flushList(); para.push(line.trim()) }
  }
  flushPara(); flushList()
  return blocks
}

// ---------- install instructions ----------

export interface InstallHelp { title: string; steps: { text: string; code?: string }[] }

export function installHelp(method: string | undefined, version: string): InstallHelp {
  switch (method) {
    case 'docker':
      return { title: 'Update the container', steps: [
        { text: 'Pull the new image:', code: `docker pull ghcr.io/xedigital/sentrel:${version}` },
        { text: `Set the image tag to ${version} in your compose file (or use latest) and recreate the container. The data volume is kept:`, code: 'docker compose up -d' },
      ] }
    case 'package':
      return { title: 'Update with your package manager', steps: [
        { text: 'Debian and Ubuntu:', code: 'sudo apt update && sudo apt install --only-upgrade sentrel-server' },
        { text: 'RHEL, Fedora and derivatives:', code: 'sudo dnf upgrade sentrel-server' },
      ] }
    default:
      return { title: 'Update manually', steps: [
        { text: 'Back up first, then download the server binary for your platform from the release page and verify it against the signed SHA256SUMS. Replace the binary and restart the service.' },
        { text: 'With the install script, which also installs the one-click updater units:', code: 'curl -fsSL https://github.com/XEDigital/Sentrel/releases/latest/download/install-server.sh -o install-server.sh\nsudo sh install-server.sh --url https://github.com/XEDigital/Sentrel/releases/latest/download/sentrel-server-linux-amd64' },
      ] }
  }
}
