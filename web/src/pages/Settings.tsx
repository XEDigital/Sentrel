import { useEffect, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Plus, RefreshCw, Save, Send, X } from 'lucide-react'
import { errorMessage, get, post, put } from '@/lib/api'
import { applyBranding, useAuth } from '@/lib/auth'
import { bytes, dateTime, duration, timezones } from '@/lib/format'
import type { Branding, Tenant } from '@/lib/types'
import { Badge, Button, Card, Checkbox, CodeBlock, CopyButton, ErrorBox, Field, Input, KV, Loading, InfoTip, Note, PageHeader, Select, SettingRow, SettingsGroup, TagInput, Textarea, Toggle, cx, useToast } from '@/components/ui'
import { roleInfo } from './Users'
import { UpdatesTab } from './UpdatesTab'
import type { UpdateInfo } from '@/lib/updates'

type Section = 'general' | 'tls' | 'smtp' | 'directory' | 'sso' | 'security' | 'retention' | 'agent_defaults' | 'alerting' | 'vuln' | 'snmp' | 'updates' | 'server'

export function Settings() {
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') as Section) || 'general'
  const s = useQuery({ queryKey: ['settings'], queryFn: () => get<Record<string, any>>('/settings') })
  const upd = useQuery({ queryKey: ['updates'], queryFn: () => get<UpdateInfo>('/server/updates'), refetchInterval: 5 * 60_000 })
  return (
    <div>
      <PageHeader title="Settings" info="Server-wide configuration. Changes apply immediately and are recorded in the audit log." />
      <div className="flex flex-col gap-6 lg:flex-row">
      <SettingsNav value={tab} onChange={(t) => setParams({ tab: t }, { replace: true })} updateAvailable={!!upd.data?.update_available} />
      <div className="min-w-0 max-w-4xl flex-1">
      {tab === 'updates' ? <UpdatesTab /> : s.isLoading ? <Loading /> : s.error ? <ErrorBox error={s.error} /> : (
        <>
          {tab === 'general' && <General data={s.data!.general} />}
          {tab === 'tls' && <TLS data={s.data!.tls} active={s.data!.active_tls_mode} fp={s.data!.ca_fingerprint} />}
          {tab === 'smtp' && <SMTP data={s.data!.smtp} />}
          {tab === 'directory' && <Directory ldap={s.data!.ldap} radius={s.data!.radius} />}
          {tab === 'sso' && <SSO oidc={s.data!.oidc} proxy={s.data!.proxy_auth} serverUrl={s.data!.general?.server_url} />}
          {tab === 'security' && <Security data={s.data!.security} />}
          {tab === 'retention' && <Retention data={s.data!.retention} />}
          {tab === 'agent_defaults' && <Agents data={s.data!.agent_defaults} />}
          {tab === 'alerting' && <Alerting data={s.data!.alerting} />}
          {tab === 'vuln' && <Vuln data={s.data!.vuln} />}
          {tab === 'snmp' && <SnmpProfiles />}
          {tab === 'server' && <Server />}
        </>
      )}
      </div>
      </div>
    </div>
  )
}

const SECTIONS: { title: string; items: { id: Section; label: string }[] }[] = [
  { title: 'Server', items: [{ id: 'general', label: 'General' }, { id: 'tls', label: 'TLS & access' }, { id: 'retention', label: 'Data retention' }, { id: 'updates', label: 'Updates' }, { id: 'server', label: 'Server & backup' }] },
  { title: 'Sign-in', items: [{ id: 'security', label: 'Security' }, { id: 'sso', label: 'Single sign-on' }, { id: 'directory', label: 'LDAP & RADIUS' }] },
  { title: 'Monitoring', items: [{ id: 'agent_defaults', label: 'Agents' }, { id: 'alerting', label: 'Alerting' }, { id: 'smtp', label: 'Email' }, { id: 'vuln', label: 'Vulnerabilities' }, { id: 'snmp', label: 'SNMP profiles' }] },
]

/** Section list: a vertical menu on wide screens, a dropdown on small ones. */
function SettingsNav({ value, onChange, updateAvailable }: { value: Section; onChange: (s: Section) => void; updateAvailable: boolean }) {
  return (
    <>
      <div className="lg:hidden">
        <Select value={value} onChange={(e) => onChange(e.target.value as Section)} aria-label="Settings section">
          {SECTIONS.map((g) => (
            <optgroup key={g.title} label={g.title}>
              {g.items.map((i) => <option key={i.id} value={i.id}>{i.label}{i.id === 'updates' && updateAvailable ? ' (update available)' : ''}</option>)}
            </optgroup>
          ))}
        </Select>
      </div>
      <nav className="hidden w-48 shrink-0 lg:block" aria-label="Settings sections">
        {SECTIONS.map((g) => (
          <div key={g.title} className="mb-4">
            <div className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-wide text-muted">{g.title}</div>
            {g.items.map((i) => (
              <button key={i.id} type="button" onClick={() => onChange(i.id)} aria-current={value === i.id ? 'page' : undefined}
                className={cx('flex w-full items-center justify-between rounded-lg px-3 py-1.5 text-left text-sm', value === i.id ? 'bg-accent/10 font-medium text-accent' : 'text-muted hover:bg-panel-2 hover:text-fg')}>
                {i.label}
                {i.id === 'updates' && updateAvailable && <span className="size-2 rounded-full bg-ok-fill" title="Update available" />}
              </button>
            ))}
          </div>
        ))}
      </nav>
    </>
  )
}

function useSection<T extends Record<string, any>>(section: string, data: T) {
  const [v, setV] = useState<T>(data)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<unknown>(null)
  const toast = useToast()
  const qc = useQueryClient()
  useEffect(() => setV(data), [data])
  const set = (patch: Partial<T>) => setV({ ...v, ...patch })
  const save = async (override?: T) => {
    setBusy(true)
    setErr(null)
    try {
      const r = await put<{ warning?: string }>(`/settings/${section}`, override || v)
      toast(r?.warning || 'Settings saved', r?.warning ? 'info' : 'ok')
      qc.invalidateQueries({ queryKey: ['settings'] })
    } catch (e) {
      setErr(e)
    } finally {
      setBusy(false)
    }
  }
  return { v, set, save, busy, err }
}

function SaveBar({ busy, err, onSave, extra }: { busy: boolean; err: unknown; onSave: () => void; extra?: ReactNode }) {
  return (
    <div className="mt-4 space-y-3">
      <ErrorBox error={err} />
      <div className="flex flex-wrap gap-2"><Button variant="primary" loading={busy} icon={<Save className="size-4" />} onClick={onSave}>Save</Button>{extra}</div>
    </div>
  )
}

const num = (s: string) => (s === '' ? 0 : Number(s))

/** Short numeric input for a SettingRow. */
function NumInput({ value, onChange, min, max, className }: { value: number | string; onChange: (n: number) => void; min?: number; max?: number; className?: string }) {
  return <Input type="number" min={min} max={max} className={`h-8 w-24 ${className ?? ''}`} value={value} onChange={(e) => onChange(num(e.target.value))} />
}

/** Row whose control is a wide field (tags, long lists) shown beneath the label. */
function StackRow({ label, info, children }: { label: ReactNode; info?: ReactNode; children: ReactNode }) {
  return (
    <div className="space-y-1.5 py-3">
      <div className="flex items-center gap-1.5 text-sm">{label}{info && <InfoTip>{info}</InfoTip>}</div>
      {children}
    </div>
  )
}
const secretHint = (set?: boolean) => (set ? 'Stored; leave blank to keep it' : undefined)

function General({ data }: { data: any }) {
  const { v, set, save, busy, err } = useSection('general', data)
  return (
    <Card title="General" className="max-w-3xl">
      <div className="-my-2 divide-y divide-line/60">
        <StackRow label="Public server URL" info="Used in agent install commands, notification links and passkeys (the RP ID is this hostname). Example: https://monitor.example.com">
          <Input value={v.server_url} onChange={(e) => set({ server_url: e.target.value })} />
        </StackRow>
        <SettingRow label="Timezone" info="Used for maintenance windows and scan schedules.">
          <Select className="h-8 w-64 max-w-full" value={v.timezone} onChange={(e) => set({ timezone: e.target.value })}>{timezones().map((z) => <option key={z}>{z}</option>)}</Select>
        </SettingRow>
      </div>
      <SaveBar busy={busy} err={err} onSave={() => save()} />
    </Card>
  )
}

function TLS({ data, active, fp }: { data: any; active: string; fp: string }) {
  const { v, set, save, busy, err } = useSection('tls', data)
  return (
    <div className="grid max-w-5xl gap-4 xl:grid-cols-2">
      <Card title="TLS & listener" subtitle={`Serving: ${active}`} className="h-full">
        <div className="-my-2 divide-y divide-line/60">
          <SettingRow label="Mode">
            <Select className="h-8 w-72 max-w-full" value={v.mode} onChange={(e) => set({ mode: e.target.value })}>
              <option value="http">Plain HTTP (behind a reverse proxy)</option>
              <option value="selfsigned">Self-signed (internal CA)</option>
              <option value="acme">Let's Encrypt (automatic)</option>
            </Select>
          </SettingRow>
          <SettingRow label="Listen address" info="host:port. ACME mode always uses :443 (plus :80 for challenges). Overridden by --listen.">
            <Input className="h-8 w-48" value={v.listen} onChange={(e) => set({ listen: e.target.value })} />
          </SettingRow>
          {v.mode !== 'http' && <>
            <SettingRow label="Hostname"><Input className="h-8 w-64 max-w-full" value={v.hostname} onChange={(e) => set({ hostname: e.target.value })} /></SettingRow>
            <StackRow label="Additional names" info="Extra DNS names or IPs for the certificate."><TagInput value={v.extra_names || []} onChange={(x) => set({ extra_names: x })} /></StackRow>
          </>}
          {v.mode === 'acme' && <>
            <SettingRow label="Contact email"><Input className="h-8 w-64 max-w-full" value={v.acme_email} onChange={(e) => set({ acme_email: e.target.value })} /></SettingRow>
            <SettingRow label="ACME directory" info="Optional. Leave blank for Let's Encrypt production; use the staging URL to test."><Input className="h-8 w-64 max-w-full" value={v.acme_directory} onChange={(e) => set({ acme_directory: e.target.value })} /></SettingRow>
          </>}
          <SettingRow label="Trust reverse proxy headers" info="Use X-Forwarded-For and X-Forwarded-Proto for client IPs and HTTPS detection. Only enable when the server is not directly reachable.">
            <Toggle checked={!!v.trust_proxy} onChange={(x) => set({ trust_proxy: x })} />
          </SettingRow>
          {v.trust_proxy && <StackRow label="Trusted proxies" info="IP addresses or CIDR ranges whose forwarding headers are believed (press Enter to add). Empty means loopback only. X-Forwarded-For is read right to left, skipping these."><TagInput value={v.trusted_proxies || []} onChange={(x) => set({ trusted_proxies: x })} placeholder="127.0.0.1 or 10.0.0.0/8" /></StackRow>}
        </div>
        <Note tone="warn" className="mt-3">Switching mode restarts the listener. If it fails to start, the server falls back to plain HTTP; <code className="mono">--force-http</code> recovers manually.</Note>
        <SaveBar busy={busy} err={err} onSave={() => save()} />
      </Card>
      <Card title="Reverse proxy" className="h-full" info="Any proxy works if it forwards HTTP/2 (gRPC) to the listen address. Agents authenticate with signed requests, so mTLS is not required through the proxy.">
        <div className="space-y-3 text-sm">
          <p className="text-muted">In plain HTTP mode a proxy terminates TLS. Caddy example for the UI, API and agent gRPC:</p>
          <CodeBlock code={`monitor.example.com {\n  reverse_proxy h2c://127.0.0.1:8080\n}`} />
          <KV items={[['Internal CA fingerprint', <span key="f" className="mono break-all text-xs">{fp}</span>]]} />
        </div>
      </Card>
    </div>
  )
}

function SMTP({ data }: { data: any }) {
  const { v, set, save, busy, err } = useSection('smtp', data)
  const [to, setTo] = useState('')
  const toast = useToast()
  return (
    <Card title="Email (SMTP relay)" info="Used by email notification channels. Works with Gmail, Microsoft 365, Resend, SES or your own relay." className="max-w-3xl">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Host"><Input value={v.host} onChange={(e) => set({ host: e.target.value })} placeholder="smtp.gmail.com" /></Field>
        <Field label="Port"><Input type="number" value={v.port} onChange={(e) => set({ port: num(e.target.value) })} /></Field>
        <Field label="Security"><Select value={v.tls_mode} onChange={(e) => set({ tls_mode: e.target.value })}><option value="starttls">STARTTLS (587)</option><option value="tls">Implicit TLS (465)</option><option value="none">None</option></Select></Field>
        <Field label="From address"><Input value={v.from} onChange={(e) => set({ from: e.target.value })} placeholder="Sentrel <alerts@example.com>" /></Field>
        <Field label="Username"><Input value={v.username} onChange={(e) => set({ username: e.target.value })} /></Field>
        <Field label="Password" hint={secretHint(v.password_set)}><Input type="password" autoComplete="new-password" value={v.password || ''} onChange={(e) => set({ password: e.target.value })} /></Field>
        <div className="sm:col-span-2"><Toggle checked={!!v.skip_verify} onChange={(x) => set({ skip_verify: x })} label="Skip certificate verification" /></div>
      </div>
      <SaveBar busy={busy} err={err} onSave={() => save({ ...v, enabled: true })} extra={<>
        <Input value={to} onChange={(e) => setTo(e.target.value)} placeholder="send test to…" className="w-56" />
        <Button icon={<Send className="size-4" />} disabled={!to} onClick={async () => {
          try { const r = await post<any>('/settings/smtp/test', { to }); toast(r.ok ? 'Test email sent' : `Failed: ${r.error}`, r.ok ? 'ok' : 'crit') } catch (e) { toast(errorMessage(e), 'crit') }
        }}>Test (save first)</Button>
      </>} />
    </Card>
  )
}

function Directory({ ldap, radius }: { ldap: any; radius: any }) {
  const L = useSection('ldap', ldap)
  const R = useSection('radius', radius)
  const toast = useToast()
  const tenants = useQuery({ queryKey: ['tenants'], queryFn: () => get<Tenant[]>('/tenants') })
  const [tu, setTu] = useState({ username: '', password: '' })
  const [ru, setRu] = useState({ username: '', password: '' })
  const maps: any[] = L.v.role_mapping || []
  const roles = (t: number) => (t === 0 ? ['admin', 'operator', 'viewer'] : ['tenant_admin', 'tenant_viewer'])
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="LDAP / Active Directory" className="h-full">
        <div className="space-y-3">
          <Toggle checked={!!L.v.enabled} onChange={(x) => L.set({ enabled: x })} label="Enable LDAP sign-in" />
          {!!L.v.enabled && (<>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="URL" className="sm:col-span-2" hint="ldaps://dc1.example.com:636 or ldap://…:389"><Input value={L.v.url} onChange={(e) => L.set({ url: e.target.value })} /></Field>
            <Field label="Bind DN"><Input value={L.v.bind_dn} onChange={(e) => L.set({ bind_dn: e.target.value })} placeholder="CN=svc-sentrel,OU=Service,DC=example,DC=com" /></Field>
            <Field label="Bind password" hint={secretHint(L.v.bind_password_set)}><Input type="password" autoComplete="new-password" value={L.v.bind_password || ''} onChange={(e) => L.set({ bind_password: e.target.value })} /></Field>
            <Field label="Base DN"><Input value={L.v.base_dn} onChange={(e) => L.set({ base_dn: e.target.value })} placeholder="DC=example,DC=com" /></Field>
            <Field label="User filter" hint="%s is the username. AD: (&(objectClass=user)(sAMAccountName=%s))"><Input value={L.v.user_filter} onChange={(e) => L.set({ user_filter: e.target.value })} /></Field>
            <Field label="Email attribute"><Input value={L.v.email_attr} onChange={(e) => L.set({ email_attr: e.target.value })} /></Field>
            <Field label="Name attribute"><Input value={L.v.name_attr} onChange={(e) => L.set({ name_attr: e.target.value })} /></Field>
            <Field label="Group attribute"><Input value={L.v.group_attr} onChange={(e) => L.set({ group_attr: e.target.value })} /></Field>
            <div className="space-y-2 pt-5"><Toggle checked={!!L.v.start_tls} onChange={(x) => L.set({ start_tls: x })} label="StartTLS" /><Toggle checked={!!L.v.skip_verify} onChange={(x) => L.set({ skip_verify: x })} label="Skip certificate verification" /></div>
          </div>
          <Field label="Group → role mapping" info="The most privileged matching mapping wins. Users matching no mapping get the default role, or are refused if none.">
            <div className="space-y-2">
              {maps.map((m, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2">
                  <Input className="min-w-56 flex-1" value={m.group} placeholder="CN=Monitoring Admins,OU=Groups,DC=…" onChange={(e) => { const a = [...maps]; a[i] = { ...m, group: e.target.value }; L.set({ role_mapping: a }) }} />
                  <Select value={m.tenant_id} onChange={(e) => { const a = [...maps]; const t = Number(e.target.value); a[i] = { ...m, tenant_id: t, role: roles(t)[0] }; L.set({ role_mapping: a }) }}>
                    {tenants.data?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </Select>
                  <Select value={m.role} onChange={(e) => { const a = [...maps]; a[i] = { ...m, role: e.target.value }; L.set({ role_mapping: a }) }}>
                    {roles(m.tenant_id).map((r) => <option key={r} value={r}>{roleInfo[r].label}</option>)}
                  </Select>
                  <Button size="sm" variant="ghost" icon={<X className="size-3.5" />} onClick={() => L.set({ role_mapping: maps.filter((_, j) => j !== i) })} />
                </div>
              ))}
              <Button size="sm" icon={<Plus className="size-3.5" />} onClick={() => L.set({ role_mapping: [...maps, { group: '', role: 'viewer', tenant_id: 0 }] })}>Add mapping</Button>
            </div>
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Default role (no mapping matched)"><Select value={L.v.default_role} onChange={(e) => L.set({ default_role: e.target.value })}><option value="">Refuse sign-in</option>{roles(L.v.default_tenant || 0).map((r) => <option key={r} value={r}>{roleInfo[r].label}</option>)}</Select></Field>
            <Field label="Default tenant"><Select value={L.v.default_tenant || 0} onChange={(e) => L.set({ default_tenant: Number(e.target.value), default_role: '' })}>{tenants.data?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</Select></Field>
          </div>
          </>)}
        </div>
        <SaveBar busy={L.busy} err={L.err} onSave={() => L.save()} extra={!!L.v.enabled && <>
          <Input className="w-32" placeholder="test user" value={tu.username} onChange={(e) => setTu({ ...tu, username: e.target.value })} />
          <Input className="w-32" type="password" placeholder="password" value={tu.password} onChange={(e) => setTu({ ...tu, password: e.target.value })} />
          <Button onClick={async () => { try { const r = await post<any>('/settings/ldap/test', tu); toast(r.ok ? r.message : r.error, r.ok ? 'ok' : 'crit') } catch (e) { toast(errorMessage(e), 'crit') } }}>Test (save first)</Button>
        </>} />
      </Card>
      <Card title="RADIUS" className="h-full">
        <div className="space-y-3">
          <Toggle checked={!!R.v.enabled} onChange={(x) => R.set({ enabled: x })} label="Enable RADIUS sign-in" />
          {!!R.v.enabled && (<>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Server" hint="host:port (default port 1812)"><Input value={R.v.server} onChange={(e) => R.set({ server: e.target.value })} /></Field>
            <Field label="Shared secret" hint={secretHint(R.v.secret_set)}><Input type="password" autoComplete="new-password" value={R.v.secret || ''} onChange={(e) => R.set({ secret: e.target.value })} /></Field>
            <Field label="NAS identifier"><Input value={R.v.nas_identifier} onChange={(e) => R.set({ nas_identifier: e.target.value })} /></Field>
            <Field label="Timeout (s)"><Input type="number" value={R.v.timeout_seconds} onChange={(e) => R.set({ timeout_seconds: num(e.target.value) })} /></Field>
            <Field label="Role attribute" info="Filter-Id or Class may carry “sentrel:admin”."><Select value={R.v.role_attribute} onChange={(e) => R.set({ role_attribute: e.target.value })}><option>Filter-Id</option><option>Class</option></Select></Field>
            <Field label="Default tenant"><Select value={R.v.default_tenant || 0} onChange={(e) => R.set({ default_tenant: Number(e.target.value), default_role: '' })}>{tenants.data?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</Select></Field>
            <Field label="Default role"><Select value={R.v.default_role} onChange={(e) => R.set({ default_role: e.target.value })}><option value="">Refuse unless attribute sets a role</option>{roles(R.v.default_tenant || 0).map((r) => <option key={r} value={r}>{roleInfo[r].label}</option>)}</Select></Field>
          </div>
          </>)}
        </div>
        <SaveBar busy={R.busy} err={R.err} onSave={() => R.save()} extra={!!R.v.enabled && <>
          <Input className="w-32" placeholder="test user" value={ru.username} onChange={(e) => setRu({ ...ru, username: e.target.value })} />
          <Input className="w-32" type="password" placeholder="password" value={ru.password} onChange={(e) => setRu({ ...ru, password: e.target.value })} />
          <Button onClick={async () => { try { const r = await post<any>('/settings/radius/test', ru); toast(r.ok ? `${r.message}${r.role_hint ? ` (role hint ${r.role_hint})` : ''}` : r.error, r.ok ? 'ok' : 'crit') } catch (e) { toast(errorMessage(e), 'crit') } }}>Test (save first)</Button>
        </>} />
      </Card>
    </div>
  )
}

function Security({ data }: { data: any }) {
  const { v, set, save, busy, err } = useSection('security', data)
  return (
    <Card title="Security" className="max-w-3xl">
      <div className="-my-2 divide-y divide-line/60">
        <SettingRow label="Two-factor authentication">
          <Select className="h-8 w-80 max-w-full" value={v.require_2fa} onChange={(e) => set({ require_2fa: e.target.value })}>
            <option value="none">Optional</option><option value="admins">Required for administrators and tenant admins</option><option value="all">Required for everyone</option>
          </Select>
        </SettingRow>
        <SettingRow label="Session length (hours)" info="Sliding: extends while in use."><NumInput value={v.session_hours} onChange={(n) => set({ session_hours: n })} /></SettingRow>
        <SettingRow label="Minimum password length"><NumInput value={v.password_min_length} onChange={(n) => set({ password_min_length: n })} /></SettingRow>
        <SettingRow label="Lock out after failed logins"><NumInput value={v.lockout_attempts} onChange={(n) => set({ lockout_attempts: n })} /></SettingRow>
        <SettingRow label="Lockout window (minutes)"><NumInput value={v.lockout_minutes} onChange={(n) => set({ lockout_minutes: n })} /></SettingRow>
        <SettingRow label="Require an API key for /metrics" info="When off, anyone who can reach the server can scrape the Prometheus endpoint.">
          <Toggle checked={!!v.metrics_auth} onChange={(x) => set({ metrics_auth: x })} />
        </SettingRow>
        <SettingRow label="Allow tenants to monitor private addresses" info="When off, tenant checks and notification channels can only reach public addresses (loopback, private ranges and link-local such as cloud metadata are blocked). Provider checks are never restricted.">
          <Toggle checked={!!v.allow_private_targets_for_tenants} onChange={(x) => set({ allow_private_targets_for_tenants: x })} />
        </SettingRow>
      </div>
      <SaveBar busy={busy} err={err} onSave={() => save()} />
    </Card>
  )
}

function Retention({ data }: { data: any }) {
  const { v, set, save, busy, err } = useSection('retention', data)
  return (
    <Card title="Data retention" className="max-w-3xl" info="Per-host overrides live in each host's settings. Per-host storage is computed nightly; the “Metric storage per host” threshold raises a warning for hosts above the limit.">
      <div className="-my-2 divide-y divide-line/60">
        <SettingRow label="Metrics (days)" info="Time-series data; default 31."><NumInput value={v.days} onChange={(n) => set({ days: n })} /></SettingRow>
        <SettingRow label="Alert history (days)"><NumInput value={v.alert_history_days} onChange={(n) => set({ alert_history_days: n })} /></SettingRow>
        <SettingRow label="Audit log (days)"><NumInput value={v.audit_days} onChange={(n) => set({ audit_days: n })} /></SettingRow>
        <SettingRow label="Job history (days)"><NumInput value={v.job_history_days} onChange={(n) => set({ job_history_days: n })} /></SettingRow>
        <SettingRow label="Failed-login events (days)"><NumInput value={v.security_event_days} onChange={(n) => set({ security_event_days: n })} /></SettingRow>
        <SettingRow label="Warn when the data disk is above (%)"><NumInput value={v.disk_warn_percent} onChange={(n) => set({ disk_warn_percent: n })} /></SettingRow>
      </div>
      <SaveBar busy={busy} err={err} onSave={() => save()} />
    </Card>
  )
}

function Agents({ data }: { data: any }) {
  const { v, set, save, busy, err } = useSection('agent_defaults', data)
  const tog = (k: string, label: string, info?: ReactNode) => (
    <SettingRow label={label} info={info}><Toggle checked={!!v[k]} onChange={(x) => set({ [k]: x })} /></SettingRow>
  )
  return (
    <div className="max-w-5xl space-y-4">
      <Card title="Collection defaults" info="Pushed to every agent immediately; hosts can override.">
        <div className="-my-3 grid gap-x-8 lg:grid-cols-2">
          <SettingsGroup title="Intervals">
            <SettingRow label="Collection interval (s)"><NumInput value={v.interval_seconds} onChange={(n) => set({ interval_seconds: n })} /></SettingRow>
            <SettingRow label="Package inventory (s)"><NumInput value={v.inventory_interval_seconds} onChange={(n) => set({ inventory_interval_seconds: n })} /></SettingRow>
            <SettingRow label="Security report (s)"><NumInput value={v.security_interval_seconds} onChange={(n) => set({ security_interval_seconds: n })} /></SettingRow>
            <SettingRow label="Top processes"><NumInput value={v.top_processes} onChange={(n) => set({ top_processes: n })} /></SettingRow>
            {tog('auto_update', 'Update agents automatically', 'When a host\'s agent is older than the agent bundled with this server, a signed update job is queued (it self-tests and rolls back on failure).')}
          </SettingsGroup>
          <SettingsGroup title="Collect">
            {tog('collect_services', 'All services')}
            {tog('collect_ports', 'Listening ports')}
            {tog('collect_docker', 'Docker containers')}
            {tog('collect_temperatures', 'Temperatures')}
            {tog('fail2ban_enabled', 'Read fail2ban')}
            {tog('refresh_package_index', 'Refresh package index')}
          </SettingsGroup>
        </div>
        <div className="border-t border-line/60">
          <StackRow label="Always-watched services"><TagInput value={v.watched_services || []} onChange={(x) => set({ watched_services: x })} placeholder="sshd" /></StackRow>
        </div>
      </Card>
      <Card title="Host defaults" info="Hosts inherit these unless a setting is overridden on the host; each host's Security, Packages and Storage views show which values it inherits. Alert levels for failed logins and port scans can also be set under Thresholds, where the brute-force threshold below is used as the warning level.">
        <div className="-my-3 grid gap-x-8 lg:grid-cols-2">
          <SettingsGroup title="Permissions">
            {tog('allow_upgrades', 'Allow remote upgrades', 'Lets administrators install updates and remove old kernels. Off by default.')}
            {tog('allow_cleanup', 'Allow disk cleanup', 'Lets administrators remove caches, old logs and temporary files. Each run still needs a dry run and confirmation.')}
            {tog('allow_ip_block', 'Allow firewall IP blocking', 'Lets Sentrel add and remove firewall blocks. Blocks always expire.')}
            {tog('auto_block', 'Block attackers automatically', 'Blocks sources that reach the brute-force or port-scan thresholds. Needs IP blocking. Off by default.')}
          </SettingsGroup>
          <SettingsGroup title="Blocking">
            <SettingRow label="Auto-block threshold" info="Failed logins from one address within the window before it is blocked."><NumInput min={1} value={v.auto_block_threshold} onChange={(n) => set({ auto_block_threshold: n })} /></SettingRow>
            <SettingRow label="Block duration (minutes)"><NumInput min={1} value={v.auto_block_minutes} onChange={(n) => set({ auto_block_minutes: n })} /></SettingRow>
            <StackRow label="Never block" info="IPs or CIDR ranges that are never blocked, manually or automatically (your office, VPN, monitoring). The Sentrel server's own addresses are always protected."><TagInput value={v.never_block || []} onChange={(x) => set({ never_block: x, auto_block_whitelist: [] })} placeholder="203.0.113.0/24" /></StackRow>
          </SettingsGroup>
          <SettingsGroup title="Brute-force detection">
            {tog('bruteforce_enabled', 'Detect failed logins', 'Reads the auth logs (Linux) and the Security log (Windows).')}
            <SettingRow label="Alert threshold (attempts)" info="Failed attempts from one address within the window before an alert."><NumInput min={1} value={v.bruteforce_threshold} onChange={(n) => set({ bruteforce_threshold: n })} /></SettingRow>
            <SettingRow label="Detection window (minutes)"><NumInput min={1} value={v.bruteforce_window_minutes} onChange={(n) => set({ bruteforce_window_minutes: n })} /></SettingRow>
          </SettingsGroup>
          <SettingsGroup title="Port-scan detection">
            {tog('portscan_enabled', 'Detect port scans', 'Linux with nftables. A kernel rule counts connection attempts to closed ports per source; it never drops traffic. Not available on Windows.')}
            <SettingRow label="Alert threshold (per minute)" info="Closed-port connection attempts per minute from one source."><NumInput min={1} value={v.portscan_threshold_per_min} onChange={(n) => set({ portscan_threshold_per_min: n })} /></SettingRow>
            <StackRow label="Allowlist" info="Sources never flagged as scanners. Addresses on the never-block list are excluded as well."><TagInput value={v.portscan_allowlist || []} onChange={(x) => set({ portscan_allowlist: x })} placeholder="198.51.100.0/24" /></StackRow>
          </SettingsGroup>
        </div>
      </Card>
      <SaveBar busy={busy} err={err} onSave={() => save()} />
    </div>
  )
}

function Alerting({ data }: { data: any }) {
  const { v, set, save, busy, err } = useSection('alerting', data)
  return (
    <Card title="Alerting" className="max-w-3xl" info="Hosts are marked down after the “Host offline after” threshold.">
      <div className="-my-2 divide-y divide-line/60">
        <SettingRow label="Group wait (seconds)" info="Combine events arriving within this window into one message."><NumInput value={v.group_wait_seconds} onChange={(n) => set({ group_wait_seconds: n })} /></SettingRow>
        <SettingRow label="Default repeat for new channels (min)" info="Re-send unacknowledged firing alerts at this interval; 0 = never. Repeats stop on acknowledgement, resolution, muting or suppression (maintenance or a parent that is down). Each channel can override it."><NumInput value={v.default_repeat_minutes} onChange={(n) => set({ default_repeat_minutes: n })} /></SettingRow>
        <SettingRow label="Flap detection window (min)"><NumInput value={v.flap_window_minutes} onChange={(n) => set({ flap_window_minutes: n })} /></SettingRow>
        <SettingRow label="Flapping after N state changes" info="0 disables flap detection."><NumInput value={v.flap_threshold} onChange={(n) => set({ flap_threshold: n })} /></SettingRow>
        <SettingRow label="Resolve after N good evaluations"><NumInput value={v.resolve_count} onChange={(n) => set({ resolve_count: n })} /></SettingRow>
      </div>
      <SaveBar busy={busy} err={err} onSave={() => save()} />
    </Card>
  )
}

function Vuln({ data }: { data: any }) {
  const { v, set, save, busy, err } = useSection('vuln', data)
  const [deleteDb, setDeleteDb] = useState(false)
  const db = useQuery({ queryKey: ['vulns', 'db'], queryFn: () => get<any>('/vulnerabilities/db'), refetchInterval: (q) => (q.state.data?.db?.updating ? 3000 : 30000) })
  const turningOff = !v.enabled && !!data.enabled
  const dbInfo = db.data?.db
  return (
    <Card title="Vulnerability scanning" className="max-w-3xl">
      <div className="-my-2 divide-y divide-line/60">
        <SettingRow label="Enable vulnerability scanning" info="Off by default to keep the server small. Turning it on downloads the Grype vulnerability database in the background: about 3 GB on disk, several minutes on first download, plus extra memory while scanning. Recommended for servers with 2 GB of RAM or more.">
          <Toggle checked={!!v.enabled} onChange={(x) => set({ enabled: x })} />
        </SettingRow>
        {v.enabled && data.enabled && dbInfo && (
          <p className="py-2 text-xs text-muted">{dbInfo.available ? `Database ready: ${bytes(dbInfo.size_bytes)}, built ${dateTime(Date.parse(dbInfo.built) / 1000)}.` : dbInfo.updating ? 'Downloading the database…' : `Database not available${dbInfo.last_error ? `: ${dbInfo.last_error}` : ''}.`}</p>
        )}
        {turningOff && (
          <div className="py-3"><Checkbox checked={deleteDb} onChange={setDeleteDb} label="Also delete the downloaded database to free disk space" /></div>
        )}
        <SettingRow label="Rescan a host whenever its packages change"><Toggle checked={!!v.scan_after_inventory} onChange={(x) => set({ scan_after_inventory: x })} /></SettingRow>
        <SettingRow label="Alert only on vulnerabilities that are fixable now"><Toggle checked={!!v.only_fixable} onChange={(x) => set({ only_fixable: x })} /></SettingRow>
        <SettingRow label="Alert on kernels that are not running" info="Off by default: an old kernel that is installed but not booted is not exploitable. The findings stay visible in the list either way.">
          <Toggle checked={!!v.alert_on_inactive_kernels} onChange={(x) => set({ alert_on_inactive_kernels: x })} />
        </SettingRow>
        <SettingRow label="Alert at severity">
          <Select className="h-8 w-44" value={v.alert_severity} onChange={(e) => set({ alert_severity: e.target.value })}><option value="Critical">Critical</option><option value="High">High and above</option><option value="Medium">Medium and above</option><option value="none">Never alert</option></Select>
        </SettingRow>
        <SettingRow label="Daily DB update hour (server time)"><NumInput min={0} max={23} value={v.sync_hour} onChange={(n) => set({ sync_hour: n })} /></SettingRow>
        <StackRow label="Database URL" info="For an air-gapped mirror. Blank uses Anchore's public listing; mirror https://grype.anchore.io/databases to serve it internally.">
          <Input value={v.db_url} onChange={(e) => set({ db_url: e.target.value })} />
        </StackRow>
      </div>
      <SaveBar busy={busy} err={err} onSave={() => save(turningOff && deleteDb ? { ...v, delete_db: true } : undefined)} />
    </Card>
  )
}

function SnmpProfiles() {
  const p = useQuery({ queryKey: ['snmp-profiles'], queryFn: () => get<any>('/snmp/profiles') })
  const qc = useQueryClient()
  const toast = useToast()
  return (
    <Card title="SNMP device profiles" info="Built-in profiles plus YAML files in the custom directory. A custom profile with the same name overrides a built-in."
      actions={<Button size="sm" icon={<RefreshCw className="size-3.5" />} onClick={async () => { try { await post('/snmp/profiles/reload'); toast('Profiles reloaded'); qc.invalidateQueries({ queryKey: ['snmp-profiles'] }) } catch (e) { toast(errorMessage(e), 'crit') } }}>Reload</Button>}>
      {p.data?.error && <ErrorBox error={p.data.error} className="mb-3" />}
      <p className="mb-3 text-sm text-muted">Custom directory: <code className="mono">{p.data?.custom_dir}</code></p>
      <div className="space-y-3">
        {(p.data?.profiles || []).map((x: any) => (
          <details key={x.name} className="rounded-xl border border-line/70 p-4">
            <summary className="cursor-pointer"><b>{x.name}</b> <Badge>{x.source}</Badge> <span className="text-sm text-muted">{x.description}</span></summary>
            <div className="mt-2 text-xs">
              {x.include?.length > 0 && <p className="text-muted">includes: {x.include.join(', ')}</p>}
              {(x.match?.sys_object_id || x.match?.sys_descr) && <p className="text-muted">matches: {[...(x.match.sys_object_id || []), ...(x.match.sys_descr || [])].join(', ')}</p>}
              <ul className="mono mt-2 space-y-1">{(x.metrics || []).map((m: any) => <li key={m.name}>{m.name}: {m.expr || m.oid}{m.label_oid ? ` [per ${m.label_name || 'index'}]` : ''}</li>)}</ul>
            </div>
          </details>
        ))}
      </div>
    </Card>
  )
}

function Server() {
  const s = useQuery({ queryKey: ['server-status'], queryFn: () => get<any>('/server/status'), refetchInterval: 30_000 })
  if (s.isLoading) return <Loading />
  const x = s.data
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="Server" className="h-full">
        <KV items={[
          ['Version', `${x.version} (${x.commit}, ${x.build_date})`], ['Go', x.go], ['Uptime', duration(x.uptime_seconds)],
          ['Agents connected', `${x.agents_connected} / ${x.agents_total}`], ['Hosts', x.hosts_total], ['TLS', x.tls_mode],
          ['Memory', bytes(x.memory_bytes)], ['Goroutines', x.goroutines], ['Data directory', <span key="d" className="mono">{x.data_dir}</span>],
          ['Disk', x.disk ? `${bytes(x.disk.used_bytes)} used of ${bytes(x.disk.total_bytes)} (${bytes(x.disk.free_bytes)} free)` : '–'],
          ['CA fingerprint', <span key="f" className="mono break-all text-xs">{x.ca_fingerprint}</span>],
        ]} />
      </Card>
      <Card title="Storage" className="h-full">
        <KV items={[
          ['SQLite', bytes(x.db_bytes)],
          ['Metrics (TSDB)', bytes(x.tsdb?.disk_bytes)], ['Series in memory', x.tsdb?.head_series], ['Blocks', x.tsdb?.blocks],
          ['Bytes per sample', x.tsdb?.bytes_per_sample?.toFixed(2)], ['Oldest data', x.tsdb?.min_time ? dateTime(x.tsdb.min_time / 1000) : '–'],
          ['Retention', `${x.retention_days} days`],
          ['Vulnerability DB', x.vulndb?.available ? `${bytes(x.vulndb.size_bytes)}, built ${dateTime(Date.parse(x.vulndb.built) / 1000)}` : 'not downloaded'],
        ]} />
      </Card>
      <Card title="Agent builds" bodyClass="p-0" className="h-full">
        <table className="w-full text-sm"><tbody>{(x.agent_binaries || []).map((b: any) => (
          <tr key={b.name} className="border-b border-line/60"><td className="px-4 py-2">{b.os}/{b.arch}</td><td className="px-4 py-2">{b.version}</td><td className="px-4 py-2 text-xs text-muted">{bytes(b.size)}</td>
            <td className="px-4 py-2 text-right"><a className="text-xs text-accent hover:underline" href={`/download/agent/${b.os}/${b.arch}`}>download</a></td></tr>
        ))}</tbody></table>
        {!x.agent_binaries?.length && <p className="p-4 text-sm text-muted">No agent binaries embedded in this build.</p>}
      </Card>
      <Card title="Backup" className="h-full" info={<>Includes the configuration database, PKI (CA, signing keys) and custom SNMP profiles. Metrics are not included; use the CLI with <code className="mono">--with-tsdb</code> for a full copy.</>}>
        <div className="space-y-3 text-sm">
          <a href="/api/v1/server/backup"><Button variant="primary" icon={<Download className="size-4" />}>Download backup</Button></a>
          <CodeBlock code={`# CLI (works while the server runs)\nsentrel-server backup --data-dir ${x.data_dir} --out backup.tar.gz\n# restore onto a stopped or new server\nsentrel-server restore --data-dir ${x.data_dir} --in backup.tar.gz`} />
          <Note tone="warn">The backup contains the CA private key and job signing key. Store it securely.{x.tls_mode === 'http' && ' This server is running without HTTPS, so download it only over a trusted network.'}</Note>
        </div>
      </Card>
    </div>
  )
}

/** Branding editor (global for provider admins, per-tenant for tenant admins). */
export function BrandingPage() {
  const { me, refresh } = useAuth()
  const toast = useToast()
  const provider = me?.user.tenant_id === 0
  const tenants = useQuery({ queryKey: ['tenants'], queryFn: () => get<Tenant[]>('/tenants'), enabled: provider })
  const [tid, setTid] = useState<number>(me?.user.tenant_id ?? 0)
  const b = useQuery({ queryKey: ['branding', tid], queryFn: () => get<Branding>('/branding', { tenant_id: tid, raw: 1 }) })
  const [v, setV] = useState<Branding | null>(null)
  useEffect(() => { if (b.data) setV(b.data) }, [b.data])
  const [err, setErr] = useState<unknown>(null)
  if (!v) return <Loading />
  const file = (k: 'logo_data_url' | 'favicon_data_url') => (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (!f) return
    if (f.size > 500_000) { toast('Image must be under 500 KB', 'crit'); return }
    const r = new FileReader()
    r.onload = () => setV({ ...v, [k]: String(r.result) })
    r.readAsDataURL(f)
  }
  return (
    <div>
      <PageHeader title="Branding" info={tid === 0 ? 'Global look: product name, logo and colours. Tenants can override any field for their portal and status pages.' : 'Overrides for this tenant; empty fields fall back to the global branding.'}
        actions={provider && (tenants.data?.length ?? 0) > 1 && <div className="w-56"><Select value={tid} onChange={(e) => setTid(Number(e.target.value))}>{tenants.data!.map((t) => <option key={t.id} value={t.id}>{t.id === 0 ? 'Global' : t.name}</option>)}</Select></div>} />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Appearance" className="h-full">
          <div className="space-y-3">
            <Field label="Product name"><Input value={v.product_name} onChange={(e) => setV({ ...v, product_name: e.target.value })} placeholder={tid ? 'inherit' : 'Sentrel'} /></Field>
            <Field label="Accent colour"><div className="flex items-center gap-2"><input type="color" value={v.accent_color || '#1f6bf5'} onChange={(e) => setV({ ...v, accent_color: e.target.value })} className="h-9 w-14 rounded border border-line bg-panel" /><Input className="w-32 mono" value={v.accent_color} onChange={(e) => setV({ ...v, accent_color: e.target.value })} /></div></Field>
            <Field label="Logo (PNG/SVG/JPEG, max 500 KB)"><div className="flex items-center gap-2"><input type="file" accept="image/*" onChange={file('logo_data_url')} className="text-sm" />{v.logo_data_url && <Button size="sm" variant="ghost" onClick={() => setV({ ...v, logo_data_url: '' })}>Remove</Button>}</div></Field>
            <Field label="Favicon"><div className="flex items-center gap-2"><input type="file" accept="image/*" onChange={file('favicon_data_url')} className="text-sm" />{v.favicon_data_url && <Button size="sm" variant="ghost" onClick={() => setV({ ...v, favicon_data_url: '' })}>Remove</Button>}</div></Field>
            <Field label="Login page text"><Textarea value={v.login_text} onChange={(e) => setV({ ...v, login_text: e.target.value })} placeholder="Authorised use only." /></Field>
            <Field label="Footer text"><Input value={v.footer_text} onChange={(e) => setV({ ...v, footer_text: e.target.value })} /></Field>
            <ErrorBox error={err} />
            <Button variant="primary" icon={<Save className="size-4" />} onClick={async () => {
              setErr(null)
              try { const eff = await put<Branding>('/branding', v, { tenant_id: tid }); toast('Branding saved'); if (tid === (me?.user.tenant_id ?? 0)) { applyBranding(eff); refresh() } } catch (e) { setErr(e) }
            }}>Save</Button>
          </div>
        </Card>
        <Card title="Preview" className="h-full">
          <div className="rounded-2xl border border-line bg-bg p-6">
            <div className="mx-auto max-w-xs rounded-2xl border border-line bg-panel p-5 text-center">
              {v.logo_data_url ? <img src={v.logo_data_url} alt="" className="mx-auto h-10 max-w-[180px] object-contain" /> : <div className="mx-auto size-10 rounded-lg" style={{ background: v.accent_color || 'var(--accent)' }} />}
              <div className="mt-2 font-semibold">{v.product_name || 'Sentrel'}</div>
              {v.login_text && <p className="mt-2 text-xs text-muted">{v.login_text}</p>}
              <div className="mt-4 rounded-md py-2 text-sm text-white" style={{ background: v.accent_color || 'var(--accent)' }}>Sign in</div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  )
}

function GroupMap({ maps, onChange, tenants, groupPlaceholder }: { maps: any[]; onChange: (m: any[]) => void; tenants?: Tenant[]; groupPlaceholder: string }) {
  const roles = (t: number) => (t === 0 ? ['admin', 'operator', 'viewer'] : ['tenant_admin', 'tenant_viewer'])
  return (
    <div className="space-y-2">
      {maps.map((m, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2">
          <Input className="min-w-40 flex-1" value={m.group} placeholder={groupPlaceholder} onChange={(e) => { const a = [...maps]; a[i] = { ...m, group: e.target.value }; onChange(a) }} />
          <Select value={m.tenant_id} onChange={(e) => { const a = [...maps]; const t = Number(e.target.value); a[i] = { ...m, tenant_id: t, role: roles(t)[0] }; onChange(a) }}>
            {tenants?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </Select>
          <Select value={m.role} onChange={(e) => { const a = [...maps]; a[i] = { ...m, role: e.target.value }; onChange(a) }}>
            {roles(m.tenant_id).map((r) => <option key={r} value={r}>{roleInfo[r].label}</option>)}
          </Select>
          <Button size="sm" variant="ghost" icon={<X className="size-3.5" />} onClick={() => onChange(maps.filter((_, j) => j !== i))} />
        </div>
      ))}
      <Button size="sm" icon={<Plus className="size-3.5" />} onClick={() => onChange([...maps, { group: '', role: 'viewer', tenant_id: 0 }])}>Add mapping</Button>
    </div>
  )
}

function DefaultRole({ v, set, tenants, none }: { v: any; set: (p: any) => void; tenants?: Tenant[]; none: string }) {
  const roles = (t: number) => (t === 0 ? ['admin', 'operator', 'viewer'] : ['tenant_admin', 'tenant_viewer'])
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label="Default role (no mapping matched)"><Select value={v.default_role} onChange={(e) => set({ default_role: e.target.value })}><option value="">{none}</option>{roles(v.default_tenant || 0).map((r) => <option key={r} value={r}>{roleInfo[r].label}</option>)}</Select></Field>
      <Field label="Default tenant"><Select value={v.default_tenant || 0} onChange={(e) => set({ default_tenant: Number(e.target.value), default_role: '' })}>{tenants?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</Select></Field>
    </div>
  )
}

function SSO({ oidc, proxy, serverUrl }: { oidc: any; proxy: any; serverUrl?: string }) {
  const O = useSection('oidc', oidc)
  const P = useSection('proxy_auth', proxy)
  const toast = useToast()
  const tenants = useQuery({ queryKey: ['tenants'], queryFn: () => get<Tenant[]>('/tenants') })
  const callback = `${(serverUrl || window.location.origin).replace(/\/$/, '')}/api/v1/auth/oidc/callback`
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="OpenID Connect" className="h-full" info="Works with Authentik, Authelia, Keycloak, Google, Microsoft Entra and other OIDC providers.">
        <div className="space-y-3">
          <Toggle checked={!!O.v.enabled} onChange={(x) => O.set({ enabled: x })} label="Enable single sign-on" />
          {!!O.v.enabled && (<>
          <Field label="Redirect URI" info="Register this exact URL with your provider. It is built from the server URL in General settings.">
            <div className="flex items-center gap-2"><Input readOnly value={callback} className="mono" /><CopyButton text={callback} /></div>
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Issuer URL" className="sm:col-span-2" hint="The address that serves /.well-known/openid-configuration"><Input value={O.v.issuer_url} onChange={(e) => O.set({ issuer_url: e.target.value })} placeholder="https://auth.example.com/application/o/sentrel" /></Field>
            <Field label="Client ID"><Input value={O.v.client_id} onChange={(e) => O.set({ client_id: e.target.value })} /></Field>
            <Field label="Client secret" hint={secretHint(O.v.client_secret_set)}><Input type="password" autoComplete="new-password" value={O.v.client_secret || ''} onChange={(e) => O.set({ client_secret: e.target.value })} /></Field>
            <Field label="Scopes"><Input value={O.v.scopes} onChange={(e) => O.set({ scopes: e.target.value })} /></Field>
            <Field label="Button label" hint="Shown as Sign in with …"><Input value={O.v.button_label} onChange={(e) => O.set({ button_label: e.target.value })} /></Field>
            <Field label="Username claim"><Input value={O.v.username_claim} onChange={(e) => O.set({ username_claim: e.target.value })} /></Field>
            <Field label="Groups claim"><Input value={O.v.groups_claim} onChange={(e) => O.set({ groups_claim: e.target.value })} /></Field>
          </div>
          <Field label="Group → role mapping" info="The most privileged matching mapping wins. Users matching none get the default role, or are refused if none.">
            <GroupMap maps={O.v.group_role_map || []} onChange={(m) => O.set({ group_role_map: m })} tenants={tenants.data} groupPlaceholder="sentrel-admins" />
          </Field>
          <DefaultRole v={O.v} set={O.set} tenants={tenants.data} none="Refuse sign-in" />
          <div className="space-y-2">
            <Toggle checked={!!O.v.allow_provision} onChange={(x) => O.set({ allow_provision: x })} label="Create accounts on first sign-in" info="Users created through OIDC cannot sign in with a password." />
            <Toggle checked={!!O.v.require_verified_email} onChange={(x) => O.set({ require_verified_email: x })} label="Require a verified email address" />
            <Toggle checked={!!O.v.trust_idp_mfa} onChange={(x) => O.set({ trust_idp_mfa: x })} label="Trust the provider's MFA" info="A sign-in whose amr claim includes mfa, otp or hwk skips the second factor here. Otherwise the normal 2FA policy applies." />
          </div>
          </>)}
        </div>
        <SaveBar busy={O.busy} err={O.err} onSave={() => O.save()} extra={!!O.v.enabled &&
          <Button onClick={async () => { try { const r = await post<any>('/settings/oidc/test'); toast(r.ok ? r.message : r.error, r.ok ? 'ok' : 'crit') } catch (e) { toast(errorMessage(e), 'crit') } }}>Test discovery (save first)</Button>
        } />
      </Card>
      <Card title="Forward-auth headers" className="h-full" info="Works with Authelia, Authentik proxy outposts, oauth2-proxy and similar.">
        <div className="space-y-3">
          <Toggle checked={!!P.v.enabled} onChange={(x) => P.set({ enabled: x })} label="Sign users in from proxy headers" />
          {!!P.v.enabled && (<>
          <Note tone="warn">Your proxy must strip these headers from client requests and set them itself, or anyone could sign in as anybody. Only trusted proxies are believed (see TLS &amp; access).</Note>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Username header"><Input value={P.v.user_header} onChange={(e) => P.set({ user_header: e.target.value })} /></Field>
            <Field label="Email header"><Input value={P.v.email_header} onChange={(e) => P.set({ email_header: e.target.value })} /></Field>
            <Field label="Name header"><Input value={P.v.name_header} onChange={(e) => P.set({ name_header: e.target.value })} /></Field>
            <Field label="Groups header" hint="Comma-separated"><Input value={P.v.groups_header} onChange={(e) => P.set({ groups_header: e.target.value })} /></Field>
          </div>
          <Field label="Group → role mapping">
            <GroupMap maps={P.v.group_role_map || []} onChange={(m) => P.set({ group_role_map: m })} tenants={tenants.data} groupPlaceholder="admins" />
          </Field>
          <DefaultRole v={P.v} set={P.set} tenants={tenants.data} none="Refuse sign-in" />
          <Toggle checked={!!P.v.allow_provision} onChange={(x) => P.set({ allow_provision: x })} label="Create accounts on first sign-in" />
          </>)}
        </div>
        <SaveBar busy={P.busy} err={P.err} onSave={() => P.save()} />
      </Card>
    </div>
  )
}
