import { describe, expect, it } from 'vitest'
import { findPackage, msiCommand, packageCommand, parseOperatorKeys, scriptCommand, urlLooksWrong, windowsCommand } from './installcmd'

import type { InstallInfo } from './types'
const base: Pick<InstallInfo, 'server_url' | 'tls_mode' | 'ca_fingerprint' | 'spki_sha256' | 'ps_pin_check'> = { server_url: 'https://mon.example', tls_mode: 'acme', ca_fingerprint: '', spki_sha256: '' }
const PIN_CHECK = "if(-not('SentrelPin' -as [type])){Add-Type -TypeDefinition 'public static class SentrelPin{}'}; [SentrelPin]::Pin=$p; [SentrelPin]::On()"
const self: typeof base = { ...base, tls_mode: 'selfsigned', ca_fingerprint: 'sha256:aa', spki_sha256: 'QUJD+/=', ps_pin_check: PIN_CHECK }
const opts = (info: typeof base, extra: Record<string, unknown> = {}) => ({ info, token: 'ABCD-1234-WXYZ', policy: 'server' as const, operatorKeys: [], docker: false, ...extra })

describe('install commands', () => {
  it('plain script for a public certificate', () => {
    expect(scriptCommand(opts(base))).toBe('curl -fsSL https://mon.example/install/agent.sh | sudo sh -s -- --server https://mon.example --token ABCD-1234-WXYZ')
  })
  it('pins the one-liner in selfsigned mode and never uses the insecure flags', () => {
    const c = scriptCommand(opts(self))
    expect(c).toContain('curl -fsSL -k --pinnedpubkey "sha256//QUJD+/="')
    expect(c).toContain('--ca-fingerprint sha256:aa --pin-sha256 QUJD+/=')
    expect(c).not.toContain('insecure')
    const w = windowsCommand(opts(self))
    // The pin check is the server's (compiled .NET), never a script block.
    expect(w.startsWith(`$p='QUJD+/='; ${PIN_CHECK}; [Net.ServicePointManager]::SecurityProtocol='Tls12'`)).toBe(true)
    expect(w).not.toContain('ServerCertificateValidationCallback={')
    expect(w).toContain('-PinSha256 QUJD+/=')
    expect(w).not.toContain('{$true}')
  })
  it('write policies and docker', () => {
    expect(scriptCommand(opts(base, { policy: 'none' }))).toContain('--write-jobs none')
    const op = scriptCommand(opts(base, { policy: 'operator', operatorKeys: ['k1', 'k2'], docker: true }))
    expect(op).toContain('--write-jobs operator --operator-key k1 --operator-key k2')
    expect(op.endsWith('--docker')).toBe(true)
  })
  it('package and msi flows', () => {
    const p = { file: 'sentrel-agent_1_amd64.deb', format: 'deb' as const }
    expect(packageCommand(opts(self), p)).toBe('sudo apt install ./sentrel-agent_1_amd64.deb && sudo sentrel-agent register --server https://mon.example --token ABCD-1234-WXYZ --ca-fingerprint sha256:aa && sudo systemctl enable --now sentrel-agent')
    expect(msiCommand(opts(base, { policy: 'operator', operatorKeys: ['k1'] }), { file: 'a.msi' })).toBe('msiexec /i a.msi SERVER=https://mon.example TOKEN=ABCD-1234-WXYZ WRITEJOBS=operator OPERATORKEY=k1 /qn')
  })
  it('rejects unsafe operator keys', () => {
    expect(parseOperatorKeys('abc= def; rm -rf /').invalid).toBe(true)
    expect(parseOperatorKeys('abc=\ndef/+').keys).toEqual(['abc=', 'def/+'])
  })
  it('finds packages and flags a wrong URL', () => {
    const pk = [{ os: 'linux', arch: 'arm64', format: 'deb', file: 'x', size: 1, sha256: 'a', url: '' }] as any
    expect(findPackage(pk, 'deb', 'arm64')?.file).toBe('x')
    expect(findPackage(pk, 'deb', 'amd64')).toBeUndefined()
    expect(urlLooksWrong('http://localhost:8080', 'mon.example')).toBe(true)
    expect(urlLooksWrong('http://localhost:8080', 'localhost')).toBe(false)
    expect(urlLooksWrong('https://mon.example', 'localhost')).toBe(false)
  })
})
