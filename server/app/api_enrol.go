package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sentrel/internal/version"
	"sentrel/server/agentdist"
	"sentrel/server/db"
)

type tokenReq struct {
	TenantID   int64    `json:"tenant_id"`
	GroupID    *int64   `json:"group_id"`
	Tags       []string `json:"tags"`
	HostName   string   `json:"host_name"`
	TTLMinutes int      `json:"ttl_minutes"`
}

type tokenResp struct {
	ID            int64             `json:"id"`
	Token         string            `json:"token"`
	ExpiresAt     int64             `json:"expires_at"`
	ServerURL     string            `json:"server_url"`
	CAFingerprint string            `json:"ca_fingerprint,omitempty"`
	SPKISHA256    string            `json:"spki_sha256,omitempty"`
	TLSMode       string            `json:"tls_mode"`
	Commands      map[string]string `json:"commands"`
}

func formatToken(raw string) string {
	return raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12]
}

// createToken makes a one-time enrolment token.
func (a *App) createToken(ctx context.Context, p *Principal, tenant int64, group *int64, tags []string, hostName string, ttl time.Duration) (*EnrollmentToken, string, error) {
	tok := formatToken(randomCode(12))
	now := db.Now()
	res, err := a.db.ExecContext(ctx, `INSERT INTO enrollment_tokens (tenant_id, token_hash, group_id, tags, host_name, created_by, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		tenant, hashToken(normaliseToken(tok)), nullID(group), StrList(cleanTags(tags)), strings.TrimSpace(hostName), p.UserID, now+int64(ttl.Seconds()), now)
	if err != nil {
		return nil, "", err
	}
	id, _ := res.LastInsertId()
	var et EnrollmentToken
	err = a.db.GetContext(ctx, &et, `SELECT * FROM enrollment_tokens WHERE id=?`, id)
	return &et, tok, err
}

// psPinType is a compiled C# class whose Check method accepts only a server
// certificate whose SubjectPublicKeyInfo hashes to SentrelPin.Pin (base64
// SHA-256). The self-signed server certificate is ECDSA P-256, so the SPKI is
// the fixed algorithm header followed by the raw public key point.
//
// It must be compiled code, not a PowerShell script block: .NET may run the
// validation callback on a thread with no PowerShell runspace, where a script
// block cannot run. That happens when the command runs unattended (as SYSTEM
// from a scheduled task, GPO or RMM tool), so the pinned download failed there.
// deploy/windows/install-agent.ps1 defines the identical class; keep the two
// in step, because whichever runs first in a session wins.
const psPinType = `using System;using System.Net;using System.Net.Security;using System.Security.Cryptography;using System.Security.Cryptography.X509Certificates;public static class SentrelPin{public static string Pin;static readonly byte[] H={0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00};public static bool Check(object s,X509Certificate c,X509Chain ch,SslPolicyErrors e){if(c==null||Pin==null)return false;byte[] k=c.GetPublicKey();byte[] b=new byte[H.Length+k.Length];Buffer.BlockCopy(H,0,b,0,H.Length);Buffer.BlockCopy(k,0,b,H.Length,k.Length);using(var h=SHA256.Create())return Convert.ToBase64String(h.ComputeHash(b))==Pin;}public static void On(){ServicePointManager.ServerCertificateValidationCallback=Check;}public static void Off(){ServicePointManager.ServerCertificateValidationCallback=null;}}`

// psPinCallback installs the pin check for $p. The -as [type] guard lets the
// command run twice in one PowerShell session without "type already exists".
const psPinCallback = `if(-not('SentrelPin' -as [type])){Add-Type -TypeDefinition '` + psPinType + `'}; [SentrelPin]::Pin=$p; [SentrelPin]::On()`

// installCommands builds copy-paste install commands for a token. In
// self-signed mode the one-liners fetch the installer with the server
// certificate pinned (curl --pinnedpubkey; a compiled .NET validation callback)
// and pass the same pin on so the installer's own downloads are pinned too.
func (a *App) installCommands(serverURL, token string) (cmds map[string]string, caFingerprint, spki string) {
	selfSigned := strings.HasPrefix(serverURL, "https://") && a.srv.Mode() == "selfsigned"
	if selfSigned {
		caFingerprint = a.ca.Fingerprint()
		spki = a.ca.ServerSPKI()
	}
	curl := "curl -fsSL"
	shExtra, psExtra, psPre := "", "", ""
	if selfSigned {
		shExtra = " --ca-fingerprint " + caFingerprint
		psExtra = " -CaFingerprint " + caFingerprint
		if spki != "" {
			curl += fmt.Sprintf(` -k --pinnedpubkey "sha256//%s"`, spki)
			shExtra += " --pin-sha256 " + spki
			psExtra += " -PinSha256 " + spki
			psPre = fmt.Sprintf("$p='%s'; %s; ", spki, psPinCallback)
		}
	}
	cmds = map[string]string{
		"linux":   fmt.Sprintf("%s %s/install/agent.sh | sudo sh -s -- --server %s --token %s%s", curl, serverURL, serverURL, token, shExtra),
		"windows": fmt.Sprintf("%s[Net.ServicePointManager]::SecurityProtocol='Tls12'; & ([scriptblock]::Create((irm %s/install/agent.ps1))) -Server %s -Token %s%s", psPre, serverURL, serverURL, token, psExtra),
		"manual":  fmt.Sprintf("sentrel-agent register --server %s --token %s", serverURL, token),
	}
	if caFingerprint != "" {
		cmds["manual"] += " --ca-fingerprint " + caFingerprint
	}
	return cmds, caFingerprint, spki
}

func (a *App) apiCreateToken(c *Ctx) (any, error) {
	var req tokenReq
	_ = c.Decode(&req)
	tenant, err := c.tenantFor(req.TenantID)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(req.TTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if ttl > 7*24*time.Hour {
		return nil, badRequest("tokens can be valid for at most 7 days")
	}
	et, tok, err := a.createToken(c.ctx(), c.P, tenant, req.GroupID, req.Tags, req.HostName, ttl)
	if err != nil {
		return nil, err
	}
	url := a.publicURL(c.R)
	cmds, fp, spki := a.installCommands(url, tok)
	c.auditT(tenant, "enrollment_token.created", "token", itoa(et.ID), map[string]any{"ttl_minutes": int(ttl.Minutes()), "host_name": req.HostName})
	return tokenResp{ID: et.ID, Token: tok, ExpiresAt: et.ExpiresAt, ServerURL: url, CAFingerprint: fp, SPKISHA256: spki, TLSMode: a.srv.Mode(), Commands: cmds}, nil
}

func (a *App) apiListTokens(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("tenant_id")
	out := []EnrollmentToken{}
	err := a.db.SelectContext(c.ctx(), &out, `SELECT * FROM enrollment_tokens WHERE used_at=0 AND expires_at>? AND `+tw+` ORDER BY created_at DESC`, append([]any{db.Now()}, args...)...)
	return out, err
}

func (a *App) apiDeleteToken(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("tenant_id")
	res, err := a.db.ExecContext(c.ctx(), `DELETE FROM enrollment_tokens WHERE id=? AND `+tw, append([]any{c.ID()}, args...)...)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, errNotFound
	}
	c.audit("enrollment_token.deleted", "token", itoa(c.ID()), nil)
	return nil, nil
}

func (a *App) apiAgentBinaries(c *Ctx) (any, error) {
	out := agentdist.List(a.cfg.AgentBinDir)
	if out == nil {
		out = []*agentdist.Binary{}
	}
	return out, nil
}

// --- groups ---

type groupReq struct {
	TenantID    int64  `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
}

func (a *App) apiListGroups(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("g.tenant_id")
	out := []HostGroup{}
	err := a.db.SelectContext(c.ctx(), &out, `SELECT g.*, (SELECT COUNT(*) FROM hosts h WHERE h.group_id=g.id) AS host_count FROM host_groups g WHERE `+tw+` ORDER BY g.name COLLATE NOCASE`, args...)
	return out, err
}

func (a *App) apiCreateGroup(c *Ctx) (any, error) {
	var req groupReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, err := c.tenantFor(req.TenantID)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 {
		return nil, badRequest("name must be 1-64 characters")
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO host_groups (tenant_id, name, description, color, created_at) VALUES (?,?,?,?,?)`,
		tenant, name, truncateStr(req.Description, 500), req.Color, db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	c.auditT(tenant, "group.created", "group", itoa(id), map[string]any{"name": name})
	var g HostGroup
	err = a.db.GetContext(c.ctx(), &g, `SELECT *, 0 AS host_count FROM host_groups WHERE id=?`, id)
	return created{g}, err
}

func (a *App) visibleGroup(c *Ctx, id int64) (*HostGroup, error) {
	var g HostGroup
	if err := a.db.GetContext(c.ctx(), &g, `SELECT *, 0 AS host_count FROM host_groups WHERE id=?`, id); err != nil || !c.P.CanTenant(g.TenantID) {
		return nil, errNotFound
	}
	return &g, nil
}

func (a *App) apiUpdateGroup(c *Ctx) (any, error) {
	g, err := a.visibleGroup(c, c.ID())
	if err != nil {
		return nil, err
	}
	var req groupReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, badRequest("name is required")
	}
	_, err = a.db.ExecContext(c.ctx(), `UPDATE host_groups SET name=?, description=?, color=? WHERE id=?`, name, truncateStr(req.Description, 500), req.Color, g.ID)
	c.auditT(g.TenantID, "group.updated", "group", itoa(g.ID), map[string]any{"name": name})
	return nil, err
}

func (a *App) apiDeleteGroup(c *Ctx) (any, error) {
	g, err := a.visibleGroup(c, c.ID())
	if err != nil {
		return nil, err
	}
	ctx := c.ctx()
	_, _ = a.db.ExecContext(ctx, `DELETE FROM threshold_rules WHERE scope='group' AND scope_id=?`, g.ID)
	if _, err := a.db.ExecContext(ctx, `DELETE FROM host_groups WHERE id=?`, g.ID); err != nil {
		return nil, err
	}
	_ = a.alerts.ReloadRules(ctx)
	_ = a.alerts.refreshHosts(ctx)
	c.auditT(g.TenantID, "group.deleted", "group", itoa(g.ID), map[string]any{"name": g.Name})
	return nil, nil
}

func (a *App) apiListTags(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("tenant_id")
	var raw []StrList
	_ = a.db.SelectContext(c.ctx(), &raw, `SELECT tags FROM hosts WHERE `+tw, args...)
	seen := map[string]int{}
	for _, l := range raw {
		for _, t := range l {
			seen[t]++
		}
	}
	type tc struct {
		Tag   string `json:"tag"`
		Count int    `json:"count"`
	}
	out := []tc{}
	for t, n := range seen {
		out = append(out, tc{t, n})
	}
	sortBy(out, func(x tc) string { return strings.ToLower(x.Tag) })
	return out, nil
}

// --- install hub ---

type installPackage struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Format string `json:"format"`
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

type installInfo struct {
	Version       string           `json:"version"`
	ServerURL     string           `json:"server_url"`
	ServerURLSet  bool             `json:"server_url_set"`
	TLSMode       string           `json:"tls_mode"`
	CAFingerprint string           `json:"ca_fingerprint"`
	SPKISHA256    string           `json:"spki_sha256"`
	// PSPinCheck is the PowerShell that installs the certificate pin check for
	// $p (self-signed mode). The Agents page builds the Windows command from
	// it, so there is one definition of the check, here on the server.
	PSPinCheck string           `json:"ps_pin_check,omitempty"`
	Packages   []installPackage `json:"packages"`
}

// apiInstallInfo describes how to install an agent from this server: the
// public URL, how the TLS certificate can be verified, and the packages the
// server can hand out.
func (a *App) apiInstallInfo(c *Ctx) (any, error) {
	url := a.publicURL(c.R)
	mode := a.srv.Mode()
	info := installInfo{
		Version:      version.Version,
		ServerURL:    url,
		ServerURLSet: strings.TrimSpace(a.settings.General().ServerURL) != "",
		TLSMode:      mode,
		Packages:     []installPackage{},
	}
	if v := agentdist.Version(a.cfg.AgentBinDir); v != "unknown" {
		info.Version = v
	}
	if mode == "selfsigned" {
		info.CAFingerprint = a.ca.Fingerprint()
		info.SPKISHA256 = a.ca.ServerSPKI()
		info.PSPinCheck = psPinCallback
	}
	for _, p := range agentdist.Packages(a.cfg.AgentBinDir) {
		info.Packages = append(info.Packages, installPackage{OS: p.OS, Arch: p.Arch, Format: p.Format, File: p.File,
			Size: p.Size, SHA256: p.SHA256, URL: url + "/download/agent/pkg/" + p.File})
	}
	return info, nil
}
