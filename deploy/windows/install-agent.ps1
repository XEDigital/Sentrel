<#
.SYNOPSIS
  Installs the Sentrel agent as a Windows service.

.EXAMPLE
  # From an elevated PowerShell:
  & ([scriptblock]::Create((irm https://SERVER/install/agent.ps1))) -Server https://SERVER -Token ABCD-1234

.PARAMETER Server        Sentrel server URL.
.PARAMETER Token         One-time enrolment token from "Add host".
.PARAMETER CaFingerprint Pin the server CA (self-signed TLS mode).
.PARAMETER BinaryPath    Use a local sentrel-agent.exe instead of downloading.
.PARAMETER Name          Display name for the host.
.PARAMETER WriteJobs     Who may authorise jobs that change this host: server (default), operator or none.
.PARAMETER ReadOnly      Shorthand for -WriteJobs none.
.PARAMETER OperatorKey   Operator public key(s) (from "sentrel-sign keygen-operator") for -WriteJobs operator.
.PARAMETER PinSha256     Self-signed TLS mode: accept only a server certificate whose public key (SPKI) hashes to this base64 SHA-256.
.PARAMETER InsecureDownload Removed; use -PinSha256. Kept only to print a clear error for old scripts.
.PARAMETER Uninstall     Remove the agent.
#>
param(
  [string]$Server,
  [string]$Token,
  [string]$CaFingerprint = "",
  [string]$BinaryPath = "",
  [string]$Name = "",
  [ValidateSet("", "server", "operator", "none")][string]$WriteJobs = "",
  [switch]$ReadOnly,
  [string[]]$OperatorKey = @(),
  [string]$PinSha256 = "",
  [switch]$InsecureDownload,
  [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:ProgramFiles "Sentrel Agent"
$DataDir = Join-Path $env:ProgramData "Sentrel Agent"
$Exe = Join-Path $InstallDir "sentrel-agent.exe"
$Config = Join-Path $DataDir "agent.yaml"

function Say($m) { Write-Host "==> $m" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated (Administrator) PowerShell."
}

if ($Uninstall) {
  Say "removing Sentrel agent"
  if (Test-Path $Exe) {
    & $Exe service stop --config $Config 2>$null | Out-Null
    & $Exe service uninstall --config $Config 2>$null | Out-Null
  }
  Get-NetFirewallRule -DisplayName "Sentrel block *" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force $InstallDir, $DataDir -ErrorAction SilentlyContinue
  Say "done"
  return
}

if (-not $Server -or -not $Token) { throw "-Server and -Token are required" }
$Server = $Server.TrimEnd('/')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
# Only SYSTEM and Administrators may read or write the agent state (keys, update staging).
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

if (Test-Path $Exe) {
  & $Exe service stop --config $Config 2>$null | Out-Null
  Start-Sleep -Seconds 2
}

if ($BinaryPath) {
  Copy-Item -Force $BinaryPath $Exe
} else {
  $url = "$Server/download/agent/windows/amd64"
  Say "downloading agent from $url"
  $tmp = "$Exe.download"
  if ($PinSha256) {
    # Verify the server certificate by the hash of its public key (SPKI), not
    # by a CA. The check is compiled C#, not a script block: .NET may call it
    # on a thread with no PowerShell runspace (for example when this runs
    # unattended as SYSTEM), where a script block cannot run. SentrelPin is the
    # same class the generated install command defines; keep them identical.
    if ($PSVersionTable.PSVersion.Major -ge 6) {
      # PowerShell 7: ServicePointManager does not affect HttpClient, so pin
      # through the handler. Its own copy of the check, because separately
      # compiled Add-Type classes cannot reference each other.
      if (-not ('SentrelPinHttp' -as [type])) {
        Add-Type -TypeDefinition 'using System;using System.Net.Http;using System.Security.Cryptography;using System.Security.Cryptography.X509Certificates;public static class SentrelPinHttp{static readonly byte[] H={0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00};static bool Match(X509Certificate c,string pin){if(c==null||pin==null)return false;byte[] k=c.GetPublicKey();byte[] b=new byte[H.Length+k.Length];Buffer.BlockCopy(H,0,b,0,H.Length);Buffer.BlockCopy(k,0,b,H.Length,k.Length);using(var h=SHA256.Create())return Convert.ToBase64String(h.ComputeHash(b))==pin;}public static HttpClient Client(string pin){var h=new HttpClientHandler();h.ServerCertificateCustomValidationCallback=(m,c,ch,e)=>Match(c,pin);return new HttpClient(h);}}'
      }
      $client = [SentrelPinHttp]::Client($PinSha256)
      try {
        $bytes = $client.GetByteArrayAsync($url).GetAwaiter().GetResult()
        [IO.File]::WriteAllBytes($tmp, $bytes)
      } finally { $client.Dispose() }
    } else {
      if (-not ('SentrelPin' -as [type])) {
        Add-Type -TypeDefinition 'using System;using System.Net;using System.Net.Security;using System.Security.Cryptography;using System.Security.Cryptography.X509Certificates;public static class SentrelPin{public static string Pin;static readonly byte[] H={0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00};public static bool Check(object s,X509Certificate c,X509Chain ch,SslPolicyErrors e){if(c==null||Pin==null)return false;byte[] k=c.GetPublicKey();byte[] b=new byte[H.Length+k.Length];Buffer.BlockCopy(H,0,b,0,H.Length);Buffer.BlockCopy(k,0,b,H.Length,k.Length);using(var h=SHA256.Create())return Convert.ToBase64String(h.ComputeHash(b))==Pin;}public static void On(){ServicePointManager.ServerCertificateValidationCallback=Check;}public static void Off(){ServicePointManager.ServerCertificateValidationCallback=null;}}'
      }
      [SentrelPin]::Pin = $PinSha256
      [SentrelPin]::On()
      try { (New-Object Net.WebClient).DownloadFile($url, $tmp) }
      finally { [SentrelPin]::Off() }
    }
  } elseif ($InsecureDownload) {
    throw "-InsecureDownload is no longer supported. Copy a current install command from the Agents page: in self-signed mode it pins the server certificate with -PinSha256."
  } else {
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
  }
  Move-Item -Force $tmp $Exe
}

& $Exe version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "agent binary does not run on this system" }

Say "registering with $Server"
$regArgs = @("register", "--server", $Server, "--token", $Token, "--config", $Config, "--state-dir", $DataDir)
if ($CaFingerprint) { $regArgs += @("--ca-fingerprint", $CaFingerprint) }
if ($Name) { $regArgs += @("--name", $Name) }
if ($ReadOnly) { $WriteJobs = "none" }
if ($WriteJobs) { $regArgs += @("--write-jobs", $WriteJobs) }
foreach ($k in $OperatorKey) { $regArgs += @("--operator-key", $k) }
& $Exe @regArgs
if ($LASTEXITCODE -ne 0) { throw "registration failed" }

Say "installing service"
& $Exe service uninstall --config $Config 2>$null | Out-Null
& $Exe service install --config $Config
if ($LASTEXITCODE -ne 0) { throw "service install failed" }
& $Exe service start --config $Config
# Restart on failure (used by self-update rollback).
sc.exe failure SentrelAgent reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Start-Sleep -Seconds 3
$svc = Get-Service SentrelAgent -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
  Say "Sentrel agent is running. It should appear in the web UI within a minute."
} else {
  throw "agent service did not start; see the Application event log"
}
