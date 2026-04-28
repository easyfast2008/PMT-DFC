# preflight.ps1 — Windows-native equivalent of scripts/preflight.sh.
#
# Runs the same 5-step domain-fronting feasibility battery against
# Google IPs / SNIs from a Windows machine using only PowerShell built-ins
# and Windows 10+'s bundled curl.exe. No WSL, Git Bash, or Go required.
#
# Usage (PowerShell, NOT cmd.exe):
#
#   .\preflight.ps1                     # single mode, default front
#   .\preflight.ps1 -Mode sweep         # sweep across default SNI list
#   .\preflight.ps1 -FrontIp 216.239.38.120 -Front mail.google.com
#   .\preflight.ps1 -Mode sweep -FrontIp 216.239.38.120
#
# If your PowerShell refuses to run unsigned scripts, prefix the call:
#
#   powershell.exe -ExecutionPolicy Bypass -File .\preflight.ps1 -Mode sweep
#
# Exit codes:
#   0  feasible (single: all 5 pass; sweep: at least one row passes)
#   1  network/TLS error
#   2  GFE intercepted somewhere
#   3  bad usage / missing tools

[CmdletBinding()]
param(
    [ValidateSet("single","sweep")]
    [string]$Mode = "single",
    [string]$Front = "www.google.com",
    [string]$FrontIp = "216.239.38.120",
    [int]$Port = 443,
    [int]$TimeoutSec = 10,
    [string[]]$Fronts = @(
        "www.google.com","mail.google.com","drive.google.com",
        "docs.google.com","calendar.google.com","accounts.google.com",
        "scholar.google.com","maps.google.com","chat.google.com",
        "translate.google.com","play.google.com","lens.google.com",
        "chromewebstore.google.com"
    )
)

$ErrorActionPreference = "Continue"

# Locate Windows curl.exe (NOT the PowerShell `curl` alias). Windows 10+
# ships C:\Windows\System32\curl.exe.
$curl = (Get-Command "curl.exe" -ErrorAction SilentlyContinue).Source
if (-not $curl) {
    Write-Error "curl.exe not found. On Windows 10+ it lives at C:\Windows\System32\curl.exe — re-check your PATH."
    exit 3
}

function Test-Tcp {
    param([string]$Ip, [int]$Port, [int]$TimeoutSec)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Ip, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)) { return $false }
        $client.EndConnect($iar) | Out-Null
        return $true
    } catch { return $false }
    finally { $client.Close() }
}

function Test-Tls {
    param([string]$Ip, [int]$Port, [string]$Sni, [int]$TimeoutSec)
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($Ip, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)) { return $null }
        $tcp.EndConnect($iar) | Out-Null
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
        # Strict cert validation. If your firewall MITMs, this throws.
        $ssl.AuthenticateAsClient($Sni)
        return @{
            Cn       = $ssl.RemoteCertificate.Subject
            Issuer   = $ssl.RemoteCertificate.Issuer
            Protocol = $ssl.SslProtocol
        }
    } catch { return $null }
    finally { try { $tcp.Close() } catch {} }
}

function Get-HttpStatusViaCurl {
    param([string]$Sni, [string]$HostHeader, [string]$Path, [string]$Ip, [int]$Port, [int]$TimeoutSec)
    # SNI is determined by the URL's host. Host header is sent for $HostHeader
    # via --connect-to mapping HostHeader:Port -> Sni:Port, and --resolve maps
    # Sni:Port -> Ip:Port.
    $args = @(
        "-s", "-o", "NUL", "-w", "%{http_code}",
        "--resolve", "${Sni}:${Port}:${Ip}",
        "--connect-to", "${HostHeader}:${Port}:${Sni}:${Port}",
        "--connect-timeout", "$TimeoutSec",
        "--max-time", "$TimeoutSec",
        "https://${HostHeader}${Path}"
    )
    $code = & $curl @args 2>$null
    if ($LASTEXITCODE -ne 0) { return "000" }
    return $code
}

function Test-Front  { param($Sni) (Get-HttpStatusViaCurl -Sni $Sni -HostHeader $Sni -Path "/" -Ip $FrontIp -Port $Port -TimeoutSec $TimeoutSec) -match '^[23]' }
function Test-Cross  { param($Sni) (Get-HttpStatusViaCurl -Sni $Sni -HostHeader "clients4.google.com" -Path "/generate_204" -Ip $FrontIp -Port $Port -TimeoutSec $TimeoutSec) -eq "204" }
function Test-RunApp {
    param($Sni)
    $rand = -join ((1..12) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
    $fake = "nonexistent-$rand-uc.a.run.app"
    $tmp  = New-TemporaryFile
    $args = @(
        "-s", "-D", "$tmp", "-o", "NUL", "-w", "%{http_code}",
        "--resolve", "${Sni}:${Port}:${FrontIp}",
        "--connect-to", "${fake}:${Port}:${Sni}:${Port}",
        "--connect-timeout", "$TimeoutSec",
        "--max-time", "$TimeoutSec",
        "https://${fake}/"
    )
    $code = & $curl @args 2>$null
    $hdrs = if (Test-Path $tmp) { Get-Content $tmp -Raw } else { "" }
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if ($LASTEXITCODE -ne 0) { return $false }
    # Cloud-Run-flavor 4xx: server: Google Frontend, body mentions Cloud Run.
    if ($code -match '^4' -and ($hdrs -match '(?i)Google Frontend|Frontend')) { return $true }
    if ($code -eq "200") { return $false }   # GFE served the front
    return ($code -match '^4')
}

function Run-Single {
    param([string]$Sni)
    Write-Host ("front={0}  front_ip={1}  port={2}" -f $Sni, $FrontIp, $Port) -ForegroundColor DarkGray
    Write-Host

    $pass = 0; $fail = 0
    Write-Host "[1/5] TCP/443 to $FrontIp"
    if (Test-Tcp -Ip $FrontIp -Port $Port -TimeoutSec $TimeoutSec) { Write-Host "  PASS" -ForegroundColor Green; $pass++ }
    else { Write-Host "  FAIL: TCP blocked" -ForegroundColor Red; exit 1 }

    Write-Host "[2/5] TLS handshake (SNI=$Sni)"
    $tls = Test-Tls -Ip $FrontIp -Port $Port -Sni $Sni -TimeoutSec $TimeoutSec
    if ($tls) {
        Write-Host ("  cert.cn  = {0}" -f $tls.Cn)
        Write-Host ("  cert.iss = {0}" -f $tls.Issuer)
        Write-Host ("  protocol = {0}" -f $tls.Protocol)
        Write-Host "  PASS" -ForegroundColor Green; $pass++
    } else {
        Write-Host "  FAIL: TLS handshake / cert verify failed (likely TLS MITM by firewall)" -ForegroundColor Red
        exit 2
    }

    Write-Host "[3/5] HTTPS GET https://$Sni/ (sanity)"
    if (Test-Front $Sni) { Write-Host "  PASS" -ForegroundColor Green; $pass++ }
    else { Write-Host "  FAIL" -ForegroundColor Red; $fail++ }

    Write-Host "[4/5] cross-origin: SNI=$Sni  Host=clients4.google.com /generate_204"
    if (Test-Cross $Sni) { Write-Host "  PASS" -ForegroundColor Green; $pass++ }
    else { Write-Host "  FAIL" -ForegroundColor Red; $fail++ }

    Write-Host "[5/5] run.app routing: SNI=$Sni  Host=<random>-uc.a.run.app /"
    if (Test-RunApp $Sni) { Write-Host "  PASS" -ForegroundColor Green; $pass++ }
    else { Write-Host "  FAIL" -ForegroundColor Red; $fail++ }

    Write-Host
    Write-Host "---- summary ----"
    Write-Host "pass: $pass / 5"
    Write-Host "fail: $fail / 5"
    if ($fail -eq 0) {
        Write-Host "feasible: domain-fronted Cloud Run should work on this network." -ForegroundColor Green
        exit 0
    }
    Write-Host "NOT feasible: at least one critical step failed; do not deploy." -ForegroundColor Red
    exit 2
}

function Run-Sweep {
    Write-Host ("sweep front_ip={0}  port={1}" -f $FrontIp, $Port) -ForegroundColor DarkGray
    Write-Host
    "{0,-30} {1,-3} {2,-3} {3,-5} {4,-5} {5,-6}  {6}" -f "SNI","tcp","tls","front","cross","runapp","verdict"
    "{0,-30} {1,-3} {2,-3} {3,-5} {4,-5} {5,-6}  {6}" -f "------------------------------","---","---","-----","-----","------","-------"

    $tcpOK = Test-Tcp -Ip $FrontIp -Port $Port -TimeoutSec $TimeoutSec
    $anyOK = $false
    foreach ($sni in $Fronts) {
        $r_tcp   = if ($tcpOK) { "ok" } else { "X" }
        $r_tls   = if ($tcpOK -and (Test-Tls -Ip $FrontIp -Port $Port -Sni $sni -TimeoutSec $TimeoutSec)) { "ok" } else { "X" }
        $r_front = if ($r_tls -eq "ok" -and (Test-Front $sni))  { "ok" } else { "X" }
        $r_cross = if ($r_tls -eq "ok" -and (Test-Cross $sni))  { "ok" } else { "X" }
        $r_run   = if ($r_tls -eq "ok" -and (Test-RunApp $sni)) { "ok" } else { "X" }

        $verdict =
            if ($r_tcp -eq "X" -or $r_tls -eq "X") { "BLOCKED" }
            elseif ($r_cross -eq "X" -or $r_run -eq "X") { "DO NOT USE" }
            else { $anyOK = $true; "FRONTING WORKS" }

        "{0,-30} {1,-3} {2,-3} {3,-5} {4,-5} {5,-6}  {6}" -f $sni, $r_tcp, $r_tls, $r_front, $r_cross, $r_run, $verdict
    }
    Write-Host
    if ($anyOK) {
        Write-Host "feasible: pick any FRONTING WORKS row for client.json's front_domain." -ForegroundColor Green
        exit 0
    }
    Write-Host "NOT feasible: no front passed; fronting is dead on this network/IP." -ForegroundColor Red
    exit 2
}

switch ($Mode) {
    "single" { Run-Single -Sni $Front }
    "sweep"  { Run-Sweep }
}
