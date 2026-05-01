# Registry Gate — Windows client setup script.
#
# Designed to be run from Intune (Windows PowerShell scripts feature) as
# SYSTEM / Administrator. Configures npm, pip, RubyGems, Composer, and Docker
# Desktop to use the proxy as the system-default registry.
#
# Usage:
#   .\setup-windows.ps1 -ProxyURL https://rg.corp.example.com
#
# CA trust and network-level enforcement are out of scope; use existing
# infrastructure (Trusted Root Certificate profile in Intune, etc.).
#
# Idempotent.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ProxyURL
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Must run as Administrator / SYSTEM.'
    exit 77
}

$Url = $ProxyURL.TrimEnd('/')

function Log([string] $msg) { Write-Host "[registry-gate] $msg" }

# npm — global npmrc at %ProgramData%; surfaced via NPM_CONFIG_GLOBALCONFIG.
$NpmRc = 'C:\ProgramData\npm\etc\npmrc'
New-Item -ItemType Directory -Force -Path (Split-Path $NpmRc) | Out-Null
Log "writing $NpmRc"
"registry=$Url" | Set-Content -Path $NpmRc -Encoding ASCII
[Environment]::SetEnvironmentVariable(
    'NPM_CONFIG_GLOBALCONFIG', $NpmRc, 'Machine')

# pip — system-wide config
$PipIni = 'C:\ProgramData\pip\pip.ini'
New-Item -ItemType Directory -Force -Path (Split-Path $PipIni) | Out-Null
Log "writing $PipIni"
@"
[global]
index-url = $Url/pypi/simple/
"@ | Set-Content -Path $PipIni -Encoding ASCII

# RubyGems — system gemrc
$GemRc = 'C:\ProgramData\gemrc'
Log "writing $GemRc"
@"
:sources:
  - $Url
"@ | Set-Content -Path $GemRc -Encoding ASCII

# Docker Desktop — per-user daemon.json (Docker Desktop is per-user on Windows)
Log 'seeding Composer repository and Docker Desktop registry mirror per user'
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
    if ($_.Name -in @('Public', 'Default', 'Default User', 'All Users')) { return }
    $composerDir = Join-Path $_.FullName 'AppData\Roaming\Composer'
    New-Item -ItemType Directory -Force -Path $composerDir | Out-Null
    @"
{
  "repositories": [
    {"type": "composer", "url": "$Url"},
    {"packagist.org": false}
  ]
}
"@ | Set-Content -Path (Join-Path $composerDir 'config.json') -Encoding ASCII

    $dockerDir = Join-Path $_.FullName '.docker'
    New-Item -ItemType Directory -Force -Path $dockerDir | Out-Null
    "{ `"registry-mirrors`": [`"$Url`"] }" |
        Set-Content -Path (Join-Path $dockerDir 'daemon.json') -Encoding ASCII
}

# Verify connectivity
Log "verifying $Url/health"
try {
    $r = Invoke-WebRequest -Uri "$Url/health" -UseBasicParsing -TimeoutSec 10
    if ($r.StatusCode -ne 200) {
        Write-Error "health check returned $($r.StatusCode)"
        exit 1
    }
} catch {
    Write-Error "proxy unreachable at $Url/health: $_"
    exit 1
}

Log 'OK'
