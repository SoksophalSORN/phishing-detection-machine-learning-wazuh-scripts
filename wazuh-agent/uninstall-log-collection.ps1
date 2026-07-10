[CmdletBinding()]
param(
    [string]$ConfigPath = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf",
    [string]$ServiceName = "wazuh"
)

$ErrorActionPreference = "Stop"
$BeginMarker = "<!-- BEGIN PHISHING DETECTION EDGE NAVIGATION -->"
$EndMarker = "<!-- END PHISHING DETECTION EDGE NAVIGATION -->"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell window."
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Wazuh configuration was not found at '$ConfigPath'."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service -and $ServiceName -eq "wazuh") {
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
}
if (-not $service) {
    throw "The Wazuh Windows service was not found."
}

$configuration = [IO.File]::ReadAllText($ConfigPath)
$hasBegin = $configuration.Contains($BeginMarker)
$hasEnd = $configuration.Contains($EndMarker)
if (-not $hasBegin -and -not $hasEnd) {
    Write-Host "The Edge navigation collection block is already absent. No changes were made."
    exit 0
}
if ($hasBegin -xor $hasEnd) {
    throw "The Wazuh configuration contains an incomplete Edge navigation marker block. Restore a valid backup manually."
}

$pattern = "(?s)[ \t]*" + [Regex]::Escape($BeginMarker) + ".*?" + [Regex]::Escape($EndMarker) + "\r?\n?"
$markerRegex = New-Object Text.RegularExpressions.Regex($pattern)
$updatedConfiguration = $markerRegex.Replace($configuration, "", 1)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = "$ConfigPath.edge-navigation-remove-$timestamp.bak"
Copy-Item -LiteralPath $ConfigPath -Destination $backupPath -Force

$encoding = New-Object Text.UTF8Encoding($false)
try {
    [IO.File]::WriteAllText($ConfigPath, $updatedConfiguration, $encoding)
    Restart-Service -Name $service.Name -ErrorAction Stop
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
} catch {
    $failure = $_
    Copy-Item -LiteralPath $backupPath -Destination $ConfigPath -Force
    try { Restart-Service -Name $service.Name -ErrorAction SilentlyContinue } catch { }
    throw "Removal failed and the Wazuh configuration was restored: $($failure.Exception.Message)"
}

Write-Host "Edge navigation collection was removed from Wazuh."
Write-Host "Backup: $backupPath"
Write-Host "Browser navigation logs were preserved."
