[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId,

    [string]$HostExecutable = (Join-Path $PSScriptRoot "dist\navigation-host.exe")
)

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell window."
}
if (-not (Test-Path -LiteralPath $HostExecutable -PathType Leaf)) {
    throw "Native host executable not found at '$HostExecutable'. Run build-host.ps1 first."
}

$InstallDirectory = Join-Path $env:ProgramFiles "PhishingDetection"
$DataDirectory = Join-Path $env:ProgramData "PhishingDetection"
$InstalledExecutable = Join-Path $InstallDirectory "navigation-host.exe"
$ManifestPath = Join-Path $InstallDirectory "com.phishing_detection.navigation.json"
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.phishing_detection.navigation"
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
Copy-Item -LiteralPath $HostExecutable -Destination $InstalledExecutable -Force

$manifest = [ordered]@{
    name = "com.phishing_detection.navigation"
    description = "Native host for the Wazuh Edge navigation pilot"
    path = $InstalledExecutable
    type = "stdio"
    allowed_origins = @("chrome-extension://$ExtensionId/")
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ManifestPath -Encoding ASCII

New-Item -Path $RegistryPath -Force | Out-Null
Set-Item -Path $RegistryPath -Value $ManifestPath

$NavigationLog = Join-Path $DataDirectory "browser-navigation.json"
if (-not (Test-Path -LiteralPath $NavigationLog)) {
    New-Item -ItemType File -Path $NavigationLog | Out-Null
}

# The Edge user needs to append and rotate. LocalSystem (the common Wazuh
# service identity) and administrators retain full control.
& icacls.exe $DataDirectory /inheritance:r | Out-Null
& icacls.exe $DataDirectory /grant:r `
    "SYSTEM:(OI)(CI)F" `
    "BUILTIN\Administrators:(OI)(CI)F" `
    "${CurrentUser}:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to configure navigation log permissions." }

Write-Host "Native host installed for Edge extension $ExtensionId"
Write-Host "Manifest: $ManifestPath"
Write-Host "Navigation log: $NavigationLog"
Write-Host "Reload the unpacked extension or restart Microsoft Edge."
