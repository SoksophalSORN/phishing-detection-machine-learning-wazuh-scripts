[CmdletBinding()]
param(
    [switch]$RemoveLogs
)

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell window."
}

$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.phishing_detection.navigation"
$InstallDirectory = Join-Path $env:ProgramFiles "PhishingDetection"
$DataDirectory = Join-Path $env:ProgramData "PhishingDetection"

if (Test-Path -LiteralPath $RegistryPath) {
    Remove-Item -LiteralPath $RegistryPath -Recurse -Force
}
if (Test-Path -LiteralPath $InstallDirectory) {
    Remove-Item -LiteralPath $InstallDirectory -Recurse -Force
}
if ($RemoveLogs -and (Test-Path -LiteralPath $DataDirectory)) {
    Remove-Item -LiteralPath $DataDirectory -Recurse -Force
}

Write-Host "Native host registration and executable removed."
if (-not $RemoveLogs) {
    Write-Host "Pilot logs were preserved at $DataDirectory. Use -RemoveLogs to delete them."
}
