[CmdletBinding()]
param(
    [ValidateSet("Production", "Staging")]
    [string]$Environment = "Production",
    [string]$ConfigPath = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf",
    [string]$NavigationLog = "$env:ProgramData\PhishingDetection\browser-navigation.json",
    [string]$AgentLog = "${env:ProgramFiles(x86)}\ossec-agent\ossec.log",
    [string]$ServiceName = "wazuh"
)

$ErrorActionPreference = "Stop"
$BeginMarker = "<!-- BEGIN PHISHING DETECTION EDGE NAVIGATION -->"
$EndMarker = "<!-- END PHISHING DETECTION EDGE NAVIGATION -->"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated PowerShell window."
    }
}

function Resolve-WazuhService([string]$PreferredName) {
    $service = Get-Service -Name $PreferredName -ErrorAction SilentlyContinue
    if (-not $service -and $PreferredName -eq "wazuh") {
        $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    }
    if (-not $service) {
        throw "The Wazuh Windows service was not found. Confirm that the Wazuh agent is installed or pass -ServiceName."
    }
    return $service
}

function Write-Utf8WithoutBom([string]$Path, [string]$Content) {
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function New-ConfigurationBlock([string]$LogPath, [string]$DeploymentEnvironment) {
    return @"
  $BeginMarker
  <!-- deployment_environment: $($DeploymentEnvironment.ToLowerInvariant()) -->
  <localfile>
    <location>$LogPath</location>
    <log_format>json</log_format>
    <only-future-events>no</only-future-events>
  </localfile>
  $EndMarker
"@
}

Assert-Administrator

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Wazuh configuration was not found at '$ConfigPath'. Pass the correct path with -ConfigPath."
}
if (-not (Test-Path -LiteralPath $NavigationLog -PathType Leaf)) {
    throw "Navigation log was not found at '$NavigationLog'. Complete and verify Phase 1 first."
}

# Confirm the producer is writing one valid JSON object per line before Wazuh
# is pointed at the file.
$lastNavigation = Get-Content -LiteralPath $NavigationLog -Tail 1 -ErrorAction Stop
try {
    $parsedNavigation = $lastNavigation | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "The last navigation log line is not valid JSON: $($_.Exception.Message)"
}
if ($parsedNavigation.event_type -ne "browser_navigation" -or -not $parsedNavigation.url) {
    throw "The navigation log does not contain the expected browser_navigation event contract."
}

$service = Resolve-WazuhService $ServiceName
$ServiceName = $service.Name
$configuration = [IO.File]::ReadAllText($ConfigPath)
$hasBegin = $configuration.Contains($BeginMarker)
$hasEnd = $configuration.Contains($EndMarker)
if ($hasBegin -xor $hasEnd) {
    throw "The Wazuh configuration contains an incomplete Edge navigation marker block. Restore a valid backup before continuing."
}

$block = New-ConfigurationBlock $NavigationLog $Environment
if ($hasBegin -and $hasEnd) {
    $pattern = "(?s)[ \t]*" + [Regex]::Escape($BeginMarker) + ".*?" + [Regex]::Escape($EndMarker)
    $markerRegex = New-Object Text.RegularExpressions.Regex($pattern)
    $updatedConfiguration = $markerRegex.Replace($configuration, $block, 1)
    $action = "updated"
} else {
    $closingTag = "</ossec_config>"
    $insertAt = $configuration.LastIndexOf($closingTag, [StringComparison]::OrdinalIgnoreCase)
    if ($insertAt -lt 0) {
        throw "No closing </ossec_config> element was found in '$ConfigPath'."
    }
    $prefix = $configuration.Substring(0, $insertAt).TrimEnd([char[]]"`r`n")
    $suffix = $configuration.Substring($insertAt)
    $updatedConfiguration = $prefix + "`r`n`r`n" + $block + "`r`n" + $suffix
    $action = "added"
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = "$ConfigPath.edge-navigation-$timestamp.bak"
Copy-Item -LiteralPath $ConfigPath -Destination $backupPath -Force

try {
    Write-Utf8WithoutBom $ConfigPath $updatedConfiguration
    Restart-Service -Name $ServiceName -ErrorAction Stop

    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    $service.Refresh()
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        throw "The Wazuh service did not return to the Running state."
    }
} catch {
    $failure = $_
    Copy-Item -LiteralPath $backupPath -Destination $ConfigPath -Force
    try { Restart-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
    throw "Wazuh configuration failed and was rolled back to '$backupPath': $($failure.Exception.Message)"
}

$monitoringConfirmed = $false
if (Test-Path -LiteralPath $AgentLog -PathType Leaf) {
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $matches = Select-String -LiteralPath $AgentLog -SimpleMatch "browser-navigation.json" -ErrorAction SilentlyContinue
        if ($matches) {
            $monitoringConfirmed = $true
            break
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
}

Write-Host "Edge navigation collection block $action in $ConfigPath"
Write-Host "Backup: $backupPath"
Write-Host "Wazuh service '$ServiceName' is running."
Write-Host "Deployment environment: $Environment"
if ($monitoringConfirmed) {
    Write-Host "The agent log confirms that logcollector recognized browser-navigation.json."
} else {
    Write-Warning "No monitoring entry was found in '$AgentLog' within 30 seconds. Run verification\verify-wazuh-agent.ps1 and inspect the agent log."
}
Write-Host "Because only-future-events is 'no', existing uncollected JSONL records are eligible for collection."
