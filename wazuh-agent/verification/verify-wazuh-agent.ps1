[CmdletBinding()]
param(
    [ValidateSet("", "Production", "Staging")]
    [string]$ExpectedEnvironment = "",
    [string]$ConfigPath = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf",
    [string]$NavigationLog = "$env:ProgramData\PhishingDetection\browser-navigation.json",
    [string]$AgentLog = "${env:ProgramFiles(x86)}\ossec-agent\ossec.log",
    [string]$ServiceName = "wazuh"
)

$ErrorActionPreference = "Stop"
$failures = New-Object Collections.Generic.List[string]
$warnings = New-Object Collections.Generic.List[string]

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service -and $ServiceName -eq "wazuh") {
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
}
if (-not $service) {
    $failures.Add("Wazuh Windows service was not found.")
} elseif ($service.Status -ne "Running") {
    $failures.Add("Wazuh service '$($service.Name)' is $($service.Status), not Running.")
} else {
    Write-Host "[PASS] Wazuh service '$($service.Name)' is running."
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    $failures.Add("Wazuh configuration not found at '$ConfigPath'.")
} else {
    $configuration = [IO.File]::ReadAllText($ConfigPath)
    if ($configuration.Contains("BEGIN PHISHING DETECTION EDGE NAVIGATION") -and
        $configuration.Contains($NavigationLog) -and
        $configuration.Contains("<log_format>json</log_format>")) {
        Write-Host "[PASS] Wazuh configuration contains the Edge JSON collection block."
    } else {
        $failures.Add("Edge JSON collection block is missing or incomplete in '$ConfigPath'.")
    }
    if ($ExpectedEnvironment) {
        $environmentMarker = "deployment_environment: $($ExpectedEnvironment.ToLowerInvariant())"
        if ($configuration.Contains($environmentMarker)) {
            Write-Host "[PASS] Deployment environment is $ExpectedEnvironment."
        } else {
            $failures.Add("Expected deployment marker '$environmentMarker' was not found.")
        }
    }
}

if (-not (Test-Path -LiteralPath $NavigationLog -PathType Leaf)) {
    $failures.Add("Navigation log not found at '$NavigationLog'.")
} else {
    $validEvents = 0
    $invalidLines = 0
    foreach ($line in (Get-Content -LiteralPath $NavigationLog -Tail 20)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $event = $line | ConvertFrom-Json -ErrorAction Stop
            if ($event.event_type -eq "browser_navigation" -and $event.url) {
                $validEvents++
            } else {
                $invalidLines++
            }
        } catch {
            $invalidLines++
        }
    }
    if ($validEvents -gt 0 -and $invalidLines -eq 0) {
        Write-Host "[PASS] The latest $validEvents navigation records are valid JSON events."
    } else {
        $failures.Add("Navigation log validation found $validEvents valid events and $invalidLines invalid lines.")
    }
}

if (-not (Test-Path -LiteralPath $AgentLog -PathType Leaf)) {
    $warnings.Add("Wazuh agent log not found at '$AgentLog'.")
} else {
    $recentAgentLog = Get-Content -LiteralPath $AgentLog -Tail 500
    $monitoring = $recentAgentLog | Select-String -SimpleMatch "browser-navigation.json"
    if ($monitoring) {
        Write-Host "[PASS] Wazuh logcollector reports browser-navigation.json in the agent log."
    } else {
        $warnings.Add("No recent logcollector entry mentions browser-navigation.json. Restart the agent and check '$AgentLog'.")
    }

    $relevantErrors = $recentAgentLog | Select-String -Pattern "(?i)(error|warning).*?(browser-navigation|PhishingDetection|logcollector)"
    if ($relevantErrors) {
        $warnings.Add("Recent agent warnings/errors may affect collection:`n$($relevantErrors -join "`n")")
    }
}

foreach ($warning in $warnings) {
    Write-Warning $warning
}
if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Write-Host "[FAIL] $failure" -ForegroundColor Red
    }
    exit 1
}

Write-Host "Wazuh agent navigation-collection checks passed."
Write-Host "Generate a new Edge navigation event, then use the Phase 3 manager checks to prove that the forwarded event reached the server."
