[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dist = Join-Path $Root "dist"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go is required to build the native host. Install Go, then rerun this script."
}

New-Item -ItemType Directory -Path $Dist -Force | Out-Null
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"

Push-Location $Root
try {
    & go test ./...
    if ($LASTEXITCODE -ne 0) { throw "Native host tests failed." }

    & go build -trimpath -ldflags "-s -w" -o (Join-Path $Dist "navigation-host.exe") .
    if ($LASTEXITCODE -ne 0) { throw "Native host build failed." }
} finally {
    Pop-Location
}

Write-Host "Built $Dist\navigation-host.exe"
