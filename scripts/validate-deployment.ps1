[CmdletBinding()]
param(
    [switch]$SkipPython,
    [switch]$SkipBicep,
    [switch]$SkipDocker
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $RepositoryRoot

function Assert-LastExitCode([string]$Step) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

try {
    if (-not $SkipPython) {
        uv sync --frozen --extra azure --extra dev
        Assert-LastExitCode 'Dependency synchronization'
        $Python = if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
            Join-Path $RepositoryRoot '.venv\Scripts\python.exe'
        } else {
            Join-Path $RepositoryRoot '.venv/bin/python'
        }
        & $Python -m ruff check src tests
        Assert-LastExitCode 'Ruff'
        & $Python -m pytest -q
        Assert-LastExitCode 'Pytest'
    }

    if (-not $SkipBicep) {
        az bicep build --file infra/main.bicep --stdout | Out-Null
        Assert-LastExitCode 'Bicep compilation'
        az bicep build-params --file infra/parameters/dev.bicepparam --stdout | Out-Null
        Assert-LastExitCode 'Bicep parameter compilation'
    }

    if (-not $SkipDocker) {
        docker build --tag malware-robustness-api:local .
        Assert-LastExitCode 'Container build'
    }

    Write-Host 'Deployment foundation validation passed.'
} finally {
    Pop-Location
}
