[CmdletBinding()]
param(
    [string]$Image = 'malware-robustness-api:local',
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,
    [string]$ArtifactDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ContainerName = "malware-api-smoke-$PID"
$DockerArguments = @('run', '--detach', '--rm', '--name', $ContainerName, '--publish', "${Port}:8000")
$ExpectedReadiness = 503

if ($ArtifactDirectory) {
    $ResolvedArtifacts = (Resolve-Path $ArtifactDirectory).Path
    $DockerArguments += @('--mount', "type=bind,source=$ResolvedArtifacts,target=/app/artifacts,readonly")
    $ExpectedReadiness = 200
}
$DockerArguments += $Image

try {
    $ContainerId = & docker @DockerArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to start the smoke-test container.'
    }

    $Healthy = $false
    for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
        try {
            $Health = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2
            if ($Health.status -eq 'ok') {
                $Healthy = $true
                break
            }
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $Healthy) {
        throw 'The container did not become live within 30 seconds.'
    }

    try {
        $Readiness = Invoke-WebRequest "http://127.0.0.1:$Port/ready" -TimeoutSec 5
        $ReadinessStatus = [int]$Readiness.StatusCode
    } catch {
        if (-not $_.Exception.Response) {
            throw
        }
        $ReadinessStatus = [int]$_.Exception.Response.StatusCode
    }
    if ($ReadinessStatus -ne $ExpectedReadiness) {
        throw "Expected readiness HTTP $ExpectedReadiness but received $ReadinessStatus."
    }

    Write-Host "Container liveness and readiness behavior passed ($ContainerId)."
} finally {
    & docker stop $ContainerName 2>$null | Out-Null
}
