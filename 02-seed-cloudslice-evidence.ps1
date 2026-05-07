$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

$workRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CloudSlice'
$scriptRoot = Join-Path $workRoot 'Scripts'
$logRoot = Join-Path $workRoot 'Logs'

New-Item -ItemType Directory -Path $scriptRoot -Force | Out-Null
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

$scriptPath = Join-Path $scriptRoot '02-seed-cloudslice-evidence.ps1'
$logPath = Join-Path $logRoot '02-seed-cloudslice-evidence.log'

$scriptUrl = 'https://raw.githubusercontent.com/GregRay-skillable/41-607-CloudLab-/refs/heads/main/02-seed-cloudslice-evidence.ps1'

if (Test-Path $logPath) {
    Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Invoke-WebRequest `
        -Uri $scriptUrl `
        -OutFile $scriptPath `
        -UseBasicParsing `
        -Headers @{ 'Cache-Control' = 'no-cache' } `
        -ErrorAction Stop | Out-Null

    if (-not (Test-Path $scriptPath)) {
        throw "Missing script file after download: $scriptPath"
    }

    $scriptParams = @{
        SubscriptionId    = '@lab.CloudSubscription.Id'
        ResourceGroupName = '@lab.CloudResourceGroup(NS-RG1).Name'
        TenantId          = '@lab.CloudTenant.Id'
        AppDisplayName    = 'svc-northSouth-@lab.LabInstance.Id'
        LabInstanceId     = '@lab.LabInstance.Id'
    }

    & $scriptPath @scriptParams *> $logPath

    return $true
}
catch {
    if (Test-Path $logPath) {
        $tail = Get-Content -Path $logPath -Tail 120 -ErrorAction SilentlyContinue
        throw "$($_.Exception.Message)`n$($tail -join [Environment]::NewLine)"
    }

    throw $_.Exception.Message
}
