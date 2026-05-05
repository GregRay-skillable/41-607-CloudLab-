param(
    [string]$SubscriptionId = '@lab.CloudSubscription.Id',
    [string]$ResourceGroupName = '@lab.CloudResourceGroup(RG1).Name',
    [string]$TenantId = '@lab.CloudTenant.Id'
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$timestamp] [$Level] $Message"
}

function Initialize-LabContext {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$TenantId
    )

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        throw 'No Azure context found. Add Connect-AzAccount or use the Skillable authenticated LCA context before running this script.'
    }

    if ([string]::IsNullOrWhiteSpace($SubscriptionId) -or $SubscriptionId -like '@lab.*') {
        $SubscriptionId = $context.Subscription.Id
        Write-Log "SubscriptionId was blank/tokenized. Using current context subscription: $SubscriptionId"
    }

    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    $context = Get-AzContext -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($TenantId) -or $TenantId -like '@lab.*') {
        $TenantId = $context.Tenant.Id
        Write-Log "TenantId was blank/tokenized. Using current context tenant: $TenantId"
    }

    if ([string]::IsNullOrWhiteSpace($ResourceGroupName) -or $ResourceGroupName -like '@lab.*') {
        Write-Log 'ResourceGroupName was blank/tokenized. Attempting to discover the Cloud Slice resource group.'
        $candidateStorage = Get-AzStorageAccount -ErrorAction Stop |
            Where-Object { $_.StorageAccountName -like 'stcloudslice*' } |
            Select-Object -First 1

        if (-not $candidateStorage) {
            throw 'Could not discover the Cloud Slice resource group because no stcloudslice* storage account was found.'
        }

        $ResourceGroupName = $candidateStorage.ResourceGroupName
        Write-Log "Discovered resource group: $ResourceGroupName"
    }

    [pscustomobject]@{
        SubscriptionId = $SubscriptionId
        ResourceGroupName = $ResourceGroupName
        TenantId = $TenantId
    }
}

function Get-CloudSliceResources {
    param([Parameter(Mandatory = $true)][string]$ResourceGroupName)

    $storage = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
        Where-Object { $_.StorageAccountName -like 'stcloudslice*' } |
        Select-Object -First 1

    $keyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
        Where-Object { $_.VaultName -like 'kv-cloudslice-*' } |
        Select-Object -First 1

    $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
        Where-Object { $_.Name -like 'nsg-cloudslice-web-*' } |
        Select-Object -First 1

    $staticWebApp = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Web/staticSites' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'swa-cloudslice-*' } |
        Select-Object -First 1

    if (-not $storage) { throw "Cloud Slice storage account not found in resource group '$ResourceGroupName'." }
    if (-not $keyVault) { throw "Cloud Slice Key Vault not found in resource group '$ResourceGroupName'." }
    if (-not $nsg) { throw "Cloud Slice NSG not found in resource group '$ResourceGroupName'." }

    [pscustomobject]@{
        StorageAccountName = $storage.StorageAccountName
        StorageAccountId   = $storage.Id
        KeyVaultName       = $keyVault.VaultName
        KeyVaultId         = $keyVault.ResourceId
        NsgName            = $nsg.Name
        NsgId              = $nsg.Id
        StaticWebAppName   = if ($staticWebApp) { $staticWebApp.Name } else { $null }
    }
}

Write-Log 'Starting LCA 02: seed Cloud Slice artifacts.'

$lab = Initialize-LabContext -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -TenantId $TenantId
$SubscriptionId = $lab.SubscriptionId
$ResourceGroupName = $lab.ResourceGroupName
$TenantId = $lab.TenantId

$contextPath = 'C:\CloudSlice\svc-cloudslice-deploy.json'
if (-not (Test-Path $contextPath)) {
    throw "Missing $contextPath. Run 01-create-compromised-sp.ps1 first."
}

$ctx = Get-Content $contextPath -Raw | ConvertFrom-Json
$resources = Get-CloudSliceResources -ResourceGroupName $ResourceGroupName

$storageAccount = Get-AzStorageAccount `
    -ResourceGroupName $ResourceGroupName `
    -Name $resources.StorageAccountName `
    -ErrorAction Stop

$storageContext = $storageAccount.Context

$seedRoot = 'C:\CloudSlice\seed'
New-Item -ItemType Directory -Path $seedRoot -Force | Out-Null
New-Item -ItemType Directory -Path "$seedRoot\site" -Force | Out-Null
New-Item -ItemType Directory -Path "$seedRoot\repo" -Force | Out-Null
New-Item -ItemType Directory -Path "$seedRoot\business" -Force | Out-Null

@"
External Researcher Report - North South Traders

Summary:
A public repository appears to contain automation configuration for the Cloud Slice Portal. The exposed values reference an application identity named svc-cloudslice-deploy.

Observed values:
tenantId=$TenantId
clientId=$($ctx.ClientId)
keyVaultName=$($ctx.KeyVaultName)
secretName=svc-cloudslice-deploy-client-secret
observedSource=198.51.100.23/32

Initial recommendation:
Confirm whether this workload identity recently authenticated, review resource changes, rotate or delete the credential, and reduce its privileges.
"@ | Set-Content -Path "$seedRoot\researcher-report.txt" -Encoding UTF8

@"
# appsettings.production.json
# Recovered from public repository cache.

{
  "CloudSlice": {
    "TenantId": "$TenantId",
    "ClientId": "$($ctx.ClientId)",
    "KeyVaultName": "$($ctx.KeyVaultName)",
    "SecretName": "svc-cloudslice-deploy-client-secret",
    "StorageContainer": "business-files"
  }
}
"@ | Set-Content -Path "$seedRoot\repo\appsettings.production.json" -Encoding UTF8

@"
Cloud Slice deployment note

The deployment automation identity svc-cloudslice-deploy was temporarily granted broad resource group permissions during initial rollout.
This should be reduced after validation.

Known follow-up items:
- Move the workload to managed identity.
- Remove secret-based authentication.
- Review network security group changes.
- Limit storage access to required containers only.
"@ | Set-Content -Path "$seedRoot\business\deployment-notes.txt" -Encoding UTF8

@"
TicketId,Region,Status,Priority,AssignedTeam
10041,North,Open,Medium,Support
10042,South,Closed,Low,Fulfillment
10043,Central,Open,High,Cloud Operations
10044,East,Open,Medium,Support
"@ | Set-Content -Path "$seedRoot\business\customer-queue.csv" -Encoding UTF8

@'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>North South Traders | Cloud Slice Portal</title>
  <style>
    body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f6f8fb;color:#172033}
    header{background:#12213f;color:white;padding:28px 48px}
    .nav{display:flex;justify-content:space-between;align-items:center}
    .brand{font-size:22px;font-weight:700}.pill{background:#2b72ff;padding:8px 12px;border-radius:999px;font-size:13px}
    .hero{padding:56px 48px;background:linear-gradient(135deg,#12213f,#2357a6);color:white}
    .hero h1{max-width:820px;font-size:42px;line-height:1.1;margin:0 0 16px}.hero p{max-width:760px;font-size:18px;line-height:1.5}
    .cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px;padding:36px 48px}.card{background:white;border-radius:16px;padding:24px;box-shadow:0 8px 24px rgba(18,33,63,.08)}
    .card h2{font-size:20px;margin:0 0 10px}.status{display:inline-block;margin-top:14px;color:#0f7b35;background:#e8f7ed;padding:6px 10px;border-radius:999px;font-size:13px}
    .footer{padding:24px 48px;color:#5c667a;font-size:13px}@media(max-width:800px){.cards{grid-template-columns:1fr}.hero h1{font-size:32px}}
  </style>
</head>
<body>
<header><div class="nav"><div class="brand">North South Traders</div><div class="pill">Cloud Slice Portal</div></div></header>
<section class="hero"><h1>Secure access to customer operations, fulfillment metrics, and regional cloud services.</h1><p>The Cloud Slice Portal provides lightweight operational visibility for support, fulfillment, and application teams across North South Traders.</p></section>
<section class="cards">
  <article class="card"><h2>Customer Operations</h2><p>Review regional request queues, support handoffs, and application health summaries.</p><span class="status">Operational</span></article>
  <article class="card"><h2>Fulfillment Insights</h2><p>Track pipeline health, partner status, and daily processing volume.</p><span class="status">Operational</span></article>
  <article class="card"><h2>Cloud Automation</h2><p>Deployment and maintenance automation runs under approved service identities.</p><span class="status">Monitoring</span></article>
</section>
<div class="footer">Internal portal mockup for lab use. No production customer data is stored on this site.</div>
</body>
</html>
'@ | Set-Content -Path "$seedRoot\site\index.html" -Encoding UTF8

Write-Log 'Uploading investigation and business artifacts to blob storage.'

Set-AzStorageBlobContent `
    -Context $storageContext `
    -Container 'investigation-artifacts' `
    -File "$seedRoot\researcher-report.txt" `
    -Blob 'researcher-report.txt' `
    -Force `
    -ErrorAction Stop | Out-Null

Set-AzStorageBlobContent `
    -Context $storageContext `
    -Container 'investigation-artifacts' `
    -File "$seedRoot\repo\appsettings.production.json" `
    -Blob 'leaked-repo/appsettings.production.json' `
    -Force `
    -ErrorAction Stop | Out-Null

Set-AzStorageBlobContent `
    -Context $storageContext `
    -Container 'business-files' `
    -File "$seedRoot\business\deployment-notes.txt" `
    -Blob 'operations/deployment-notes.txt' `
    -Force `
    -ErrorAction Stop | Out-Null

Set-AzStorageBlobContent `
    -Context $storageContext `
    -Container 'business-files' `
    -File "$seedRoot\business\customer-queue.csv" `
    -Blob 'exports/customer-queue.csv' `
    -Force `
    -ErrorAction Stop | Out-Null

Set-AzStorageBlobContent `
    -Context $storageContext `
    -Container 'web-content' `
    -File "$seedRoot\site\index.html" `
    -Blob 'index.html' `
    -Force `
    -ErrorAction Stop | Out-Null

$desktop = [Environment]::GetFolderPath('Desktop')
if (-not [string]::IsNullOrWhiteSpace($desktop) -and (Test-Path $desktop)) {
    Copy-Item "$seedRoot\researcher-report.txt" "$desktop\Cloud Slice - Researcher Report.txt" -Force
    Write-Log "Copied starting clue to $desktop\Cloud Slice - Researcher Report.txt"
}
else {
    Write-Log 'Desktop path not found. Skipping local clue copy.' 'WARN'
}

Write-Log "Static Web App resource: $($resources.StaticWebAppName)"
Write-Log 'LCA 02 complete.'
