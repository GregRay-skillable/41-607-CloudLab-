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

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 8,
        [int]$DelaySeconds = 15,
        [switch]$AllowFailure,
        [string]$ActionName = 'operation'
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-Log "Running $ActionName. Attempt $attempt of $MaxAttempts."
            return & $ScriptBlock
        }
        catch {
            Write-Log "$ActionName failed on attempt $attempt. $($_.Exception.Message)" 'WARN'
            if ($attempt -lt $MaxAttempts) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    if ($AllowFailure) {
        Write-Log "$ActionName failed after $MaxAttempts attempts. Continuing." 'WARN'
        return $null
    }

    throw "$ActionName failed after $MaxAttempts attempts."
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

Write-Log 'Starting LCA 03: generate benign helpDeskSupport noise.'

$lab = Initialize-LabContext -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -TenantId $TenantId
$SubscriptionId = $lab.SubscriptionId
$ResourceGroupName = $lab.ResourceGroupName
$TenantId = $lab.TenantId

$resources = Get-CloudSliceResources -ResourceGroupName $ResourceGroupName

Write-Log "Resource group: $ResourceGroupName"
Write-Log "Storage account: $($resources.StorageAccountName)"
Write-Log "Key Vault: $($resources.KeyVaultName)"
Write-Log "NSG: $($resources.NsgName)"
if ($resources.StaticWebAppName) {
    Write-Log "Static Web App: $($resources.StaticWebAppName)"
}

$storageAccount = Get-AzStorageAccount `
    -ResourceGroupName $ResourceGroupName `
    -Name $resources.StorageAccountName `
    -ErrorAction Stop

Write-Log 'Generating benign resource read activity.'
Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop | Out-Null
Get-AzResource -ResourceGroupName $ResourceGroupName -ErrorAction Stop | Out-Null
Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $resources.StorageAccountName -ErrorAction Stop | Out-Null
Get-AzStorageContainer -Context $storageAccount.Context -ErrorAction Stop | Out-Null
Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $resources.KeyVaultName -ErrorAction Stop | Out-Null
Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $resources.NsgName -ErrorAction Stop | Out-Null

if ($resources.StaticWebAppName) {
    Get-AzResource `
        -ResourceGroupName $ResourceGroupName `
        -ResourceType 'Microsoft.Web/staticSites' `
        -Name $resources.StaticWebAppName `
        -ErrorAction SilentlyContinue | Out-Null
}

Write-Log 'Applying harmless helpDeskSupport review tags to the resource group.'

$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
$tags = @{}

if ($rg.Tags) {
    foreach ($key in $rg.Tags.Keys) {
        $tags[$key] = $rg.Tags[$key]
    }
}

$tags['LastReviewedBy'] = 'helpDeskSupport'
$tags['LastReviewedScenario'] = 'CloudSlice'
$tags['LastReviewedDate'] = (Get-Date -Format 'yyyy-MM-dd')

Set-AzResourceGroup `
    -Name $ResourceGroupName `
    -Tag $tags `
    -ErrorAction Stop | Out-Null

Write-Log 'LCA 03 complete.'
