#requires -Modules Az.Accounts,Az.Resources,Az.Storage,Az.KeyVault,Az.Network

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

param(
    [string]$SubscriptionId = '@lab.CloudSubscription.Id',
    [string]$ResourceGroupName = '@lab.CloudResourceGroup(RG1).Name',
    [string]$TenantId = '@lab.CloudTenant.Id',
    [string]$AppDisplayName = 'svc-cloudslice-deploy'
)

Write-Log 'Starting LCA 01: create compromised service principal.'

$lab = Initialize-LabContext -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -TenantId $TenantId
$SubscriptionId = $lab.SubscriptionId
$ResourceGroupName = $lab.ResourceGroupName
$TenantId = $lab.TenantId

$resources = Get-CloudSliceResources -ResourceGroupName $ResourceGroupName
$resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
$resourceGroupId = $resourceGroup.ResourceId

Write-Log "Resource group: $ResourceGroupName"
Write-Log "Storage account: $($resources.StorageAccountName)"
Write-Log "Key Vault: $($resources.KeyVaultName)"
Write-Log "NSG: $($resources.NsgName)"

$app = Get-AzADApplication -DisplayName $AppDisplayName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $app) {
    Write-Log "Creating app registration: $AppDisplayName"
    $app = New-AzADApplication -DisplayName $AppDisplayName -ErrorAction Stop
}
else {
    Write-Log "Reusing app registration: $AppDisplayName"
}

$appId = $app.AppId

$sp = Get-AzADServicePrincipal -ApplicationId $appId -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sp) {
    Write-Log "Creating service principal for appId: $appId"
    $sp = New-AzADServicePrincipal -ApplicationId $appId -ErrorAction Stop
}
else {
    Write-Log "Reusing service principal objectId: $($sp.Id)"
}

Write-Log 'Creating client secret.'
$credential = New-AzADAppCredential `
    -ApplicationId $appId `
    -StartDate (Get-Date) `
    -EndDate (Get-Date).AddDays(30) `
    -ErrorAction Stop

$clientSecret = $credential.SecretText
if ([string]::IsNullOrWhiteSpace($clientSecret)) {
    throw 'New-AzADAppCredential did not return SecretText.'
}

Write-Log 'Storing client secret in Key Vault.'
$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
Set-AzKeyVaultSecret `
    -VaultName $resources.KeyVaultName `
    -Name 'svc-cloudslice-deploy-client-secret' `
    -SecretValue $secureSecret `
    -ContentType 'client-secret' `
    -Tag @{
        owner = 'Cloud Slice DevOps'
        rotation = 'overdue'
        labPurpose = 'investigation-evidence'
    } `
    -ErrorAction Stop | Out-Null

$secret = Get-AzKeyVaultSecret `
    -VaultName $resources.KeyVaultName `
    -Name 'svc-cloudslice-deploy-client-secret' `
    -ErrorAction Stop

$secretUri = $secret.Id

Write-Log 'Assigning intentionally excessive Contributor access at resource group scope.'
Invoke-WithRetry -ActionName 'Assign Contributor to svc-cloudslice-deploy' -ScriptBlock {
    New-AzRoleAssignment `
        -ObjectId $sp.Id `
        -RoleDefinitionName 'Contributor' `
        -Scope $resourceGroupId `
        -ErrorAction Stop | Out-Null
} -AllowFailure

Write-Log 'Assigning Storage Blob Data Reader on the lab storage account.'
Invoke-WithRetry -ActionName 'Assign Storage Blob Data Reader to svc-cloudslice-deploy' -ScriptBlock {
    New-AzRoleAssignment `
        -ObjectId $sp.Id `
        -RoleDefinitionName 'Storage Blob Data Reader' `
        -Scope $resources.StorageAccountId `
        -ErrorAction Stop | Out-Null
} -AllowFailure

Write-Log 'Assigning Key Vault Secrets User on Key Vault.'
Invoke-WithRetry -ActionName 'Assign Key Vault Secrets User to svc-cloudslice-deploy' -ScriptBlock {
    New-AzRoleAssignment `
        -ObjectId $sp.Id `
        -RoleDefinitionName 'Key Vault Secrets User' `
        -Scope $resources.KeyVaultId `
        -ErrorAction Stop | Out-Null
} -AllowFailure

$outputPath = 'C:\CloudSlice'
if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

[ordered]@{
    TenantId = $TenantId
    SubscriptionId = $SubscriptionId
    ResourceGroupName = $ResourceGroupName
    AppDisplayName = $AppDisplayName
    ClientId = $appId
    ServicePrincipalObjectId = $sp.Id
    ClientSecret = $clientSecret
    KeyVaultName = $resources.KeyVaultName
    KeyVaultId = $resources.KeyVaultId
    SecretName = 'svc-cloudslice-deploy-client-secret'
    SecretUri = $secretUri
    StorageAccountName = $resources.StorageAccountName
    StorageAccountId = $resources.StorageAccountId
    NsgName = $resources.NsgName
    StaticWebAppName = $resources.StaticWebAppName
} | ConvertTo-Json -Depth 6 | Set-Content -Path "$outputPath\svc-cloudslice-deploy.json" -Encoding UTF8

Write-Log "LCA 01 complete. Context saved to $outputPath\svc-cloudslice-deploy.json"
