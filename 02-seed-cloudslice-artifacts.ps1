#requires -Version 5.1
<#
Cloud Slice lab script.
Designed for Skillable Cloud Platform LCA or any PowerShell host with Az modules.
#>

[CmdletBinding()]
param(
    [string] $SubscriptionId = "",
    [string] $TenantId = "",
    [string] $ResourceGroupName = "",
    [string] $SetupClientId = "",
    [string] $SetupClientSecret = "",
    [switch] $UseManagedIdentity,
    [switch] $AllowModuleInstall
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Section {
    param([string] $Message)
    Write-Host ""
    Write-Host "==== $Message ===="
}

function Ensure-AzModule {
    param([string[]] $ModuleNames)

    foreach ($moduleName in $ModuleNames) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            if (-not $AllowModuleInstall) {
                throw "Required module '$moduleName' was not found. Re-run with -AllowModuleInstall or preinstall Az modules in the LCA host."
            }

            Write-Host "Installing module $moduleName..."
            Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        }

        Import-Module $moduleName -Force
    }
}

function Connect-CloudSliceAz {
    param(
        [string] $SubscriptionId,
        [string] $TenantId,
        [string] $ClientId,
        [string] $ClientSecret,
        [switch] $UseManagedIdentity
    )

    Write-Section "Authenticating to Azure"

    $existing = Get-AzContext -ErrorAction SilentlyContinue
    if ($existing -and [string]::IsNullOrWhiteSpace($ClientId) -and -not $UseManagedIdentity) {
        Write-Host "Using existing Az context: $($existing.Account.Id)"
    }
    elseif ($UseManagedIdentity) {
        Write-Host "Connecting with managed identity..."
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            Connect-AzAccount -Identity | Out-Null
        }
        else {
            Connect-AzAccount -Identity -Tenant $TenantId | Out-Null
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ClientId) -and -not [string]::IsNullOrWhiteSpace($ClientSecret) -and -not [string]::IsNullOrWhiteSpace($TenantId)) {
        Write-Host "Connecting with setup service principal..."
        $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
        Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $credential | Out-Null
    }
    else {
        throw "No usable authentication path found. Provide existing Az context, -UseManagedIdentity, or -TenantId/-SetupClientId/-SetupClientSecret."
    }

    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }

    $context = Get-AzContext
    if (-not $context) {
        throw "Azure authentication failed. No Az context is available."
    }

    Write-Host "Connected as: $($context.Account.Id)"
    Write-Host "Subscription: $($context.Subscription.Id)"
    Write-Host "Tenant: $($context.Tenant.Id)"

    return $context
}

function Get-CloudSliceResources {
    param([string] $ResourceGroupName)

    Write-Section "Discovering Cloud Slice resources"

    $storageAccounts = if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        Get-AzStorageAccount | Where-Object { $_.StorageAccountName -like "stcloudslice*" }
    }
    else {
        Get-AzStorageAccount -ResourceGroupName $ResourceGroupName | Where-Object { $_.StorageAccountName -like "stcloudslice*" }
    }

    $storage = $storageAccounts | Select-Object -First 1
    if (-not $storage) {
        throw "Could not find a storage account named stcloudslice*. Pass -ResourceGroupName if discovery is ambiguous."
    }

    $rgName = $storage.ResourceGroupName

    $vault = Get-AzKeyVault -ResourceGroupName $rgName | Where-Object { $_.VaultName -like "kv-cloudslice-*" } | Select-Object -First 1
    if (-not $vault) {
        throw "Could not find a Key Vault named kv-cloudslice-* in resource group '$rgName'."
    }

    $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $rgName | Where-Object { $_.Name -like "nsg-cloudslice-web-*" } | Select-Object -First 1
    if (-not $nsg) {
        Write-Warning "Could not find NSG named nsg-cloudslice-web-* in resource group '$rgName'. Attacker NSG activity will be skipped if this is script 04."
    }

    $staticSite = Get-AzResource -ResourceGroupName $rgName -ResourceType "Microsoft.Web/staticSites" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "swa-cloudslice-*" } |
        Select-Object -First 1

    $resourceGroup = Get-AzResourceGroup -Name $rgName

    Write-Host "Resource group: $rgName"
    Write-Host "Storage account: $($storage.StorageAccountName)"
    Write-Host "Key Vault: $($vault.VaultName)"
    if ($nsg) { Write-Host "NSG: $($nsg.Name)" }
    if ($staticSite) { Write-Host "Static Web App: $($staticSite.Name)" }

    return [pscustomobject]@{
        ResourceGroup = $resourceGroup
        ResourceGroupName = $rgName
        Storage = $storage
        KeyVault = $vault
        NetworkSecurityGroup = $nsg
        StaticSite = $staticSite
    }
}

function Get-CurrentPrincipalObjectId {
    $context = Get-AzContext
    $accountId = $context.Account.Id

    $sp = Get-AzADServicePrincipal -ApplicationId $accountId -ErrorAction SilentlyContinue
    if ($sp) { return $sp.Id }

    $spByDisplay = Get-AzADServicePrincipal -DisplayName $accountId -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($spByDisplay) { return $spByDisplay.Id }

    $user = Get-AzADUser -UserPrincipalName $accountId -ErrorAction SilentlyContinue
    if ($user) { return $user.Id }

    Write-Warning "Could not resolve current principal object id for '$accountId'. Some role assignments may be skipped."
    return $null
}

function Ensure-RoleAssignment {
    param(
        [Parameter(Mandatory=$true)][string] $ObjectId,
        [Parameter(Mandatory=$true)][string] $RoleDefinitionName,
        [Parameter(Mandatory=$true)][string] $Scope
    )

    $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Role already assigned: $RoleDefinitionName on $Scope"
        return
    }

    Write-Host "Assigning role: $RoleDefinitionName on $Scope"
    New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction Stop | Out-Null
}

function Get-SecretTextFromCredential {
    param([object] $Credential)

    foreach ($propertyName in @("SecretText", "SecretValue", "Value")) {
        if ($Credential.PSObject.Properties.Name -contains $propertyName) {
            $value = $Credential.$propertyName
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                return $value
            }
        }
    }

    throw "The app credential was created, but the secret text was not returned by the installed Az.Resources version."
}


Ensure-AzModule -ModuleNames @("Az.Accounts", "Az.Resources", "Az.KeyVault", "Az.Storage", "Az.Network")

$context = Connect-CloudSliceAz -SubscriptionId $SubscriptionId -TenantId $TenantId -ClientId $SetupClientId -ClientSecret $SetupClientSecret -UseManagedIdentity:$UseManagedIdentity
$resources = Get-CloudSliceResources -ResourceGroupName $ResourceGroupName

Write-Section "Finding compromised identity"
$app = Get-AzADApplication -DisplayName "svc-cloudslice-deploy" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $app) {
    throw "Could not find app registration svc-cloudslice-deploy. Run script 01 first."
}

$storageContext = New-AzStorageContext -StorageAccountName $resources.Storage.StorageAccountName -UseConnectedAccount

function Ensure-Container {
    param([string] $Name)
    $container = Get-AzStorageContainer -Context $storageContext -Name $Name -ErrorAction SilentlyContinue
    if (-not $container) {
        Write-Host "Creating container: $Name"
        New-AzStorageContainer -Context $storageContext -Name $Name -Permission Off | Out-Null
    }
    else {
        Write-Host "Container already exists: $Name"
    }
}

function Upload-TextBlob {
    param(
        [string] $Container,
        [string] $BlobName,
        [string] $Content
    )

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("CloudSliceSeed-" + [guid]::NewGuid().ToString("n"))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    try {
        $filePath = Join-Path $tempRoot ($BlobName -replace "[\\/]", "_")
        Set-Content -Path $filePath -Value $Content -Encoding UTF8
        Set-AzStorageBlobContent -Context $storageContext -Container $Container -File $filePath -Blob $BlobName -Force | Out-Null
        Write-Host "Uploaded: $Container/$BlobName"
    }
    finally {
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Section "Preparing containers"
foreach ($containerName in @("investigation-artifacts", "business-files", "web-content")) {
    Ensure-Container -Name $containerName
}

Write-Section "Uploading investigation and business artifacts"

$researcherReport = @"
Cloud Slice Researcher Report

Summary:
A public configuration sample appears to reference the deployment identity svc-cloudslice-deploy.
The identity may have broader permissions than required.

Observed indicators:
- Workload identity display name: svc-cloudslice-deploy
- Possible exposed application configuration file: appsettings.production.json
- Storage paths of interest: business-files/operations and business-files/exports
- Key Vault secret pattern: svc-cloudslice-deploy-client-secret

Recommended investigation:
1. Review Entra application and service principal activity.
2. Review role assignments scoped to the resource group, storage account, and Key Vault.
3. Review storage access patterns.
4. Review recent NSG and resource group tag changes.
"@

$leakedConfig = @"
{
  "Application": "CloudSlice.Web",
  "Environment": "Production",
  "DeploymentIdentity": "svc-cloudslice-deploy",
  "KeyVaultSecretName": "svc-cloudslice-deploy-client-secret",
  "StorageAccount": "$($resources.Storage.StorageAccountName)",
  "Warning": "Sample configuration only. Do not store production identity references in public repositories."
}
"@

$deploymentNotes = @"
Cloud Slice Operations Deployment Notes

Deployment owner: platform operations
Current deployment identity: svc-cloudslice-deploy
Storage account: $($resources.Storage.StorageAccountName)
Key Vault: $($resources.KeyVault.VaultName)

Temporary exception process:
Remote administrative access must be approved and time-bound.
Any NSG rule for remote access should be reviewed immediately.
"@

$customerQueue = @"
TicketId,Priority,Customer,Status
CS-1001,High,Northwind Research,Pending Review
CS-1002,Medium,Contoso Energy,Waiting on Operations
CS-1003,Low,Fabrikam Health,Queued
"@

$indexHtml = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Cloud Slice</title>
</head>
<body>
  <h1>Cloud Slice Research Workspace</h1>
  <p>Internal research portal for Cloud Slice operations.</p>
</body>
</html>
"@

Upload-TextBlob -Container "investigation-artifacts" -BlobName "researcher-report.txt" -Content $researcherReport
Upload-TextBlob -Container "investigation-artifacts" -BlobName "leaked-repo/appsettings.production.json" -Content $leakedConfig
Upload-TextBlob -Container "business-files" -BlobName "operations/deployment-notes.txt" -Content $deploymentNotes
Upload-TextBlob -Container "business-files" -BlobName "exports/customer-queue.csv" -Content $customerQueue
Upload-TextBlob -Container "web-content" -BlobName "index.html" -Content $indexHtml

Write-Section "Complete"
Write-Host "Cloud Slice seed artifacts were uploaded."
