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

Write-Section "Generating benign support activity"

Write-Host "Reading resource group..."
Get-AzResourceGroup -Name $resources.ResourceGroupName | Out-Null

Write-Host "Listing resources..."
Get-AzResource -ResourceGroupName $resources.ResourceGroupName | Out-Null

Write-Host "Reading storage account and containers..."
Get-AzStorageAccount -ResourceGroupName $resources.ResourceGroupName -Name $resources.Storage.StorageAccountName | Out-Null
$storageContext = New-AzStorageContext -StorageAccountName $resources.Storage.StorageAccountName -UseConnectedAccount
Get-AzStorageContainer -Context $storageContext -ErrorAction SilentlyContinue | Out-Null

Write-Host "Reading Key Vault metadata..."
Get-AzKeyVault -VaultName $resources.KeyVault.VaultName | Out-Null

if ($resources.NetworkSecurityGroup) {
    Write-Host "Reading NSG..."
    Get-AzNetworkSecurityGroup -ResourceGroupName $resources.ResourceGroupName -Name $resources.NetworkSecurityGroup.Name | Out-Null
}

if ($resources.StaticSite) {
    Write-Host "Reading Static Web App resource..."
    Get-AzResource -ResourceId $resources.StaticSite.ResourceId | Out-Null
}

Write-Section "Adding harmless review tags"
$tags = @{}
if ($resources.ResourceGroup.Tags) {
    foreach ($key in $resources.ResourceGroup.Tags.Keys) {
        $tags[$key] = $resources.ResourceGroup.Tags[$key]
    }
}

$tags["LastReviewedBy"] = "helpDeskSupport"
$tags["LastReviewedScenario"] = "CloudSlice"
$tags["LastReviewedDate"] = (Get-Date).ToString("yyyy-MM-dd")

Set-AzResourceGroup -Name $resources.ResourceGroupName -Tag $tags | Out-Null

Write-Section "Complete"
Write-Host "Benign activity generated. Note: Azure Activity Log actor is the identity used to run this script."
