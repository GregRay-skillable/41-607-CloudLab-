param(
    [string]$SubscriptionId = '@lab.CloudSubscription.Id',
    [string]$ResourceGroupName = '@lab.CloudResourceGroup(NS-RG1).Name',
    [string]$TenantId = '@lab.CloudTenant.Id',
    [string]$AppDisplayName = 'svc-northSouth-@lab.LabInstance.Id',
    [string]$ArtifactContainerName = 'investigation-artifacts'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$safeAppName = $AppDisplayName.ToLower() -replace '[^a-z0-9-]', '-'
$safeAppName = $safeAppName.Trim('-')

$secretName = "$safeAppName-client-secret"
$contextFileName = "$safeAppName.json"
$contextBlobName = "setup/$contextFileName"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    [System.Console]::Out.WriteLine("[$timestamp] [$Level] $Message")
}

function Test-IsSkillableTokenOrBlank {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($Value.Trim().StartsWith('@lab.')) { return $true }
    return $false
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
        Write-Log "$ActionName failed after $MaxAttempts attempts. Continuing because AllowFailure was set." 'WARN'
        return $null
    }

    throw "$ActionName failed after $MaxAttempts attempts."
}

function Get-CloudSliceWorkRoot {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) 'CloudSlice'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    return $root
}

function Initialize-LabContext {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$TenantId
    )

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        throw 'No Azure context found. The cloud-target LCA must run in an authenticated Az PowerShell context.'
    }

    if (Test-IsSkillableTokenOrBlank -Value $SubscriptionId) {
        $SubscriptionId = $context.Subscription.Id
        Write-Log "SubscriptionId was blank/tokenized. Using current context subscription: $SubscriptionId"
    }

    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    $context = Get-AzContext -ErrorAction Stop

    if (Test-IsSkillableTokenOrBlank -Value $TenantId) {
        $TenantId = $context.Tenant.Id
        Write-Log "TenantId was blank/tokenized. Using current context tenant: $TenantId"
    }

    if (Test-IsSkillableTokenOrBlank -Value $ResourceGroupName) {
        Write-Log 'ResourceGroupName was blank/tokenized. Attempting to discover the Cloud Slice resource group.'

        $ResourceGroupName = Invoke-WithRetry `
            -ActionName 'Discover Cloud Slice resource group' `
            -MaxAttempts 12 `
            -DelaySeconds 15 `
            -ScriptBlock {
                $candidateStorage = Get-AzStorageAccount -ErrorAction SilentlyContinue |
                    Where-Object { $_.StorageAccountName -like 'stcloudslice*' } |
                    Select-Object -First 1

                if ($candidateStorage -and -not [string]::IsNullOrWhiteSpace($candidateStorage.ResourceGroupName)) {
                    return $candidateStorage.ResourceGroupName
                }

                $candidateKeyVault = Get-AzResource `
                    -ResourceType 'Microsoft.KeyVault/vaults' `
                    -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like 'kv-cloudslice-*' } |
                    Select-Object -First 1

                if ($candidateKeyVault -and -not [string]::IsNullOrWhiteSpace($candidateKeyVault.ResourceGroupName)) {
                    return $candidateKeyVault.ResourceGroupName
                }

                throw 'Could not discover the Cloud Slice resource group from storage accounts or Key Vaults.'
            }

        Write-Log "Discovered resource group: $ResourceGroupName"
    }

    [pscustomobject]@{
        SubscriptionId     = $SubscriptionId
        ResourceGroupName = $ResourceGroupName
        TenantId           = $TenantId
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

    $staticWebApp = Get-AzResource `
        -ResourceGroupName $ResourceGroupName `
        -ResourceType 'Microsoft.Web/staticSites' `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'swa-cloudslice-*' } |
        Select-Object -First 1

    if (-not $storage) { throw "Cloud Slice storage account not found in resource group '$ResourceGroupName'." }
    if (-not $keyVault) { throw "Cloud Slice Key Vault not found in resource group '$ResourceGroupName'." }
    if (-not $nsg) { throw "Cloud Slice NSG not found in resource group '$ResourceGroupName'." }

    $keyVaultId = $keyVault.ResourceId
    if ([string]::IsNullOrWhiteSpace($keyVaultId)) { $keyVaultId = $keyVault.Id }
    if ([string]::IsNullOrWhiteSpace($keyVaultId)) { throw "Could not determine resource ID for Key Vault '$($keyVault.VaultName)'." }

    [pscustomobject]@{
        StorageAccountName = $storage.StorageAccountName
        StorageAccountId   = $storage.Id
        KeyVaultName       = $keyVault.VaultName
        KeyVaultId         = $keyVaultId
        NsgName            = $nsg.Name
        NsgId              = $nsg.Id
        StaticWebAppName   = if ($staticWebApp) { $staticWebApp.Name } else { $null }
    }
}

function Resolve-CurrentAccountIdentity {
    $ctx = Get-AzContext -ErrorAction Stop
    $accountId = $ctx.Account.Id
    $accountType = "$($ctx.Account.Type)"

    $identity = [ordered]@{
        AccountId     = $accountId
        AccountType   = $accountType
        ObjectId      = $null
        SignInName    = $null
        PrincipalType = $null
    }

    Write-Log "Current setup account: $accountId"
    Write-Log "Current setup account type: $accountType"

    if ($accountType -eq 'User') {
        $identity.SignInName = $accountId
        $identity.PrincipalType = 'User'

        try {
            $user = Get-AzADUser -UserPrincipalName $accountId -ErrorAction Stop | Select-Object -First 1
            if ($user -and -not [string]::IsNullOrWhiteSpace($user.Id)) {
                $identity.ObjectId = $user.Id
                Write-Log "Resolved current user objectId: $($identity.ObjectId)"
            }
        }
        catch {
            Write-Log "Could not resolve current user objectId. Will fall back to SignInName if needed. $($_.Exception.Message)" 'WARN'
        }
    }
    elseif ($accountType -eq 'ServicePrincipal') {
        $identity.PrincipalType = 'ServicePrincipal'

        try {
            $setupSp = Get-AzADServicePrincipal -ApplicationId $accountId -ErrorAction Stop | Select-Object -First 1
            if ($setupSp -and -not [string]::IsNullOrWhiteSpace($setupSp.Id)) {
                $identity.ObjectId = $setupSp.Id
                Write-Log "Resolved current service principal objectId by ApplicationId: $($identity.ObjectId)"
            }
        }
        catch {
            Write-Log "Could not resolve current service principal by ApplicationId. Trying ObjectId. $($_.Exception.Message)" 'WARN'
        }

        if ([string]::IsNullOrWhiteSpace($identity.ObjectId)) {
            try {
                $setupSp = Get-AzADServicePrincipal -ObjectId $accountId -ErrorAction Stop | Select-Object -First 1
                if ($setupSp -and -not [string]::IsNullOrWhiteSpace($setupSp.Id)) {
                    $identity.ObjectId = $setupSp.Id
                    Write-Log "Resolved current service principal objectId directly: $($identity.ObjectId)"
                }
            }
            catch {
                Write-Log "Could not resolve current service principal by ObjectId. $($_.Exception.Message)" 'WARN'
            }
        }
    }
    else {
        Write-Log "Current account type '$accountType' is not explicitly handled. Continuing with best effort." 'WARN'
    }

    [pscustomobject]$identity
}

function Ensure-RoleAssignment {
    param(
        [string]$ObjectId,
        [string]$SignInName,
        [Parameter(Mandatory = $true)][string]$RoleDefinitionName,
        [Parameter(Mandatory = $true)][string]$Scope,
        [int]$MaxAttempts = 8,
        [int]$DelaySeconds = 15,
        [switch]$AllowFailure
    )

    if ([string]::IsNullOrWhiteSpace($ObjectId) -and [string]::IsNullOrWhiteSpace($SignInName)) {
        throw "Cannot assign role '$RoleDefinitionName' because neither ObjectId nor SignInName was supplied."
    }

    $principalDescription = if (-not [string]::IsNullOrWhiteSpace($ObjectId)) { "ObjectId $ObjectId" } else { "SignInName $SignInName" }

    Invoke-WithRetry `
        -ActionName "Ensure role '$RoleDefinitionName' for $principalDescription" `
        -MaxAttempts $MaxAttempts `
        -DelaySeconds $DelaySeconds `
        -AllowFailure:$AllowFailure `
        -ScriptBlock {
            $existing = $null

            try {
                if (-not [string]::IsNullOrWhiteSpace($ObjectId)) {
                    $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction SilentlyContinue | Select-Object -First 1
                }
                elseif (-not [string]::IsNullOrWhiteSpace($SignInName)) {
                    $existing = Get-AzRoleAssignment -SignInName $SignInName -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction SilentlyContinue | Select-Object -First 1
                }
            }
            catch {
                Write-Log "Existing role assignment lookup failed. Continuing to create assignment. $($_.Exception.Message)" 'WARN'
            }

            if ($existing) {
                Write-Log "Role assignment already exists: '$RoleDefinitionName' at '$Scope' for $principalDescription."
                return $existing
            }

            try {
                if (-not [string]::IsNullOrWhiteSpace($ObjectId)) {
                    New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction Stop | Out-Null
                }
                else {
                    New-AzRoleAssignment -SignInName $SignInName -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction Stop | Out-Null
                }

                Write-Log "Created role assignment: '$RoleDefinitionName' at '$Scope' for $principalDescription."
            }
            catch {
                if ($_.Exception.Message -match '(?i)already exists|role assignment already exists|conflict') {
                    Write-Log "Role assignment already exists after create attempt: '$RoleDefinitionName' at '$Scope' for $principalDescription."
                    return $null
                }
                throw
            }
        } | Out-Null
}

function Grant-CurrentPrincipalKeyVaultSecretAccess {
    param(
        [Parameter(Mandatory = $true)][string]$VaultName,
        [Parameter(Mandatory = $true)][string]$VaultId
    )

    $vault = Get-AzKeyVault -VaultName $VaultName -ErrorAction Stop
    $identity = Resolve-CurrentAccountIdentity

    if ($vault.EnableRbacAuthorization) {
        Write-Log "Key Vault '$VaultName' uses Azure RBAC authorization."

        if (-not [string]::IsNullOrWhiteSpace($identity.ObjectId)) {
            Ensure-RoleAssignment -ObjectId $identity.ObjectId -RoleDefinitionName 'Key Vault Secrets Officer' -Scope $VaultId -MaxAttempts 8 -DelaySeconds 20 -AllowFailure
        }
        elseif (-not [string]::IsNullOrWhiteSpace($identity.SignInName)) {
            Ensure-RoleAssignment -SignInName $identity.SignInName -RoleDefinitionName 'Key Vault Secrets Officer' -Scope $VaultId -MaxAttempts 8 -DelaySeconds 20 -AllowFailure
        }
        else {
            Write-Log 'Could not resolve current setup principal for Key Vault RBAC assignment. Continuing; secret write will verify access.' 'WARN'
        }
    }
    else {
        Write-Log "Key Vault '$VaultName' uses access policy authorization."

        Invoke-WithRetry `
            -ActionName 'Set Key Vault access policy for current setup principal' `
            -MaxAttempts 8 `
            -DelaySeconds 20 `
            -AllowFailure `
            -ScriptBlock {
                if (-not [string]::IsNullOrWhiteSpace($identity.ObjectId)) {
                    Set-AzKeyVaultAccessPolicy `
                        -VaultName $VaultName `
                        -ObjectId $identity.ObjectId `
                        -PermissionsToSecrets get,list,set,delete,recover,backup,restore `
                        -ErrorAction Stop | Out-Null

                    Write-Log "Set expanded Key Vault access policy for setup objectId: $($identity.ObjectId)"
                    return
                }

                if (-not [string]::IsNullOrWhiteSpace($identity.SignInName)) {
                    Set-AzKeyVaultAccessPolicy `
                        -VaultName $VaultName `
                        -UserPrincipalName $identity.SignInName `
                        -PermissionsToSecrets get,list,set,delete,recover,backup,restore `
                        -ErrorAction Stop | Out-Null

                    Write-Log "Set expanded Key Vault access policy for setup user: $($identity.SignInName)"
                    return
                }

                throw 'Could not resolve current setup principal for Key Vault access policy assignment.'
            } | Out-Null

        Write-Log 'Waiting 120 seconds for setup identity Key Vault access policy propagation.'
        Start-Sleep -Seconds 120
    }
}

function Get-OrCreate-CloudSliceApp {
    param([Parameter(Mandatory = $true)][string]$AppDisplayName)

    $app = Get-AzADApplication -DisplayName $AppDisplayName -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $AppDisplayName } |
        Select-Object -First 1

    if ($app) {
        Write-Log "Reusing app registration: $AppDisplayName"
        return $app
    }

    Write-Log "Creating app registration: $AppDisplayName"
    $app = New-AzADApplication -DisplayName $AppDisplayName -ErrorAction Stop

    if (-not $app -or [string]::IsNullOrWhiteSpace($app.AppId)) {
        throw "Failed to create or resolve app registration '$AppDisplayName'."
    }

    $app
}

function Get-OrCreate-CloudSliceServicePrincipal {
    param([Parameter(Mandatory = $true)][string]$AppId)

    Invoke-WithRetry `
        -ActionName "Get or create service principal for appId $AppId" `
        -MaxAttempts 8 `
        -DelaySeconds 15 `
        -ScriptBlock {
            $sp = Get-AzADServicePrincipal -ApplicationId $AppId -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sp) {
                Write-Log "Reusing service principal objectId: $($sp.Id)"
                return $sp
            }

            Write-Log "Creating service principal for appId: $AppId"
            $sp = New-AzADServicePrincipal -ApplicationId $AppId -ErrorAction Stop

            if (-not $sp -or [string]::IsNullOrWhiteSpace($sp.Id)) {
                throw "Failed to create or resolve service principal for appId '$AppId'."
            }

            $sp
        }
}

function New-CloudSliceClientSecret {
    param([Parameter(Mandatory = $true)][string]$AppId)

    Invoke-WithRetry `
        -ActionName 'Create client secret for app registration' `
        -MaxAttempts 5 `
        -DelaySeconds 10 `
        -ScriptBlock {
            $appForCredential = Get-AzADApplication -ApplicationId $AppId -ErrorAction Stop
            $credential = $appForCredential |
                New-AzADAppCredential -StartDate (Get-Date) -EndDate (Get-Date).AddDays(30) -ErrorAction Stop

            if (-not $credential -or [string]::IsNullOrWhiteSpace($credential.SecretText)) {
                throw 'New-AzADAppCredential did not return SecretText.'
            }

            $credential
        }
}

function Ensure-ArtifactContainer {
    param(
        [Parameter(Mandatory = $true)]$StorageContext,
        [Parameter(Mandatory = $true)][string]$ContainerName
    )

    $container = Get-AzStorageContainer -Name $ContainerName -Context $StorageContext -ErrorAction SilentlyContinue
    if ($container) {
        Write-Log "Storage container already exists: $ContainerName"
        return
    }

    Write-Log "Creating storage container: $ContainerName"
    New-AzStorageContainer -Name $ContainerName -Context $StorageContext -Permission Off -ErrorAction Stop | Out-Null
}

try {
    Write-Log 'Starting LCA 01: create compromised service principal.'
    Write-Log "App display name: $AppDisplayName"
    Write-Log "Safe app name: $safeAppName"
    Write-Log "Secret name: $secretName"
    Write-Log "Context artifact blob: $contextBlobName"

    $lab = Initialize-LabContext -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -TenantId $TenantId
    $SubscriptionId = $lab.SubscriptionId
    $ResourceGroupName = $lab.ResourceGroupName
    $TenantId = $lab.TenantId

    $resources = Invoke-WithRetry -ActionName 'Discover Cloud Slice resources' -MaxAttempts 12 -DelaySeconds 15 -ScriptBlock {
        Get-CloudSliceResources -ResourceGroupName $ResourceGroupName
    }

    $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
    $resourceGroupId = $resourceGroup.ResourceId

    Write-Log "Tenant ID: $TenantId"
    Write-Log "Subscription ID: $SubscriptionId"
    Write-Log "Resource group: $ResourceGroupName"
    Write-Log "Storage account: $($resources.StorageAccountName)"
    Write-Log "Key Vault: $($resources.KeyVaultName)"
    Write-Log "NSG: $($resources.NsgName)"

    $app = Get-OrCreate-CloudSliceApp -AppDisplayName $AppDisplayName
    $appId = $app.AppId
    Write-Log "App registration appId/clientId: $appId"

    $sp = Get-OrCreate-CloudSliceServicePrincipal -AppId $appId
    Write-Log "Service principal objectId: $($sp.Id)"

    Write-Log 'Creating client secret.'
    $credential = New-CloudSliceClientSecret -AppId $appId
    $clientSecret = $credential.SecretText

    if ([string]::IsNullOrWhiteSpace($clientSecret)) {
        throw 'Client secret was empty after credential creation.'
    }

    Grant-CurrentPrincipalKeyVaultSecretAccess -VaultName $resources.KeyVaultName -VaultId $resources.KeyVaultId

    Write-Log "Storing client secret in Key Vault as '$secretName'."
    $secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force

    Invoke-WithRetry `
        -ActionName "Store $AppDisplayName client secret in Key Vault" `
        -MaxAttempts 12 `
        -DelaySeconds 20 `
        -ScriptBlock {
            Set-AzKeyVaultSecret `
                -VaultName $resources.KeyVaultName `
                -Name $secretName `
                -SecretValue $secureSecret `
                -ContentType 'client-secret' `
                -Tag @{
                    owner      = 'Cloud Slice DevOps'
                    rotation   = 'overdue'
                    labPurpose = 'investigation-evidence'
                    appName    = $AppDisplayName
                } `
                -ErrorAction Stop | Out-Null
        } | Out-Null

    $secret = Get-AzKeyVaultSecret -VaultName $resources.KeyVaultName -Name $secretName -ErrorAction Stop
    $secretUri = $secret.Id

    Write-Log 'Assigning intentionally excessive Contributor access at resource group scope.'
    Ensure-RoleAssignment -ObjectId $sp.Id -RoleDefinitionName 'Contributor' -Scope $resourceGroupId -MaxAttempts 10 -DelaySeconds 20

    Write-Log 'Assigning Storage Blob Data Reader on the lab storage account.'
    Ensure-RoleAssignment -ObjectId $sp.Id -RoleDefinitionName 'Storage Blob Data Reader' -Scope $resources.StorageAccountId -MaxAttempts 10 -DelaySeconds 20

    Write-Log 'Assigning Key Vault Secrets User on Key Vault.'
    Ensure-RoleAssignment -ObjectId $sp.Id -RoleDefinitionName 'Key Vault Secrets User' -Scope $resources.KeyVaultId -MaxAttempts 10 -DelaySeconds 20

    Write-Log 'Checking Key Vault authorization mode for compromised service principal secret access.'
    $keyVaultAuthorization = Get-AzKeyVault -VaultName $resources.KeyVaultName -ErrorAction Stop

    if (-not $keyVaultAuthorization.EnableRbacAuthorization) {
        Write-Log "Key Vault '$($resources.KeyVaultName)' is using access policy mode. Granting $AppDisplayName get/list secret access with a Key Vault access policy."

        Invoke-WithRetry `
            -ActionName "Grant Key Vault access policy to $AppDisplayName" `
            -MaxAttempts 8 `
            -DelaySeconds 20 `
            -ScriptBlock {
                Set-AzKeyVaultAccessPolicy `
                    -VaultName $resources.KeyVaultName `
                    -ObjectId $sp.Id `
                    -PermissionsToSecrets get,list `
                    -ErrorAction Stop | Out-Null
            } | Out-Null

        Write-Log 'Waiting 120 seconds for compromised service principal Key Vault access policy propagation.'
        Start-Sleep -Seconds 120
    }
    else {
        Write-Log "Key Vault '$($resources.KeyVaultName)' uses Azure RBAC authorization. The Key Vault Secrets User role assignment controls secret data-plane access."
    }

    Write-Log 'Writing context artifact to the investigation-artifacts container for cloud-target continuity.'

    $workRoot = Get-CloudSliceWorkRoot
    $contextPath = Join-Path $workRoot $contextFileName

    [ordered]@{
        TenantId                 = $TenantId
        SubscriptionId           = $SubscriptionId
        ResourceGroupName        = $ResourceGroupName
        AppDisplayName           = $AppDisplayName
        SafeAppName              = $safeAppName
        ClientId                 = $appId
        ServicePrincipalObjectId = $sp.Id
        KeyVaultName             = $resources.KeyVaultName
        KeyVaultId               = $resources.KeyVaultId
        SecretName               = $secretName
        SecretUri                = $secretUri
        StorageAccountName       = $resources.StorageAccountName
        StorageAccountId         = $resources.StorageAccountId
        NsgName                  = $resources.NsgName
        StaticWebAppName         = $resources.StaticWebAppName
        ContextBlobName          = $contextBlobName
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $contextPath -Encoding UTF8

    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $resources.StorageAccountName -ErrorAction Stop
    $storageContext = $storageAccount.Context

    Invoke-WithRetry -ActionName "Ensure storage container '$ArtifactContainerName'" -MaxAttempts 8 -DelaySeconds 15 -ScriptBlock {
        Ensure-ArtifactContainer -StorageContext $storageContext -ContainerName $ArtifactContainerName
    } | Out-Null

    Invoke-WithRetry -ActionName "Upload $AppDisplayName context artifact" -MaxAttempts 8 -DelaySeconds 15 -ScriptBlock {
        Set-AzStorageBlobContent `
            -Context $storageContext `
            -Container $ArtifactContainerName `
            -File $contextPath `
            -Blob $contextBlobName `
            -Force `
            -ErrorAction Stop | Out-Null
    } | Out-Null

    Write-Log "Context artifact uploaded to $ArtifactContainerName/$contextBlobName"
    Write-Log 'LCA 01 complete.'
}
catch {
    Write-Log "LCA 01 failed. $($_.Exception.Message)" 'ERROR'
    if ($_.ScriptStackTrace) {
        Write-Log $_.ScriptStackTrace 'ERROR'
    }
    throw
}
