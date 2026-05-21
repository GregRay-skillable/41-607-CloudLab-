param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$AppDisplayName,

    [Parameter(Mandatory = $false)]
    [string]$LabInstanceId = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

function Test-IsSkillableTokenOrBlank {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($Value.Trim().StartsWith('@lab.')) { return $true }

    return $false
}

function ConvertTo-SafeName {
    param([Parameter(Mandatory = $true)][string]$Value)

    $safe = $Value.ToLowerInvariant()
    $safe = $safe -replace '[^a-z0-9-]', '-'
    $safe = $safe -replace '-+', '-'
    $safe = $safe.Trim('-')

    if ([string]::IsNullOrWhiteSpace($safe)) {
        $safe = 'cloudslice'
    }

    return $safe
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [int]$MaxAttempts = 6,

        [int]$DelaySeconds = 15,

        [string]$ActionName = 'operation'
    )

    $lastError = $null

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            $lastError = $_
            if ($attempt -lt $MaxAttempts) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    throw "$ActionName failed after $MaxAttempts attempts. $($lastError.Exception.Message)"
}

function Resolve-CloudSliceResourceGroup {
    param([string]$RequestedResourceGroupName)

    if (-not (Test-IsSkillableTokenOrBlank -Value $RequestedResourceGroupName)) {
        return [string]$RequestedResourceGroupName
    }

    $storage = Get-AzStorageAccount -ErrorAction SilentlyContinue |
        Where-Object { $_.StorageAccountName -like 'stcloudslice*' } |
        Select-Object -First 1

    if ($storage) {
        return [string]$storage.ResourceGroupName
    }

    $kv = Get-AzResource -ResourceType 'Microsoft.KeyVault/vaults' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'kv-cloudslice-*' } |
        Select-Object -First 1

    if ($kv) {
        return [string]$kv.ResourceGroupName
    }

    throw 'Could not resolve the Cloud Slice resource group.'
}

function Ensure-Container {
    param(
        [Parameter(Mandatory = $true)]$StorageContext,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $container = Get-AzStorageContainer `
        -Context $StorageContext `
        -Name $Name `
        -ErrorAction SilentlyContinue

    if (-not $container) {
        New-AzStorageContainer `
            -Context $StorageContext `
            -Name $Name `
            -Permission Off `
            -ErrorAction Stop | Out-Null
    }
}

function Set-TextBlob {
    param(
        [Parameter(Mandatory = $true)]$StorageContext,
        [Parameter(Mandatory = $true)][string]$ContainerName,
        [Parameter(Mandatory = $true)][string]$BlobName,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

    try {
        [System.IO.File]::WriteAllText($tempFile, $Content, [System.Text.UTF8Encoding]::new($false))

        Set-AzStorageBlobContent `
            -Context $StorageContext `
            -Container $ContainerName `
            -File $tempFile `
            -Blob $BlobName `
            -Force `
            -ErrorAction Stop | Out-Null
    }
    finally {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Try-Set-KeyVaultSecret {
    param(
        [Parameter(Mandatory = $true)][string]$VaultName,
        [Parameter(Mandatory = $true)][string]$SecretName,
        [Parameter(Mandatory = $true)][string]$SecretValue,
        [hashtable]$Tags = @{}
    )

    try {
        $secureValue = ConvertTo-SecureString -String $SecretValue -AsPlainText -Force

        Invoke-WithRetry `
            -ActionName "Set Key Vault secret $SecretName" `
            -MaxAttempts 5 `
            -DelaySeconds 20 `
            -ScriptBlock {
                Set-AzKeyVaultSecret `
                    -VaultName $VaultName `
                    -Name $SecretName `
                    -SecretValue $secureValue `
                    -ContentType 'training-decoy-secret' `
                    -Tag $Tags `
                    -ErrorAction Stop | Out-Null
            }

        return $true
    }
    catch {
        return $false
    }
}

try {
    if (-not (Test-IsSkillableTokenOrBlank -Value $SubscriptionId)) {
        Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    }

    $azContext = Get-AzContext -ErrorAction Stop

    if (Test-IsSkillableTokenOrBlank -Value $SubscriptionId) {
        $SubscriptionId = $azContext.Subscription.Id
    }

    if (Test-IsSkillableTokenOrBlank -Value $TenantId) {
        $TenantId = $azContext.Tenant.Id
    }

    $ResourceGroupName = Resolve-CloudSliceResourceGroup -RequestedResourceGroupName $ResourceGroupName

    $safeAppName = ConvertTo-SafeName -Value $AppDisplayName

    $storage = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
        Where-Object { $_.StorageAccountName -like 'stcloudslice*' } |
        Select-Object -First 1

    if (-not $storage) {
        throw "No storage account matching 'stcloudslice*' was found in resource group '$ResourceGroupName'."
    }

    $keyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
        Where-Object { $_.VaultName -like 'kv-cloudslice-*' } |
        Select-Object -First 1

    if (-not $keyVault) {
        throw "No Key Vault matching 'kv-cloudslice-*' was found in resource group '$ResourceGroupName'."
    }

    $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
        Where-Object { $_.Name -like 'nsg-cloudslice-web-*' } |
        Select-Object -First 1

    if (-not $nsg) {
        throw "No NSG matching 'nsg-cloudslice-web-*' was found in resource group '$ResourceGroupName'."
    }

    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'law-cloudslice-*' } |
        Select-Object -First 1

    $appInsights = Get-AzApplicationInsights -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'appi-cloudslice-*' } |
        Select-Object -First 1

    $staticSite = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Web/staticSites' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'swa-cloudslice-*' } |
        Select-Object -First 1

    $app = Get-AzADApplication -DisplayName $AppDisplayName -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $AppDisplayName } |
        Select-Object -First 1

    if (-not $app) {
        throw "App registration '$AppDisplayName' was not found. Run LCA 1 first."
    }

    $sp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $sp) {
        throw "Service principal for '$AppDisplayName' was not found. Run LCA 1 first."
    }

    $storageContext = $storage.Context

    foreach ($containerName in @('investigation-artifacts', 'business-files', 'web-content')) {
        Ensure-Container -StorageContext $storageContext -Name $containerName
    }

    $timestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $fakeSourceIp = '198.51.100.42'
    $suspiciousMgmtIp = '198.51.100.23/32'
    $fakeSecretName = "$safeAppName-client-secret"

    $summary = [ordered]@{
        LabName = 'Cloud Slice'
        GeneratedUtc = $timestampUtc
        TenantId = $TenantId
        SubscriptionId = $SubscriptionId
        ResourceGroupName = $ResourceGroupName
        AppDisplayName = $AppDisplayName
        SafeAppName = $safeAppName
        ClientId = $app.AppId
        ServicePrincipalObjectId = $sp.Id
        KeyVaultName = $keyVault.VaultName
        FakeSecretName = $fakeSecretName
        SecretIsValidCredential = $false
        StorageAccountName = $storage.StorageAccountName
        NsgName = $nsg.Name
        WorkspaceName = if ($workspace) { $workspace.Name } else { $null }
        ApplicationInsightsName = if ($appInsights) { $appInsights.Name } else { $null }
        StaticWebAppName = if ($staticSite) { $staticSite.Name } else { $null }
        Scenario = 'Identity posture investigation with simulated compromised service principal evidence.'
        ImportantNote = 'The Key Vault secret is intentionally fake and cannot be used for service principal authentication.'
    } | ConvertTo-Json -Depth 8

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'investigation-artifacts' `
        -BlobName 'setup/cloudslice-evidence-summary.json' `
        -Content $summary

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'investigation-artifacts' `
        -BlobName 'logs/deployment-run.log' `
        -Content @"
2026-05-06T13:11:42Z INFO  Starting Cloud Slice deployment workflow.
2026-05-06T13:12:08Z INFO  Deployment identity selected: $AppDisplayName
2026-05-06T13:12:11Z WARN  Client secret rotation check returned status: overdue.
2026-05-06T13:12:20Z INFO  Validated storage account: $($storage.StorageAccountName)
2026-05-06T13:12:34Z INFO  Validated Key Vault: $($keyVault.VaultName)
2026-05-06T13:13:02Z WARN  Deployment identity has Contributor scope on resource group: $ResourceGroupName
2026-05-06T13:13:44Z INFO  Deployment workflow completed.
2026-05-06T13:21:10Z WARN  Unusual source IP observed during deployment follow-up activity: $fakeSourceIp
2026-05-06T13:27:55Z WARN  Management access rule created on NSG: $($nsg.Name)
"@

    $identityEvents = @(
        [ordered]@{
            timestamp = '2026-05-06T13:22:09Z'
            category = 'IdentityProtection'
            identity = $AppDisplayName
            clientId = $app.AppId
            result = 'Failure'
            reason = 'Invalid client secret'
            sourceIp = $fakeSourceIp
            resource = $keyVault.VaultName
            severity = 'Medium'
            trainingNote = 'Simulated evidence. The stored secret is intentionally not a valid Entra credential.'
        },
        [ordered]@{
            timestamp = '2026-05-06T13:24:31Z'
            category = 'StorageAccess'
            identity = $AppDisplayName
            clientId = $app.AppId
            result = 'Success'
            reason = 'Blob enumeration observed'
            sourceIp = $fakeSourceIp
            resource = $storage.StorageAccountName
            severity = 'Medium'
            trainingNote = 'Simulated investigation artifact.'
        },
        [ordered]@{
            timestamp = '2026-05-06T13:29:04Z'
            category = 'SecretAccess'
            identity = $AppDisplayName
            clientId = $app.AppId
            result = 'Success'
            reason = 'Secret metadata read'
            sourceIp = $fakeSourceIp
            resource = $keyVault.VaultName
            severity = 'High'
            trainingNote = 'Simulated investigation artifact.'
        },
        [ordered]@{
            timestamp = '2026-05-06T13:37:44Z'
            category = 'NetworkChange'
            identity = $AppDisplayName
            clientId = $app.AppId
            result = 'Success'
            reason = 'Inbound management rule created'
            sourceIp = $fakeSourceIp
            resource = $nsg.Name
            severity = 'High'
            trainingNote = 'Backed by a real NSG rule created by this LCA.'
        }
    ) | ConvertTo-Json -Depth 8

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'investigation-artifacts' `
        -BlobName 'logs/identity-risk-events.json' `
        -Content $identityEvents

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'investigation-artifacts' `
        -BlobName 'exports/role-assignments.csv' `
        -Content @"
principalName,principalType,role,scope,risk,expected
$AppDisplayName,ServicePrincipal,Contributor,$ResourceGroupName,High,No
$AppDisplayName,ServicePrincipal,Storage Blob Data Reader,$($storage.StorageAccountName),Medium,Partially
$AppDisplayName,ServicePrincipal,Key Vault Secrets User,$($keyVault.VaultName),High,No
cloudslice-webapp,ManagedIdentity,Reader,$ResourceGroupName,Low,Yes
northsouth-admin,User,Owner,$ResourceGroupName,Medium,Yes
"@

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'investigation-artifacts' `
        -BlobName 'notes/incident-summary.txt' `
        -Content @"
Cloud Slice Incident Notes

A deployment identity named $AppDisplayName was observed with elevated access across the Cloud Slice resource group.

Known indicators:
- App registration display name: $AppDisplayName
- Client ID: $($app.AppId)
- Service principal object ID: $($sp.Id)
- Key Vault: $($keyVault.VaultName)
- Storage account: $($storage.StorageAccountName)
- Secret name: $fakeSecretName
- Suspicious source IP: $fakeSourceIp
- Suspicious NSG rule: AllowMgmtFromSuspiciousSource

Important:
The stored Key Vault secret is a fake training artifact. It is intentionally not a valid Entra application credential.

Initial concern:
The identity appears to have more access than required for deployment automation. Review role assignments, Key Vault secret exposure, storage artifacts, and network rule changes.
"@

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'investigation-artifacts' `
        -BlobName 'playbooks/investigation-guide.md' `
        -Content @"
# Cloud Slice Investigation Guide

## Investigation goals

1. Identify the risky service principal.
2. Review its role assignments.
3. Determine whether the stored secret is valid for authentication.
4. Inspect Key Vault and storage artifacts.
5. Review NSG changes for suspicious management access.
6. Recommend least-privilege remediation.

## Important finding

The secret named $fakeSecretName is a training artifact. It looks like a leaked client secret, but it is not a valid Entra application credential.

## Evidence locations

- Storage account: $($storage.StorageAccountName)
- Container: investigation-artifacts
- Key Vault: $($keyVault.VaultName)
- NSG: $($nsg.Name)
- App registration: $AppDisplayName
"@

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'business-files' `
        -BlobName 'finance/q4-cloud-spend.csv' `
        -Content @"
department,service,monthlyCost,owner
Engineering,Static Web Apps,842.21,Cloud Slice DevOps
Engineering,Storage Accounts,391.04,Cloud Slice DevOps
Security,Microsoft Defender for Cloud,612.88,Security Operations
Operations,Key Vault,39.11,Cloud Slice DevOps
Operations,Log Analytics,218.44,Security Operations
"@

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'business-files' `
        -BlobName 'ops/infra-overview.md' `
        -Content @"
# Cloud Slice Infrastructure Overview

Cloud Slice hosts a static web application, a storage account, a Key Vault, and supporting network controls.

Deployment automation uses the $AppDisplayName service principal.

The service principal was originally created for CI/CD tasks and should only have minimum required permissions.
"@

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'business-files' `
        -BlobName 'contracts/vendor-renewal-summary.txt' `
        -Content @"
Vendor Renewal Summary

The Cloud Slice project uses managed Azure services for hosting, storage, and secrets management.

Renewal owner: Cloud Slice DevOps
Review date: 2026-05-15
Status: Pending security review
"@

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'web-content' `
        -BlobName 'index.html' `
        -Content @"
<!doctype html>
<html>
<head>
  <title>Cloud Slice</title>
</head>
<body>
  <h1>Cloud Slice Portal</h1>
  <p>Internal cloud operations dashboard.</p>
  <script src="./assets/app.js"></script>
</body>
</html>
"@

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'web-content' `
        -BlobName 'assets/app.js' `
        -Content @"
const appConfigPath = '/config/appsettings.json';

async function loadConfig() {
  const response = await fetch(appConfigPath);
  return await response.json();
}

loadConfig().then(config => {
  console.log('Cloud Slice config loaded.');
});
"@

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'web-content' `
        -BlobName 'config/appsettings.json' `
        -Content @"
{
  "applicationName": "Cloud Slice Portal",
  "environment": "training",
  "keyVaultName": "$($keyVault.VaultName)",
  "deploymentIdentity": "$AppDisplayName",
  "notes": "Secrets are retrieved by deployment automation. Do not place plaintext credentials in web content."
}
"@

    $decoySecretResults = @()

    $secretMap = [ordered]@{
        'sql-admin-password' = 'P@ssw0rd-Training-Only-61572827!'
        'storage-backup-sas' = 'sv=2024-11-04&ss=b&srt=sco&sp=rl&se=2026-06-01T00:00:00Z&sig=trainingOnlyDoNotUse'
        'github-deploy-token' = 'ghp_trainingOnly_61572827_fakeTokenValue'
        'appinsights-connection-string' = 'InstrumentationKey=00000000-0000-0000-0000-000000000000;IngestionEndpoint=https://eastus-0.in.applicationinsights.azure.com/'
        'legacy-api-key' = 'legacy_training_key_61572827'
        'vpn-shared-key' = 'training-vpn-shared-key-rotate-me'
    }

    foreach ($secretName in $secretMap.Keys) {
        $created = Try-Set-KeyVaultSecret `
            -VaultName $keyVault.VaultName `
            -SecretName $secretName `
            -SecretValue $secretMap[$secretName] `
            -Tags @{
                owner = 'Cloud Slice DevOps'
                labPurpose = 'investigation-noise'
                trainingOnly = 'true'
            }

        $decoySecretResults += [ordered]@{
            secretName = $secretName
            vaultName = $keyVault.VaultName
            createdInKeyVault = $created
            trainingOnly = $true
        }
    }

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'investigation-artifacts' `
        -BlobName 'setup/decoy-secret-seeding-results.json' `
        -Content ($decoySecretResults | ConvertTo-Json -Depth 8)

    $existingRule = $nsg.SecurityRules |
        Where-Object { $_.Name -eq 'AllowMgmtFromSuspiciousSource' } |
        Select-Object -First 1

    if (-not $existingRule) {
        $nsg | Add-AzNetworkSecurityRuleConfig `
            -Name 'AllowMgmtFromSuspiciousSource' `
            -Description 'Training evidence: suspicious inbound management access from documentation IP range.' `
            -Access Allow `
            -Protocol Tcp `
            -Direction Inbound `
            -Priority 110 `
            -SourceAddressPrefix $suspiciousMgmtIp `
            -SourcePortRange '*' `
            -DestinationAddressPrefix '*' `
            -DestinationPortRange 3389 `
            -ErrorAction Stop | Out-Null

        $nsg | Set-AzNetworkSecurityGroup -ErrorAction Stop | Out-Null
    }

    $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
    $tags = @{}

    if ($rg.Tags) {
        foreach ($key in $rg.Tags.Keys) {
            $tags[$key] = $rg.Tags[$key]
        }
    }

    $tags['CloudSliceScenario'] = 'CompromisedServicePrincipal'
    $tags['InvestigationStatus'] = 'NeedsReview'
    $tags['EvidenceSeededUtc'] = $timestampUtc

    Set-AzResourceGroup -Name $ResourceGroupName -Tag $tags -ErrorAction Stop | Out-Null

    $storageTags = @{}
    if ($storage.Tags) {
        foreach ($key in $storage.Tags.Keys) {
            $storageTags[$key] = $storage.Tags[$key]
        }
    }

    $storageTags['LastAccessReview'] = 'Overdue'
    $storageTags['DataExposureRisk'] = 'Medium'

    Set-AzResource `
        -ResourceId $storage.Id `
        -Tag $storageTags `
        -Force `
        -ErrorAction Stop | Out-Null

    $kvResource = Get-AzResource -ResourceId $keyVault.ResourceId -ErrorAction Stop
    $kvTags = @{}

    if ($kvResource.Tags) {
        foreach ($key in $kvResource.Tags.Keys) {
            $kvTags[$key] = $kvResource.Tags[$key]
        }
    }

    $kvTags['SecretRotation'] = 'Overdue'
    $kvTags['PrivilegedIdentityLinked'] = $safeAppName

    Set-AzResource `
        -ResourceId $keyVault.ResourceId `
        -Tag $kvTags `
        -Force `
        -ErrorAction Stop | Out-Null

    Set-TextBlob `
        -StorageContext $storageContext `
        -ContainerName 'investigation-artifacts' `
        -BlobName 'setup/evidence-seeding-complete.txt' `
        -Content "Cloud Slice evidence seeding completed at $timestampUtc."

    exit 0
}
catch {
    throw
}
