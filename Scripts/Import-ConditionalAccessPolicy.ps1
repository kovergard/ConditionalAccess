<#
.SYNOPSIS
Imports Conditional Access policies exported by EntraExporter into Entra ID using Microsoft Graph.

.DESCRIPTION
Reads Conditional Access policy JSON files exported by EntraExporter and recreates them in Entra ID. The script:
- Creates any missing security groups referenced by policies (from exported group JSON).
- Creates named locations (except builtin ones) referenced by policies.
- Maps exported IDs to the newly created/imported IDs.
- Adjusts policy properties where required (for example, authentication strength object shape and CAE report-only state).
- Skips policies that already exist or that require preview/P2 features.

The script calls Microsoft Graph (v1.0 and beta endpoints) via Invoke-MgGraphRequest and requires an active Connect-MgGraph session with the scopes listed in the script.

.PARAMETER Path
Path to the folder containing EntraExporter output. Expected subfolders under this path:
- Identity\Conditional\AccessPolicies
- Identity\Conditional\NamedLocations
- Groups

.EXAMPLE
.\Import-ConditionalAccessPolicy.ps1 -Path 'C:\temp\EntraExporter\Output'

.EXAMPLE
# Connect to Microsoft Graph first with required scopes, then run:
Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess, Group.ReadWrite.All, Application.Read.All, Policy.Read.All
.\Import-ConditionalAccessPolicy.ps1 -Path 'C:\temp\EntraExporter\Output'

.INPUTS
None. The script reads JSON files from disk and calls Microsoft Graph.

.OUTPUTS
Writes progress and warning messages to the host.

.NOTES
- Requires PowerShell 7.5.0 or newer (#requires -version 7.5.0 is present in the script).
- Requires the Microsoft.Graph PowerShell module and an active Graph connection with appropriate scopes.
- Builtin named locations such as 'All' and 'AllTrusted' are not recreated.
- Policies using preview features or requiring premium P2 may be skipped.
#>

#requires -version 7.5.0
[CmdletBinding()]
param (
    # Path to the folder with output from EntraExporter
    [Parameter(Mandatory)]
    [string]
    $Path
)

# Always stop on errors
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Define variables
$NeededScopes = "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All", "Group.ReadWrite.All"
$CaPolicyChildPath = "Identity\Conditional\AccessPolicies"
$CaLocationChildPath = "Identity\Conditional\NamedLocations"
$GroupChildPath = "Groups"
$BuiltinLocations = @('All','AllTrusted')

# Ensure that Microsoft.Graph is available
if (-not (Get-InstalledModule -Name Microsoft.Graph -ErrorAction SilentlyContinue)) {
    Write-Warning "This script uses the Microsoft.Graph module. Please make sure it is installed."
    return
}

# Ensure a Graph connection exists with the right permissions
$MgContext = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $MgContext) {
    Write-Warning "Please run Connect-MgGraph before running this script."
    return
}
$MissingScopes = Compare-Object -ReferenceObject $MgContext.Scopes -DifferenceObject $NeededScopes | Where-Object {$_.SideIndicator -eq '=>'} | Select-Object -ExpandProperty InputObject
if ($MissingScopes) {
    Write-Warning "Missing the following scopes in Graph: $($MissingScopes -join ', ')"
    return
}

# Import Conditional Access JSON files exported by EntraExporter
$CaJsonPath = Join-Path -Path $Path -ChildPath $CaPolicyChildPath -ErrorAction SilentlyContinue
$CaJsonFiles = Get-ChildItem -Path $CaJsonPath -Filter '*.json' -File -Recurse
$CaPolicies = $CaJsonFiles | ForEach-Object {
    try {
        Get-Content -Path $_.FullName | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not import JSON from file $_.FullName. "
    }
}
if ($null -eq $CaPolicies)
{
    Write-Warning "No policies could be imported from $CaJsonPath"
    return
}
$CaPolicies = $CaPolicies | Sort-Object -Property displayName
Write-Host "Found $($CaPolicies.Count) Conditional Access policies in $CaJsonPath" -ForegroundColor Green

# Get names of existing Conditional Access policies
$ExistingCaPolicyNames = @(Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' | Select-Object -ExpandProperty value | Select-Object -ExpandProperty displayName)
$ExistingCaPolicies = Compare-Object -ReferenceObject $ExistingCaPolicyNames -DifferenceObject $CaPolicies.displayName -IncludeEqual | Where-Object {$_.SideIndicator -eq '=='} | Select-Object -ExpandProperty InputObject
if ($ExistingCaPolicies) {
    Write-Host "The following Conditional Access policies already exists, and will be skipped during import:" -ForegroundColor Green
    $ExistingCaPolicies | Sort-Object | ForEach-Object {
        Write-Host " - $_"
    }
    $CaPolicies = $CaPolicies | Where-Object {$_.displayName -notin $ExistingCaPolicyNames}
}

# Ensure that all group names used in policies exists in Entra ID
Write-Host "Creating Entra ID groups used in policies." -ForegroundColor Green
$CaPolicyGroupIds = $CaPolicies | Select-Object -ExpandProperty conditions | Select-Object -ExpandProperty users | Select-Object -ExpandProperty excludeGroups
$CaPolicyGroupIds += $CaPolicies | Select-Object -ExpandProperty conditions | Select-Object -ExpandProperty users | Select-Object -ExpandProperty includeGroups
$CaPolicyGroupIds = $CaPolicyGroupIds | Select-Object -Unique
$GroupJsonPath = Join-Path -Path $Path -ChildPath $GroupChildPath -ErrorAction SilentlyContinue
$GroupIdMapping = @()
foreach ($GroupId in $CaPolicyGroupIds)
{
    try {
        $GroupExportPath = Join-Path -Path $GroupJsonPath -ChildPath $GroupId -AdditionalChildPath "$GroupId.json"
        $GroupExport = Get-Content $GroupExportPath | ConvertFrom-Json
        $GroupDisplayName = $GroupExport.displayName
    }
    catch {
        $GroupDisplayName = $null
        Write-Warning "Group with ID $GroupId not found in $GroupExportPath. Skipping group creation."
        Continue
    }

    $FilterName = $GroupDisplayName.replace('&','%26')
    $ImportId = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$FilterName'" | Select-Object -ExpandProperty value | Select-Object -ExpandProperty id
    if ($null -eq $ImportId) {
        $NewGroupJson = [PSCustomObject]@{
            displayName     = $GroupDisplayName
            mailNickname    = (New-Guid).Guid
            mailEnabled     = $false
            securityEnabled = $true
        } | ConvertTo-Json

        try {
            $CreateGroupRequest = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/groups" -Body $NewGroupJson
            $ImportId = $CreateGroupRequest.id
            Write-Host " - $GroupDisplayName"
        }
        catch {
            Write-Warning "Could not create Entra ID group '$GroupDisplayName'. $_"
            $ImportId = $null
        }
    }

    $GroupIdMapping += [PSCustomObject]@{
        ExportId    = $GroupId
        ImportId    = $ImportId
        DisplayName = $GroupDisplayName
    }
}

# Ensure that all named locations used in policies exists in Entra ID
Write-Host "Creating named locations used in policies." -ForegroundColor Green
$CaPolicyLocationIds = $CaPolicies | Select-Object -ExpandProperty conditions | Select-Object -ExpandProperty locations | Select-Object -ExpandProperty includeLocations
$CaPolicyLocationIds += $CaPolicies | Select-Object -ExpandProperty conditions | Select-Object -ExpandProperty locations | Select-Object -ExpandProperty excludeLocations
$CaPolicyLocationIds = $CaPolicyLocationIds | Select-Object -Unique
$LocationJsonPath = Join-Path -Path $Path -ChildPath $CaLocationChildPath -ErrorAction SilentlyContinue
$LocationIdMapping = @()
foreach ($LocationId in $CaPolicyLocationIds)
{
    if ($LocationId -in $BuiltinLocations) {
        $ExportId = $LocationId
        $ImportId = $LocationId
        $LocationDisplayName = $LocationId
    }
    else {
        try {
            $LocationExportPath = Join-Path -Path $LocationJsonPath -ChildPath $LocationId -AdditionalChildPath "$LocationId.json"
            $LocationExport = Get-Content $LocationExportPath | ConvertFrom-Json
            $LocationDisplayName = $LocationExport.displayName
        }
        catch {
            $LocationExport = $null
            Write-Warning "Location with ID $LocationId not found in $LocationExportPath. Skipping location creation."
            Continue
        }

        $FilterName = $LocationDisplayName.replace('&','%26')
        $ImportId = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?`$filter=displayName eq '$FilterName'" | Select-Object -ExpandProperty value | Select-Object -ExpandProperty id
        if ($null -eq $ImportId) {
            $NewLocationJson = [PSCustomObject]@{
                '@odata.type'                     = $LocationExport.'@odata.type'
                displayName                       = $LocationDisplayName
                countriesAndRegions               = $LocationExport.countriesAndRegions
                includeUnknownCountriesAndRegions = $LocationExport.includeUnknownCountriesAndRegions
                countryLookupMethod               = $LocationExport.countryLookupMethod
            } | ConvertTo-Json

            try {
                $CreateLocationRequest = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -Body $NewLocationJson
                $ImportId = $CreateLocationRequest.id
                Write-Host " - $LocationDisplayName"
            }
            catch {
                Write-Warning "Could not create location '$LocationDisplayName'. $_"
                $ImportId = $null
            }
        }
    }

    $LocationIdMapping += [PSCustomObject]@{
        ExportId    = $LocationId
        ImportId    = $ImportId
        DisplayName = $LocationDisplayName
    }
}

# Create Conditional Access policies
Write-Host "Creating Conditional Access policies in Entra ID." -ForegroundColor Green
foreach ($CaPolicy in $CaPolicies) {
    $Conditions = $CaPolicy.conditions

    # Map group IDs
    $IncludeGroups = @($Conditions.users.includeGroups | ForEach-Object {
        $ExportId = $_
        $GroupIdMapping | Where-Object {$_.ExportId -eq $ExportId} | Select-Object -ExpandProperty ImportId
    })
    $Conditions.users.includeGroups = $IncludeGroups

    $ExcludeGroups = @($Conditions.users.excludeGroups | ForEach-Object {
        $ExportId = $_
        $GroupIdMapping | Where-Object {$_.ExportId -eq $ExportId} | Select-Object -ExpandProperty ImportId
    })
    $Conditions.users.excludeGroups = $ExcludeGroups

    # Map location IDs
    if ($Conditions.locations) {
        $IncludeLocations = @($Conditions.locations.includeLocations | ForEach-Object {
            $ExportId = $_
            $LocationIdMapping | Where-Object {$_.ExportId -eq $ExportId} | Select-Object -ExpandProperty ImportId
        })
        $Conditions.locations.includeLocations = $IncludeLocations

        $ExcludeLocations = @($Conditions.locations.excludeLocations | ForEach-Object {
            $ExportId = $_
            $LocationIdMapping | Where-Object {$_.ExportId -eq $ExportId} | Select-Object -ExpandProperty ImportId
        })
        $Conditions.locations.excludeLocations = $ExcludeLocations
    }

    # Fix authentication strength
    $GrantControls = $CaPolicy.grantControls
    $AuthStrength = $GrantControls | Select-Object -ExpandProperty authenticationStrength
    if ($null -ne $AuthStrength)
    {
        $AuthStrength = [PSCustomObject]@{
            id = $GrantControls.authenticationStrength.id
        }
        $GrantControls.authenticationStrength = $AuthStrength
    }
    # If CAE is in policy, it cannot be in Report-only, set to off.
    $State = 'EnabledForReportingButNotEnforced'
    $CaeMode = $CaPolicy | Select-Object -ExpandProperty sessionControls | Select-Object -ExpandProperty continuousAccessEvaluation
    if ($null -ne $CaeMode)
    {
        $State = 'disabled'
    }

    # Create new policy object
    $NewPolicyJson = [PSCustomObject]@{
        displayName     = $CaPolicy.displayName
        conditions      = $Conditions
        grantControls   = $GrantControls
        sessionControls = $CaPolicy.sessionControls
        state           = $State
    } | ConvertTo-Json -Depth 10
    try {
        $null = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" -Body $NewPolicyJson
        Write-Host " - $($CaPolicy.displayName)"
    }
    catch {
        $Exception = $_
        $Message =  $Exception | Select-Object -ExpandProperty ErrorDetails |  Select-Object -ExpandProperty Message
        if ($null -ne $Message) {
            if ($Message.Contains('1038: The policy you are trying to create or update contains preview features')) {
                Write-Warning "Could not create Conditional Access policy '$($CaPolicy.displayName)', as it uses preview features." #TODO: Make retry with the beta endpoint
                Continue
            }
            if ($Message.Contains('1039: Cannot create or update policies with premium P2 features')) {
                Write-Warning "Could not create Conditional Access policy '$($CaPolicy.displayName)', as it requires a premium P2 license."
                Continue
            }
        }
        Write-Warning "Could not create Conditional Access policy '$($CaPolicy.displayName)'. $Exception"
    }
}

Write-Host "DONE." -ForegroundColor Green
