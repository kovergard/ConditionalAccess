<# 
    WIP

    2925-12-09: Abandoned this approach. as it produced long and hard to read names
#>
[CmdletBinding()]
param()
#requires -version 7.5.0

# Always stop on errors
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Define variables
$GraphVersion = 'beta'
$PolicyNameTemplate = '<SerialNumber> - <CloudApp>: <Response> For <Principal> When <Conditions>'

#region Internal functions

function Confirm-GraphConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $RequiredScopes
    )

    # Check if Graph module is installed
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication -Verbose:$false)) {
        throw 'Microsoft Graph PowerShell module is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }

    # Check if connected
    $MgContext = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $MgContext) {
        throw "Not connected to Microsoft Graph. Please run Connect-MgGraph -Scopes $($RequiredScopes -join ', ')"
    }

    # Check scopes
    $MissingScopes = $RequiredScopes | Where-Object { $_ -notin $MgContext.Scopes }
    if ($MissingScopes) {
        throw "Missing required Graph scopes: $($MissingScopes -join ', ')"
    }

    Write-Verbose 'Connected to Microsoft Graph with required scopes.'
    return $MgContext
}

function Resolve-CaApplication {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    $Applications = $Policy.conditions.applications

    # Resolve cloud app
    if ($Applications.includeApplications) {
        $AppId = $Applications.includeApplications
        if ($AppId -contains 'All') {
            return 'All cloud apps'
        }
        if ($AppId.count -gt 1) {
            return 'Multiple apps'
        }
        if ($AppId -contains 'Office365') {
            return 'Office 365'
        }
        if ($AppId -contains 'MicrosoftAdminPortals') {
            return 'Microsoft Admin Portals'
        }
        try {
            $SpLookup = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/$GraphVersion/servicePrincipals?`$filter=appId eq '$AppId'" -Verbose:$false
            return $SpLookup.value.displayName
        }
        catch {
            throw 'Unknown app'
            return 'Unknown app'
        }        
    }

    # Resolve user action
    if ($Applications.includeUserActions) {
        if ($Applications.includeUserActions -contains 'urn:user:registerdevice' ) {
            return 'Register or join devices'
        }
        if ($Applications.includeUserActions -contains 'urn:user:registersecurityinfo' ) {
            return 'Register security information'
        }
        throw 'Unknown user action'
        return 'Unknown action'
    }

    Write-Warning "Could not resolve application or action from $($Applications | ConvertTo-Json -Compress)"
    return 'Unresolved app or action'
}

function Resolve-CaResponse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    $Controls = @()

    # Resolve grant controls
    $GrantControls = $Policy | Select-Object -ExpandProperty grantControls
    $BuiltInControls = $GrantControls | Select-Object -ExpandProperty builtInControls
    if ($BuiltInControls) {
        if ($BuiltInControls -contains 'block') {
            $Controls += 'Block access'
        }
        if ($BuiltInControls -contains 'mfa') {
            $Controls += 'Require MFA'
        }
        if ($BuiltInControls -contains 'compliantApplication') {
            $Controls += 'Require app protection policy'
        }
        if ($BuiltInControls -contains 'compliantDevice') {
            $Controls += 'Require compliant device'
        }
    }
    $AuthenticationStrength = $GrantControls | Select-Object -ExpandProperty authenticationStrength
    if ($AuthenticationStrength) {
        $Controls += "Require auth strength '$($AuthenticationStrength.displayName)'"
    }

    # Resolve session controls
    $SessionControls = $Policy | Select-Object -ExpandProperty sessionControls
    $ApplicationEnforcedRestrictions = $SessionControls | Select-Object -ExpandProperty applicationEnforcedRestrictions
    if ($ApplicationEnforcedRestrictions) {
        if ($ApplicationEnforcedRestrictions.isEnabled) {
            $Controls += 'Use app enforced restrictions'
        }
    }
    $SignInFrequency = $SessionControls | Select-Object -ExpandProperty signInFrequency
    if ($SignInFrequency) {
        if ($SignInFrequency.isEnabled) {
            if ($SignInFrequency.frequencyInterval -eq 'timeBased') {
                $Controls += "Sign-in frequency '$($SignInFrequency.value) $($SignInFrequency.type)'"
            }
            else {
                $Controls += "Sign-in frequency 'Every time'"
            }
        }
    }
    $PersistentBrowser = $SessionControls | Select-Object -ExpandProperty persistentBrowser
    if ($PersistentBrowser) {
        if ($PersistentBrowser.isEnabled) {
            $Controls += "Persistent browser '$($PersistentBrowser.mode)'" 
        }
    }
    $ContinuousAccessEvaluation = $SessionControls | Select-Object -ExpandProperty continuousAccessEvaluation
    if ($ContinuousAccessEvaluation) {
        $Controls += "Conditional access evaluation '$($ContinuousAccessEvaluation.mode)'" 
    }


    if ($Controls.count -gt 0) {
        return $Controls -join ', '
    }

    throw 'UNRESOLVED RESPONSE'
    return 'UNRESOLVED RESPONSE'
}

function Resolve-CaPrincipal {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    if ($Policy.conditions.users.includeUsers -contains 'All') {
        return 'Everyone'
    }

    if ($Policy.conditions.users.includeRoles) {
        return 'Admins'
    }

    if ($Policy.conditions.users.includeGuestsOrExternalUsers) {
        return 'Guests'
    }

    #$Policy.conditions.users | ConvertTo-Json -Compress | Write-Host 
    return 'Specific Users'
}

function Resolve-CaCondition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy,

        [Parameter(Mandatory)]
        [PSCustomObject]
        $NamedLocations
    )

    $Conditions = @()

    # Device platforms
    $Platforms = $Policy | Select-Object -ExpandProperty conditions | Select-Object -ExpandProperty platforms
    if ($Platforms) {
        if ($Platforms.includePlatforms -contains 'All') {
            $Conditions += 'All device platforms'
        }
        else {
            $Conditions += "Device platform $($Platforms.includePlatforms -join ' or ')"
        }
    }

    # Locations
    $Locations = $Policy | Select-Object -ExpandProperty conditions | Select-Object -ExpandProperty locations
    if ($Locations) {
        if ($Locations.includeLocations -contains 'All') {
            $IncludeLocationsResolved = @('All locations')
        }
        else {
            $IncludeLocationsResolved = foreach ($LocId in $Locations.includeLocations) {
                $NamedLocations | Where-Object { $_.id -eq $LocId } | ForEach-Object { $_.displayName }
            }
        }
        $ExcludeLocationsResolved = foreach ($LocId in $Locations.excludeLocations) {
            $NamedLocations | Where-Object { $_.id -eq $LocId } | ForEach-Object { $_.displayName }
        }

        if ($ExcludeLocationsResolved) {
            $Conditions += "Location is $($IncludeLocationsResolved -join ' or ') except $($ExcludeLocationsResolved -join ' or ')"
        }
        elseif ($IncludeLocationsResolved -notcontains 'All locations') {
            $Conditions += "Location is $($IncludeLocationsResolved -join ' or ')"
        }
    }

    # Client apps
    $ClientApps = $Policy | Select-Object -ExpandProperty conditions | Select-Object -ExpandProperty clientAppTypes
    if ($ClientApps) {
        if ($ClientApps -contains 'All') {
            $AllClientApps = $true
        }
        else {
            $Conditions += "Client apps $($ClientApps -join ' or ')"
            $AllClientApps = $false
        }
    }

    if ($Conditions.count -gt 0) {
        return $Conditions -join ' and '
    }

    if ($AllClientApps) {
        return
    }

    return 'No conditions'
}

#endregion

#region MAIN

# Check if connected to Microsoft Graph
$MgContext = Confirm-GraphConnection -RequiredScopes 'Policy.Read.All', 'Application.Read.All'

# Fetch Conditional Access policies
$MgPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GraphVersion/identity/conditionalAccess/policies" -Verbose:$false | Select-Object -ExpandProperty value | Sort-Object -Property displayName
$MgLocations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GraphVersion/identity/conditionalAccess/namedLocations" -Verbose:$false | Select-Object -ExpandProperty value

# Remove Microsoft-managed policies
$MsManagedCount = ($MgPolicies | Where-Object { $_.templateId }).count
if ($MsManagedCount -gt 0) {
    Write-Verbose "Skipping $MsManagedCount Microsoft-managed policies"
    $MgPolicies = $MgPolicies | Where-Object { -not $_.templateId }
}

# Determine if a CA99 / CA999 serial number standard is in use
$PoliciesWithCaSn = $MgPolicies.displayName | Select-String -Pattern '^CA\d{2,3}' 
if ($PoliciesWithCaSn) {
    if ($PoliciesWithCaSn.count -gt ($MgPolicies.count / 2)) {
        $SnLength = $PoliciesWithCaSn.Matches | Select-Object -ExpandProperty Length -Unique | Select-Object -First 1
        $SnStandardDetected = $true
        if ($SnLength -eq 4) {
            $SnForNewPolicies = 'CA99'
        }
        else {
            $SnForNewPolicies = 'CA999'
        }
        Write-Verbose "Detected that a serial number standard is in use, using $SnForNewPolicies for policies without a serial number."
    }
}
else {
    Write-Verbose 'No serial number standard detected, all policies will get new serials, starting with CA01.'
    $SnStandardDetected = $false
    $SnIndex = 1
}

# Process each policy
foreach ($MgPolicy in $MgPolicies) {
    try {

        Write-Host $MgPolicy.displayName -ForegroundColor Cyan

        # Determine serial number
        if ($SnStandardDetected) {
            $ExistingSn = ($MgPolicy.displayName | Select-String -Pattern '^CA\d{2,3}')
            if ($ExistingSn) {
                $SerialNumber = $ExistingSn.Matches.Value
            }
            else {
                $SerialNumber = $SnForNewPolicies
            }
        }
        else {
            $SerialNumber = 'CA' + '{0:D2}' -f $SnIndex
            $SnIndex++
        }

        # Resolve policy components
        #TODO: Some policies might have multiple responses, applications, principals, conditions - need to handle those better
        $CloudApp = Resolve-CaApplication -Policy $MgPolicy
        $Response = Resolve-CaResponse -Policy $MgPolicy
        $Principal = Resolve-CaPrincipal -Policy $MgPolicy
        $Conditions = Resolve-CaCondition -Policy $MgPolicy -NamedLocations $MgLocations

        # Construct recommended policy name
        $RecommendedPolicyName = $PolicyNameTemplate -replace '<SerialNumber>', $SerialNumber -replace '<CloudApp>', $CloudApp -replace '<Response>', $Response -replace '<Principal>', $Principal 
        if ($Conditions) {
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Conditions>', $Conditions
        }
        else {
            $RecommendedPolicyName = $RecommendedPolicyName -replace ' When <Conditions>', ''
        }
        
        # TODO: Maximum length check (128 characters)

        # Output resultning object
        [PSCustomObject]@{
            #Id                    = $MgPolicy.id
            #CurrentPolicyName     = $MgPolicy.displayName
            RecommendedPolicyName = $RecommendedPolicyName
            NameLength            = $RecommendedPolicyName.Length
            ComplianceStatus      = 'TODO'
        }   
    }
    catch {
        $_
        $MgPolicy | ConvertTo-Json -Depth 4
        return 
    }        
}

#endregion MAIN