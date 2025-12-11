<# 
    WIP
#>
[CmdletBinding()]
param(
    # Templates string for the suggested policy names
    [Parameter()]
    [string]
    $PolicyNameTemplate = '<SerialNumber>-<Persona>-<PolicyType>-<TargetResource>-<Platform>-<Grant>-<Optional>'
    #$PolicyNameTemplate = '<SerialNumber> - <CloudApp>: <Response> For <Principal> When <Conditions>'
)
#requires -version 7.5.0

# Tempoary

#region Internal variables

# At time of script authoring, the beta endpoint had be used to read newer features, like Continuous Access Evaluation
$GraphVersion = 'beta'

#endregion

#region Initialize

# Always stop on errors
$ErrorActionPreference = 'Stop'

# Enforce strict mode
Set-StrictMode -Version Latest

#endregion

#region Internal functions


function Convert-ToPascalCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$InputString
    )

    process {
        # Split on any non-alphanumeric group, drop empties, then capitalize each token
        $tokens = $InputString -split '[^A-Za-z0-9]+' | Where-Object { $_.Length -gt 0 }

        # Capitalize: first char upper, rest lower (digits are kept as-is)
        ($tokens | ForEach-Object {
            if ($_.Length -eq 1) { $_.ToUpper() }
            else { $_.Substring(0, 1).ToUpper() + $_.Substring(1).ToLower() }
        }) -join ''
    }
}

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

function Resolve-CaTargetResource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    # Resolve cloud app
    $Apps = $Policy.conditions.applications.includeApplications | ForEach-Object {
        switch ($_) {
            'All' { 'AllApps' }
            'Office365' { 'O365' }
            'MicrosoftAdminPortals' { 'AdminPortals' }
            '00000002-0000-0ff1-ce00-000000000000' { 'EXO' }
            '00000003-0000-0ff1-ce00-000000000000' { 'SPO' }
            '00000003-0000-0000-c000-000000000000' { 'MicrosoftGraph' }      
            '00000009-0000-0000-c000-000000000000' { 'PowerBI' }             
            '1fec8e78-bce4-4aaf-ab1b-5451cc387264' { 'Teams' }               
            'd4ebce55-015a-49b5-a083-c84d1797ae8c' { 'IntuneEnrollment' }            
            '797f4846-ba00-4fd7-ba43-dac1f8f63013' { 'AzureResourceManager' }
            '499b84ac-1321-427f-aa17-267ca6975798' { 'AzureDevOps' }         
            '04b07795-8ddb-461a-bbee-02f9e1bf7b46' { 'AzureCLI' }            
            '1950a258-227b-4e31-a9cf-717495945fc2' { 'AzurePowerShell' }     
            'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' { 'AzurePortal' }            
            default {  
                Write-Warning "Unrecognized AppId '$_' in policy '$($Policy.displayName)'"
                'UnknownApp'
            }
        }
    }
    if ($Apps) {
        return $Apps -join '&'
    }

    # Resolve user action
    $Actions = $Policy.conditions.applications.includeUserActions | ForEach-Object {
        switch ($_) {
            'urn:user:registerdevice' { 'RegisterOrJoin' }
            'urn:user:registersecurityinfo' { 'SecurityInfo' }
            default {  
                Write-Warning "Unrecognized UserAction '$_' in policy '$($Policy.displayName)'"
                'UnknownAction'
            }
        }
    }
    if ($Actions) {
        return $Actions -join '&'
    }

    Write-Warning "Could not resolve application or action from $($Policy.conditions.applications | ConvertTo-Json -Compress) in policy '$($Policy.displayName)'"
    return 'UnknownAppOrAction'
}

function Resolve-CaPlatform {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    $IncludePlatforms = $Policy.conditions.platforms?.includePlatforms
    
    # If no platforms are specified, all platforms are included
    if ($null -eq $IncludePlatforms -or $IncludePlatforms -contains 'all') {
        return 'AnyPlatform'
    }

    # Return included platforms
    return $IncludePlatforms -join '&'
}


function Resolve-CaGrant {
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
            $Controls += 'Block'
        }
        if ($BuiltInControls -contains 'mfa') {
            $Controls += 'MFA'
        }
        if ($BuiltInControls -contains 'compliantApplication') {
            $Controls += 'Require app protection policy'
        }
        if ($BuiltInControls -contains 'compliantDevice') {
            $Controls += 'Compliant'
        }
    }
    $AuthenticationStrength = $GrantControls | Select-Object -ExpandProperty authenticationStrength
    if ($AuthenticationStrength) {
        $Controls += 'AuthStrength'
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
                $Controls += "SigninFreq$($SignInFrequency.value)$($SignInFrequency.type[0])"
            }
            else {
                $Controls += 'SigninEveryTime'
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
        return $Controls -join '&'
    }

    throw 'UNRESOLVED GRANT'
    return 'UNRESOLVED GRANT'
}

function Resolve-CaPersona {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    if ($Policy.conditions.users.includeUsers -contains 'All') {
        return 'Global'
    }

    if ($Policy.conditions.users.includeRoles) {
        return 'Admins'
    }

    if ($Policy.conditions.users.includeGuestsOrExternalUsers) {
        return 'Guests'
    }

    #$Policy.conditions.users | ConvertTo-Json -Compress | Write-Host 
    return 'Internals'
}

<#
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
#>

function Resolve-CaOptional {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy,

        [Parameter(Mandatory)]
        [PSCustomObject]
        $NamedLocations
    )

    $OptionalComponents = @()

    $AuthenticationStrength = $Policy.grantControls?.authenticationStrength
    if ($AuthenticationStrength) {
        $OptionalComponents += Convert-ToPascalCase -InputString $AuthenticationStrength.displayName
    }


    return $OptionalComponents
    
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
            $SnForNewPolicies = 'CAxx'
        }
        else {
            $SnForNewPolicies = 'CAxxx'
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

        # Initialize recommended policy name
        $RecommendedPolicyName = $PolicyNameTemplate  

        # Determine serial number
        if ($RecommendedPolicyName.Contains('<SerialNumber>')) {
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
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<SerialNumber>', $SerialNumber 
        }
    
        if ($RecommendedPolicyName.Contains('<Persona>')) {
            $Persona = Resolve-CaPersona -Policy $MgPolicy
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Persona>', $Persona
        }

        if ($RecommendedPolicyName.Contains('<PolicyType>')) {
            # TODO: Resolve policy type
        }

        if ($RecommendedPolicyName.Contains('<TargetResource>')) {
            $TargetResource = Resolve-CaTargetResource -Policy $MgPolicy
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<TargetResource>', $TargetResource
        }

        if ($RecommendedPolicyName.Contains('<Platform>')) {
            $Platform = Resolve-CaPlatform -Policy $MgPolicy
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Platform>', $Platform
        }

        if ($RecommendedPolicyName.Contains('<Grant>')) {
            $Grant = Resolve-CaGrant -Policy $MgPolicy
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Grant>', $Grant
        }

        if ($RecommendedPolicyName.Contains('<Optional>')) {
            $OptionalComponents = Resolve-CaOptional -Policy $MgPolicy -NamedLocations $MgLocations
            if ($OptionalComponents) {   
                $RecommendedPolicyName = $RecommendedPolicyName -replace '<Optional>', ($OptionalComponents -join '-')
            }
            else {
                $RecommendedPolicyName = $RecommendedPolicyName -replace '[- ]*<Optional>', ''
            }
        }

        # TODO: Change this to only resolve components used in the template - makes it possible to support different naming standards

        # Resolve policy components
        # TODO: Some policies might have multiple responses, applications, principals, conditions - need to handle those better
        #$CloudApp = Resolve-CaApplication -Policy $MgPolicy
        #$Response = Resolve-CaResponse -Policy $MgPolicy
        #$Principal = Resolve-CaPrincipal -Policy $MgPolicy
        #$Conditions = Resolve-CaCondition -Policy $MgPolicy -NamedLocations $MgLocations

        # Construct recommended policy name
        <#        $RecommendedPolicyName = $PolicyNameTemplate -replace '<SerialNumber>', $SerialNumber -replace '<CloudApp>', $CloudApp -replace '<Response>', $Response -replace '<Principal>', $Principal 
        if ($Conditions) {
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Conditions>', $Conditions
        }
        else {
            $RecommendedPolicyName = $RecommendedPolicyName -replace ' When <Conditions>', ''
        } #>
        
        # TODO: Maximum length check (128 characters)

        # Output resultning object
        [PSCustomObject]@{
            #Id                    = $MgPolicy.id
            CurrentPolicyName     = $MgPolicy.displayName
            RecommendedPolicyName = $RecommendedPolicyName
            #NameLength            = $RecommendedPolicyName.Length
            #ComplianceStatus      = 'TODO'
        }   
    }
    catch {
        $_
        $MgPolicy | ConvertTo-Json -Depth 4
        return 
    }        
}

#endregion MAIN