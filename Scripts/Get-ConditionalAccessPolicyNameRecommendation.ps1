<# 
    WIP
#>
[CmdletBinding()]
param(
    # Templates string for the suggested policy names
    [Parameter()]
    [string]
    $PolicyNameTemplate = '<SerialNumber>-<Persona>-<PolicyType>-<TargetResource>-<Platform>-<Response>-<Optional>'
    #$PolicyNameTemplate = '<SerialNumber> - <CloudApp>: <Response> For <Principal> When <Conditions>'
)
#requires -version 7.5.0

#region Configuration

# At this time, the beta endpoint must be used to read newer features, like Continuous Access Evaluation
$GRAPH_VERSION = 'beta'

# Scopes needed for Graph access
$GRAPH_SCOPES = @(
    'Policy.Read.All',
    'Application.Read.All'
    'Group.Read.All'
)

# Serial number regex for detection
$CA_SERIAL_NUMBER_REGEX = '^CA\d{3,4}'

# Persona definitions
$CA_PERSONA = @(
    @{
        Name           = 'Global'
        EntraGroupName = 'CA-Persona-Global'
        SerialPrefix   = 'CA0'
        MatchAll       = $true
    }
    @{
        Name           = 'Admins'
        EntraGroupName = 'CA-Persona-Admins'
        SerialPrefix   = 'CA1'
        MatchRoles     = $true
    }
    @{
        Name           = 'Internals' 
        EntraGroupName = 'CA-Persona-Internals'
        SerialPrefix   = 'CA2'
    }
    @{
        Name           = 'Externals' 
        EntraGroupName = 'CA-Persona-Externals'
        SerialPrefix   = 'CA3'
    }
    @{
        Name           = 'Guests'
        EntraGroupName = 'CA-Persona-Guests'
        SerialPrefix   = 'CA4'
        MatchGuests    = $true
    }
    @{
        Name           = 'GuestAdmins'
        EntraGroupName = 'CA-Persona-GuestAdmins'
        SerialPrefix   = 'CA5'
    }
    @{
        Name           = 'Microsoft365ServiceAccounts'
        EntraGroupName = 'CA-Persona-Microsoft365ServiceAccounts'
        SerialPrefix   = 'CA6'
    }
    @{
        Name           = 'AzureServiceAccounts'
        EntraGroupName = 'CA-Persona-AzureServiceAccounts'
        SerialPrefix   = 'CA7'
    }
    @{
        Name           = 'CorpServiceAccounts'
        EntraGroupName = 'CA-Persona-CorpServiceAccounts'
        SerialPrefix   = 'CA8'
    }
    @{
        Name           = 'WorkloadIdentities'
        EntraGroupName = 'CA-Persona-WorkloadIdentities'
        SerialPrefix   = 'CA9'
    }
    @{
        Name           = 'Developers'
        EntraGroupName = 'CA-Persona-Developers'
        SerialPrefix   = 'CA10'
    }
    @{
        Name           = 'Unknown'
        EntraGroupName = 'CA-Persona-Unknown'
        SerialPrefix   = 'CAx'
        MatchUnknown   = $true
    }
)

$CA_APP = @{
    'All'                                  = 'AllApps' 
    'Office365'                            = 'O365' 
    'MicrosoftAdminPortals'                = 'AdminPortals' 
    '00000002-0000-0ff1-ce00-000000000000' = 'EXO' 
    '00000003-0000-0ff1-ce00-000000000000' = 'SPO' 
    '00000003-0000-0000-c000-000000000000' = 'MicrosoftGraph' 
    '00000009-0000-0000-c000-000000000000' = 'PowerBI'        
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Teams'               
    'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'IntuneEnrollment'            
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'AzureResourceManager' 
    '499b84ac-1321-427f-aa17-267ca6975798' = 'AzureDevOps'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'AzureCLI' 
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'AzurePowerShell'
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'AzurePortal'
}

$CA_USERACTION = @{
    'urn:user:registerdevice'       = 'RegisterOrJoin'
    'urn:user:registersecurityinfo' = 'SecurityInfo' 
}

$CA_PLATFORM = @{
    'all'          = 'AnyPlatform'
    'android'      = 'Android'
    'iOS'          = 'iOS'
    'macOS'        = 'MacOS'
    'windowsPhone' = 'WindowsPhone'
    'windows'      = 'Windows'
}

$CA_RESPONSE = @{
    'Block'                     = 'Block'
    'BlockSpecifiedLocations'    = 'BlockSpecifiedLocations'
    'AllowOnlySpecifiedLocations'   = 'AllowOnlySpecifiedLocations'
    'BlockUnknownPlatforms'     = 'BlockUnknownPlatforms'
    'BLockLegacyAuthentication' = 'BlockLegacyAuth'
    'BlockAuthenticationFlows'  = 'BlockAuthFlows'

    'mfa'                       = 'MFA'
    'compliantDevice'           = 'Compliant'
    'compliantApplication'      = 'RequireAppProtectionPolicy'
}

$CA_AND_DELIMITER = '&'
$CA_OR_DELIMITER = '/'

#endregion

#region Initialize

$ErrorActionPreference = 'Stop'     # Always stop on errors
Set-StrictMode -Version Latest      # Enforce strict mode

$MgGroupCache = @()                 # Define cache
$SerialNumbersInUse = @()           # Track used serial numbers

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

function Get-EntraIdGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $GroupId
    )

    # Check cache first
    $CachedGroup = $MgGroupCache | Where-Object { $_.id -eq $GroupId }
    if ($CachedGroup) {
        return $CachedGroup
    }

    # Fetch group from Graph
    $Group = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/groups/$GroupId" -Verbose:$false

    if (-not $Group) {
        Write-Warning "Could not retrieve group with ID '$GroupId' from Microsoft Graph."
        return
    }

    # Cache group
    $Script:MgGroupCache += $Group

    # Return group
    return $Group
}

function Resolve-CaPersona {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    
    )

    # Check for 'All users' inclusion
    if ($Policy.conditions.users.includeUsers -contains 'All') {
        return $CA_PERSONA | Where-Object { $_['MatchAll'] -eq $true }
    }

    # Check included groups
    if ($Policy.conditions.users.includeGroups) {
        foreach ($GroupId in $Policy.conditions.users.includeGroups) {
            
            # Get group from Entra ID
            $Group = Get-EntraIdGroup -GroupId $GroupId
            if ($null -eq $Group) {
                continue
            }

            # Check if group matches any persona
            foreach ($PersonaDef in $CA_PERSONA) {
                if ($Group.displayName -eq $PersonaDef.EntraGroupName) {
                    return $PersonaDef
                }
            }
        }
    }

    # Check for role-based or guest/external user inclusion
    if ($Policy.conditions.users.includeRoles) {
        return $CA_PERSONA | Where-Object { $_['MatchRoles'] -eq $true }
    }
    if ($Policy.conditions.users.includeGuestsOrExternalUsers) {
        return $CA_PERSONA | Where-Object { $_['MatchGuests'] -eq $true }
    }

    # Fallback to Unknown persona
    return $CA_PERSONA | Where-Object { $_['MatchUnknown'] -eq $true }
}

function Resolve-CaSerialNumber {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy,

        [Parameter(Mandatory)]
        [string]
        $Prefix
    )

    # Check if existing serial number can be reused
    $ExistingSn = ($Policy.displayName | Select-String -Pattern $CA_SERIAL_NUMBER_REGEX)
    if ($ExistingSn) {
        $SerialNumber = $ExistingSn.Matches.Value
        if ($SerialNumber.StartsWith($Prefix)) {
            return $SerialNumber
        }
    }

    # Check existing serial numbers in use
    $ExistingSerialsForPrefix = $SerialNumbersInUse | Where-Object { $_ -like "$Prefix*" } | Sort-Object

    if ($null -ne $ExistingSerialsForPrefix) {
        # Reuse the lowest available serial number
        $LastSerial = @($ExistingSerialsForPrefix)[-1]
        $LastSerialNumber = [int]($LastSerial.Substring($Prefix.Length))
        $NewSerialNumber = $LastSerialNumber + 1
    }
    else {
        # Start new serial numbering
        $NewSerialNumber = 1
    }

    # Construct new serial number
    $NewSerial = "$Prefix{0:D2}" -f $NewSerialNumber

    # Track new serial number as used
    $Script:SerialNumbersInUse += $NewSerial

    return $NewSerial
}


function Resolve-CaTargetResource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    # Resolve cloud apps
    $Apps = $Policy.conditions.applications.includeApplications | ForEach-Object {
        if ($CA_APP[$_]) {
            $CA_APP[$_]
        }
        else {
            Write-Warning "Unrecognized AppId '$_' in policy '$($Policy.displayName)'"
            'UnknownApp'
        }
    }
    if ($Apps) {
        return $Apps -join $CA_AND_DELIMITER
    }

    # Resolve user actions
    $Actions = $Policy.conditions.applications.includeUserActions | ForEach-Object {
        if ($CA_USERACTION[$_]) {
            $CA_USERACTION[$_]
        }
        else {
            Write-Warning "Unrecognized UserAction '$_' in policy '$($Policy.displayName)'"
            'UnknownAction'
        }
    }
    if ($Actions) {
        return $Actions -join $CA_AND_DELIMITER
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
        return $CA_PLATFORM['all']
    }

    $Platforms = $IncludePlatforms | ForEach-Object {
        if ($CA_PLATFORM[$_]) {
            $CA_PLATFORM[$_]
        }
        else {
            Write-Warning "Unrecognized platform '$_' in policy '$($Policy.displayName)'"
            'UnknownPlatform'
        }
    }

    # Return included platforms
    return $Platforms -join $CA_AND_DELIMITER
}


function Resolve-CaCombinedResponse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    $Response = @()


    if ($Response.count -gt 0) {
        return $Response -join $CA_AND_DELIMITER
    }

    throw 'Find a way to resolve!'


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
        return $Controls -join $CA_AND_DELIMITER
    }

    throw 'UNRESOLVED GRANT'
    return 'UNRESOLVED GRANT'
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
$MgContext = Confirm-GraphConnection -RequiredScopes $GRAPH_SCOPES

# Fetch Conditional Access policies
$MgPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/policies" -Verbose:$false | Select-Object -ExpandProperty value | Sort-Object -Property displayName
$MgLocations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/namedLocations" -Verbose:$false | Select-Object -ExpandProperty value

# Remove Microsoft-managed policies
$MsManagedCount = ($MgPolicies | Where-Object { $_.templateId }).count
if ($MsManagedCount -gt 0) {
    Write-Verbose "Skipping $MsManagedCount Microsoft-managed policies"
    $MgPolicies = $MgPolicies | Where-Object { -not $_.templateId }
}

# Determine if a CA999 / CA9999 serial number standard is in use
$PoliciesWithCaSn = $MgPolicies.displayName | Select-String -Pattern $CA_SERIAL_NUMBER_REGEX
if ($PoliciesWithCaSn) {
    if ($PoliciesWithCaSn.count -gt ($MgPolicies.count / 2)) {
        $SerialNumbersInUse = $PoliciesWithCaSn.Matches | ForEach-Object { $_.Value } | Sort-Object -Unique
        Write-Verbose 'Detected existing serial numbers. Will reuse serial numbers, if they match the personas.'
    }
}
if ($SerialNumbersInUse.count -eq 0) {
    Write-Verbose 'No serial numbers detected. All policies will get new serials.'
}

# Process each policy
foreach ($MgPolicy in $MgPolicies) {
    try {

        # Write-Host $MgPolicy.displayName -ForegroundColor Cyan

        # Initialize recommended policy name
        $RecommendedPolicyName = $PolicyNameTemplate  

        $Persona = Resolve-CaPersona -Policy $MgPolicy

        if ($RecommendedPolicyName.Contains('<Persona>')) {
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Persona>', $Persona.Name
        }

        # Determine serial number
        if ($RecommendedPolicyName.Contains('<SerialNumber>')) {
            $SerialNumber = Resolve-CaSerialNumber -Policy $MgPolicy -Prefix $Persona.SerialPrefix
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<SerialNumber>', $SerialNumber 
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

        if ($RecommendedPolicyName.Contains('<Response>')) {
            $Response = Resolve-CaResponse -Policy $MgPolicy
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Response>', $Response
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