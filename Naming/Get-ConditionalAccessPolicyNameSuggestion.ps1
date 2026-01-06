<#
    .SYNOPSIS
    Suggest names for Conditional Access policies based on their configuration.
    .DESCRIPTION
    Connects to Microsoft Graph to enumerate Conditional Access policies and returns suggested policy names using a configurable pattern. 
    Supports condensing token values to PascalCase, reusing or generating serial numbers, and configurable delimiters for name parts.
    .EXAMPLE
    # Run with default options
    .\Get-ConditionalAccessPolicyNameSuggestion.ps1
    .EXAMPLE
    # Run and condense token values while preserving existing serial numbers
    .\Get-ConditionalAccessPolicyNameSuggestion.ps1 -Condense -KeepSerialNumbers
    .NOTES
    Requires PowerShell 7.4.0+ and the Microsoft.Graph.Authentication module. 
    The script uses the Microsoft Graph beta endpoint for newer Conditional Access features.
    .PARAMETER NamePattern
    Pattern string used to render suggested names; see the script's param block for full parameter details.
#>
[CmdletBinding()]
param(
    # Pattern for the suggested policy names
    [Parameter()]
    [string]
    $NamePattern = '{SerialNumber} - {Persona} - {TargetResource} - {Network} - {Condition} - {Response}',

    # Prefix for all new serial numbers
    [Parameter()]
    [string] 
    $SerialNumberPrefix = 'CA',

    # Delimiter used when all parts must be satisfied (logical AND)
    [Parameter()]
    [string]
    $AllPartsDelimiter = ' and ',

    # Delimiter used when any part may satisfy (logical OR)
    [Parameter()]
    [string]
    $AnyPartsDelimiter = ' or ',

    # Delimiter used when a part is excluded from another part (logical AND NOT)
    [Parameter()]
    [string]
    $ExcludePartsDelimiter = ' except ',

    # Always keep existing serial numbers, even if they don't match the persona
    [Parameter()]
    [switch]
    $KeepSerialNumbers,

    # Condense each part to PascalCase and remove non-alphanumeric characters
    [Parameter()]
    [switch]
    $Condense
)
#requires -version 7.4.0

#region Configuration

# At this time, the beta endpoint must be used to read newer features, like Continuous Access Evaluation
$GRAPH_VERSION = 'beta'

# Scopes needed for Graph access
$GRAPH_SCOPES = @(
    'Policy.Read.All',
    'Application.Read.All'
    'Group.Read.All'
)

# $GRAPH_SCOPES: scopes required for APIs used by the script. Must be consented prior to running.

# The number of digits in new serial numbers following the prefix, e.g. 'CA{PERSONA_SERIAL_DIGITS}{COUNTER_SERIAL_DIGITS}'
$PERSONA_SERIAL_DIGITS = 2
$COUNTER_SERIAL_DIGITS = 2

# Serial format: <Prefix><PersonaGroup><Counter>. PERSONA_SERIAL_DIGITS + COUNTER_SERIAL_DIGITS control lengths.
# $CA_SERIAL_NUMBER_REGEX matches existing serials at the start of policy names.

# Serial number regex for detection of existing serial numbers in policy names
$CA_SERIAL_NUMBER_REGEX = "^$($SerialNumberPrefix)\d{2,$($PERSONA_SERIAL_DIGITS + $COUNTER_SERIAL_DIGITS)}"

# Persona definitions
$CA_PERSONA = @(
    @{
        Name              = 'Global'
        EntraGroupName    = 'CA-Persona-Global'
        SerialNumberGroup = '00'
        MatchAll          = $true
    }
    @{
        Name              = 'Admins'
        EntraGroupName    = 'CA-Persona-Admins'
        SerialNumberGroup = '01'
        MatchRoles        = $true
    }
    @{
        Name              = 'Internals' 
        EntraGroupName    = 'CA-Persona-Internals'
        SerialNumberGroup = '02'
    }
    @{
        Name              = 'Externals' 
        EntraGroupName    = 'CA-Persona-Externals'
        SerialNumberGroup = '03'
    }
    @{
        Name              = 'Guests'
        EntraGroupName    = 'CA-Persona-Guests'
        SerialNumberGroup = '04'
        MatchGuests       = $true
    }
    @{
        Name              = 'GuestAdmins'
        EntraGroupName    = 'CA-Persona-GuestAdmins'
        SerialNumberGroup = '05'
    }
    @{
        Name              = 'Microsoft365ServiceAccounts'
        EntraGroupName    = 'CA-Persona-Microsoft365ServiceAccounts'
        SerialNumberGroup = '06'
    }
    @{
        Name              = 'AzureServiceAccounts'
        EntraGroupName    = 'CA-Persona-AzureServiceAccounts'
        SerialNumberGroup = '07'
    }
    @{
        Name              = 'CorpServiceAccounts'
        EntraGroupName    = 'CA-Persona-CorpServiceAccounts'
        SerialNumberGroup = '08'
    }
    @{
        Name              = 'WorkloadIdentities'
        EntraGroupName    = 'CA-Persona-WorkloadIdentities'
        SerialNumberGroup = '09'
    }
    @{
        Name              = 'Developers'
        EntraGroupName    = 'CA-Persona-Developers'
        SerialNumberGroup = '10'
    }
    @{
        Name              = 'Agents'
        EntraGroupName    = 'CA-Persona-Agents'
        SerialNumberGroup = '11'
        MatchAgents       = $true
    }
    @{
        Name              = 'Unknown'
        EntraGroupName    = 'CA-Persona-Unknown'
        SerialNumberGroup = '99'
        MatchUnknown      = $true
    }
)

# Lookup tables for various Conditional Access components

$CA_APP = @{
    'All'                                  = 'All apps' 
    'Office365'                            = 'Office 365' 
    'MicrosoftAdminPortals'                = 'Admin portals' 
    '00000002-0000-0ff1-ce00-000000000000' = 'EXO' 
    '00000003-0000-0ff1-ce00-000000000000' = 'SPO' 
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph' 
    '00000009-0000-0000-c000-000000000000' = 'PowerBI'   
    '0000000a-0000-0000-c000-000000000000' = 'Intune'
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Teams'               
    'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'Intune enrollment'            
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Azure Resource Manager' 
    '499b84ac-1321-427f-aa17-267ca6975798' = 'Azure DevOps'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Azure CLI' 
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'Azure PowerShell'
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Azure portal'
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Graph CLI'
    '2793995e-0a7d-40d7-bd35-6968ba142197' = 'MyApps'
    'None'                                 = 'No app'
    'Unresolved'                           = 'Unresolved app'
}

$CA_USERACTION = @{
    'urn:user:registerdevice'       = 'Register or join device'
    'urn:user:registersecurityinfo' = 'Register security info' 
    'Unresolved'                    = 'Unresolved user action'
}

$CA_NETWORK = @{
    'All'        = 'Any network'
    'AllTrusted' = 'Trusted networks'
    #TODO: Add Compliant Network locations when supported
    'Selected'   = '{Locations}'
    'Unresolved' = 'Unresolved network'
}

$CA_CONDITION = @{
    'None'                = 'Always'
    'UserRiskLevels'      = "User risk levels '{UserRisks}'"
    'SignInRiskLevels'    = "Sign-in risk levels '{SignInRisks}'"
    'InsiderRiskLevels'   = "Insider risk levels '{InsiderRisks}'"
    'AgentIdRiskLevels'   = "Agent risk levels '{AgentRisks}'"
    'DevicePlatforms'     = "Platforms '{Platforms}'"
    'UnknownPlatforms'    = 'Any unknown platform'
    'ClientAppTypes'      = "Client apps '{ClientApps}'"
    'DeviceFilters'       = 'Device filters applied'
    'AuthenticationFlows' = 'Authentication flows used'
    'Unresolved'          = 'Unresolved condition'
}

$CA_RESPONSE = @{

    # Grant controls
    'Block'                                    = 'Block'
    'RequirePrefix'                            = 'Require'
    'MFA'                                      = 'MFA'
    'AuthenticationStrength'                   = "authentication strength '{AuthStrength}'"
    'CompliantDevice'                          = 'compliant device'
    'DomainJoinedDevice'                       = 'hybrid-joined device'
    # Approved clients apps are being retired
    'CompliantApplication'                     = 'app protection policy'
    'PasswordChange'                           = 'password change'
    'RiskRemediation'                          = 'risk remediation'
    'TermsOfUse'                               = 'Terms of Use'

    # Session controls
    'AppEnforcedRestrictions'                  = 'Use app enforced restrictions'
    'CloudAppSecurityMonitorOnly'              = "Use CA App Control 'Monitor only'"
    'CloudAppSecurityBlockDownloads'           = "Use CA App Control 'Block downloads'"
    'CloudAppSecurityCustomPolicy'             = "Use CA App Control 'Custom policy'"
    'SignInFrequency'                          = "Sign-in frequency '{SignInFrequency}'"
    'PersistentBrowserNever'                   = 'Never persist browser'
    'PersistentBrowserAlways'                  = 'Always persist browser'
    'ContinuousAccessEvaluationStrictLocation' = 'Strict location CAE'
    'ContinuousAccessEvaluationDisabled'       = 'Disable CAE'
    'DisableResilienceDefaults'                = 'Disable resilience defaults'
    'RequireTokenProtection'                   = 'Require token protection'
    #TODO: Add handling of Global Secure Access security profiles

    # Unresolved
    'Unresolved'                               = 'Unresolved response'
}

#endregion Configuration

#region Initialize

$ErrorActionPreference = 'Stop'     # Always stop on errors
Set-StrictMode -Version Latest      # Enforce strict mode

$MgGroupCache = @()                 # Define cache
$SerialNumbersInUse = @()           # Track used serial numbers

#endregion Initialize

#region Helper functions

<#
    .SYNOPSIS
    Check Microsoft Graph connection and required scopes.
    .DESCRIPTION
    Verifies that the Microsoft.Graph.Authentication module is installed, that the session is connected to Microsoft Graph, 
    and that the specified scopes are present. Returns the Graph context object when successful.
    .EXAMPLE
    Confirm-GraphConnection -RequiredScopes @('Policy.Read.All')
#>
function Confirm-GraphConnection {
    [CmdletBinding()]
    param (
        # An array of scopes that must be present in the current Graph context.
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

<#
    .SYNOPSIS
    Retrieve an Entra ID group (cached).
    .DESCRIPTION
    Fetches a group by its object id from Microsoft Graph and caches the result in the script-level cache to avoid repeated API calls.
    .EXAMPLE
    Get-EntraIdGroup -GroupId '00000000-0000-0000-0000-000000000000'
#>
function Get-EntraIdGroup {
    [CmdletBinding()]
    param (
        # The object id of the group to retrieve.
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

<#
    .SYNOPSIS
    Determine the persona for a Conditional Access policy.
    .DESCRIPTION
    Analyzes the policy's user conditions (included users, groups, roles, guests, agents) and returns the matching persona definition 
    from the $CA_PERSONA lookup. Falls back to the Unknown persona when no specific match is found.
    .EXAMPLE
    Resolve-CaPersona -Policy $policy
#>
function Resolve-CaPersona {
    [CmdletBinding()]
    param (
        # The policy object (hashtable) retrieved from Microsoft Graph.
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
    if ($Policy.conditions.users.includeGuestsOrExternalUsers -or $Policy.conditions.users.includeUsers -contains 'GuestsOrExternalUsers') {
        return $CA_PERSONA | Where-Object { $_['MatchGuests'] -eq $true }
    }

    # Check for agents
    $AgentIdServicePrincipals = @($Policy.conditions.clientApplications | Select-Object -ExpandProperty includeAgentIdServicePrincipals)
    if ($AgentIdServicePrincipals.Count -gt 0 -or $Policy.conditions.users.includeUsers -contains 'AllAgentIdUsers') {
        return $CA_PERSONA | Where-Object { $_['MatchAgents'] -eq $true }
    }

    # Fallback to Unknown persona
    return $CA_PERSONA | Where-Object { $_['MatchUnknown'] -eq $true }
}


<#
    .SYNOPSIS
    Resolve or generate a serial number for a policy.
    .DESCRIPTION
    Checks the policy display name for an existing serial number and decides whether to reuse it (honoring the -KeepSerialNumbers option). 
    If none is suitable, generates a new unique serial using the provided prefix and the configured counter width.
    .EXAMPLE
    Resolve-CaSerialNumber -Policy $policy -Prefix 'CA00'
#>
function Resolve-CaSerialNumber {
    [CmdletBinding()]
    param (
        # The policy object to inspect for an existing serial.
        [Parameter(Mandatory)]
        [hashtable]
        $Policy,

        # The serial prefix (e.g., 'CA00') to use when generating a new serial.
        [Parameter(Mandatory)]
        [string]
        $Prefix
    )

    # Define total length of serial numbers for validation
    $SerialNumberLength = $Prefix.Length + $COUNTER_SERIAL_DIGITS

    # Check if an existing serial number should be reused
    $ExistingSn = ($Policy.displayName | Select-String -Pattern $CA_SERIAL_NUMBER_REGEX)
    
    if ($ExistingSn) {
        $SerialNumber = $ExistingSn.Matches.Value
        if ($KeepSerialNumbers) {
            return $SerialNumber
        }
        if ($SerialNumber.StartsWith($Prefix) -and $SerialNumber.Length -eq $SerialNumberLength) {
            return $SerialNumber
        }
    }

    # Check existing serial numbers in use
    $ExistingSerialsForPrefix = $SerialNumbersInUse | Where-Object { $_ -like "$Prefix*" } | Sort-Object
    # Write-Verbose "Existing serials for prefix '$Prefix': $($ExistingSerialsForPrefix -join ',')"

    $NewSerialCounter = 1
    while ($true) {
        $NewSerialNumber = "$Prefix{0:D$($COUNTER_SERIAL_DIGITS)}" -f $NewSerialCounter
        if ($ExistingSerialsForPrefix -notcontains $NewSerialNumber) {
            break
        }
        $NewSerialCounter++
        if ($NewSerialCounter -gt [math]::Pow(10, $COUNTER_SERIAL_DIGITS)) {
            Write-Warning "Exhausted all available serial numbers for prefix '$Prefix'."
            $NewSerialNumber = "$Prefix{0:D$($COUNTER_SERIAL_DIGITS)}" -f 0
            break
        }
    }

    $Script:SerialNumbersInUse += $NewSerialNumber

    return $NewSerialNumber
}

<#
    .SYNOPSIS
    Resolve the target resource (apps or user actions) for a policy.
    .DESCRIPTION
    Converts included/excluded application and user action identifiers into a human-friendly string using the $CA_APP and $CA_USERACTION 
    lookup tables. Emits warnings for unrecognized app ids or user actions.
    .EXAMPLE
    Resolve-CaTargetResource -Policy $policy
#>
function Resolve-CaTargetResource {
    [CmdletBinding()]
    param (
        # The policy object to inspect for target resources.
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
            $CA_APP['Unresolved']
        }
    }
    $ExcludeApps = $Policy.conditions.applications.excludeApplications | ForEach-Object {
        if ($CA_APP[$_]) {
            $CA_APP[$_]
        }
        else {
            Write-Warning "Unrecognized Exclude AppId '$_' in policy '$($Policy.displayName)'"
            $CA_APP['Unresolved']
        }
    }

    # Check for excludes if All apps are included
    if ($Apps -contains $CA_APP['All'] -and $ExcludeApps) {
        return "$($Apps) except $($ExcludeApps -join $AllPartsDelimiter)"
    }

    if ($Apps) {
        return $Apps -join $AllPartsDelimiter
    }

    # Resolve user actions
    $Actions = $Policy.conditions.applications.includeUserActions | ForEach-Object {
        if ($CA_USERACTION[$_]) {
            $CA_USERACTION[$_]
        }
        else {
            Write-Warning "Unrecognized user action '$_' in policy '$($Policy.displayName)'"
            $CA_USERACTION['Unresolved']
        }
    }
    if ($Actions) {
        return $Actions -join $AllPartsDelimiter
    }

    Write-Warning "Could not resolve application or action from $($Policy.conditions.applications | ConvertTo-Json -Compress) in policy '$($Policy.displayName)'"
    return 'Unknown app or action'
}

<#
    .SYNOPSIS
    Resolve network (named locations) included/excluded in a policy.
    .DESCRIPTION
    Fetches named locations from Graph and translates the policy's include/exclude location ids into readable names, handling special values 
    such as 'All' and 'AllTrusted'.
    .EXAMPLE
    Resolve-CaNetwork -Policy $policy
#>
function Resolve-CaNetwork {
    [CmdletBinding()]
    param (
        # The policy object to inspect for network conditions.
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    # Fetch named locations
    $MgLocations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/namedLocations" -Verbose:$false | Select-Object -ExpandProperty value

    # Resolve included networks
    $NetworksIncluded = @()
    $IncludeLocations = @($Policy.conditions.locations | Select-Object -ExpandProperty includeLocations -ErrorAction Ignore)
    if ($IncludeLocations.Count -eq 0 -or $IncludeLocations -contains 'All') {
        $NetworksIncluded += $CA_NETWORK['All']
    }
    elseif ($IncludeLocations -contains 'AllTrusted') {
        $NetworksIncluded += $CA_NETWORK['AllTrusted']
    }
    else {
        $LocationNames = ($MgLocations | Where-Object { $_.id -in $IncludeLocations } | Select-Object -ExpandProperty displayName)
        if ($null -ne $LocationNames) {
            $NetworksIncluded += $CA_NETWORK['Selected'].Replace('{Locations}', ($LocationNames -join $AllPartsDelimiter))
        }
        else {
            Write-Warning "Could not resolve included locations '$($IncludeLocations -join ', ')'"
            $NetworksIncluded += $CA_NETWORK['Unresolved']
        }
    }

    # Resolve excluded networks
    $NetworksExcluded = @()
    $ExcludeLocations = @($Policy.conditions.locations | Select-Object -ExpandProperty excludeLocations -ErrorAction Ignore)
    if ($ExcludeLocations.count -gt 0) {
        if ($ExcludeLocations -contains 'AllTrusted') {
            $NetworksExcluded += $CA_NETWORK['AllTrusted']
        }
        else {
            $LocationNames = ($MgLocations | Where-Object { $_.id -in $ExcludeLocations } | Select-Object -ExpandProperty displayName)
            if ($null -ne $LocationNames) {
                $NetworksExcluded += $CA_NETWORK['Selected'].Replace('{Locations}', ($LocationNames -join $AllPartsDelimiter))
            }
            else {
                Write-Warning "Could not resolve excluded locations '$($ExcludeLocations -join ', ')'"
                $NetworksExcluded += $CA_NETWORK['Unresolved']
            }
        }
    }
    
    # Return resolved networks
    if ($NetworksIncluded.count -gt 0) {
        if ($NetworksExcluded.count -gt 0) {
            return "$($NetworksIncluded -join $AnyPartsDelimiter)$ExcludePartsDelimiter$($NetworksExcluded -join $AllPartsDelimiter)"
        }
        return $NetworksIncluded -join $AllPartsDelimiter
    }

    return $CA_NETWORK['Unresolved']
}

<#
    .SYNOPSIS
    Resolve the conditions (risks, platforms, client apps, device filters, authentication flows) of a policy.
    .DESCRIPTION
    Collects various condition parts from the policy such as risk levels, platforms, client app types, device filters, and authentication flows 
    and returns a human-friendly description joined by configured delimiters. Returns 'Always' when no specific conditions apply.
    .EXAMPLE
    Resolve-CaCondition -Policy $policy
#>
function Resolve-CaCondition {
    [CmdletBinding()]
    param (
        # The policy object to inspect for conditions.
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    $Conditions = @()

    # User risk levels
    $UserRisks = @($Policy.conditions | Select-Object -ExpandProperty userRiskLevels -ErrorAction Ignore)
    if ($UserRisks.count -gt 0) {
        $Conditions += $CA_CONDITION['UserRiskLevels'].Replace('{UserRisks}', $UserRisks -join $AnyPartsDelimiter)
    }

    # Sign-in risk levels
    $SignInRisks = @($Policy.conditions | Select-Object -ExpandProperty signInRiskLevels -ErrorAction Ignore)
    if ($SignInRisks.count -gt 0) {
        $Conditions += $CA_CONDITION['SignInRiskLevels'].Replace('{SignInRisks}', $SignInRisks -join $AnyPartsDelimiter)
    }

    # Insider risk levels
    $InsiderRisks = @($Policy.conditions | Select-Object -ExpandProperty insiderRiskLevels -ErrorAction Ignore)
    if ($InsiderRisks.count -gt 0) {
        $Conditions += $CA_CONDITION['InsiderRiskLevels'].Replace('{InsiderRisks}', $InsiderRisks -join $AnyPartsDelimiter)
    }

    # Agent risk levels
    $AgentRisks = @($Policy.conditions | Select-Object -ExpandProperty agentIdRiskLevels -ErrorAction Ignore)
    if ($AgentRisks.count -gt 0) {
        $Conditions += $CA_CONDITION['AgentIdRiskLevels'].Replace('{AgentRisks}', ($AgentRisks.Split(',')) -join $AnyPartsDelimiter)
    }

    # Device platforms
    $IncludePlatforms = @($Policy.conditions.platforms | Select-Object -ExpandProperty includePlatforms -ErrorAction Ignore)
    $ExcludePlatforms = @($Policy.conditions.platforms | Select-Object -ExpandProperty excludePlatforms -ErrorAction Ignore)
    if ($IncludePlatforms -contains 'all' -and $ExcludePlatforms.Count -eq 6) {
        $Conditions += $CA_CONDITION['UnknownPlatforms']
    }
    elseif ($IncludePlatforms.count -gt 0 -and ($IncludePlatforms -notcontains 'all' -or $ExcludePlatforms.count -gt 0)) {
        $PlatformsIncluded = $IncludePlatforms -join $AnyPartsDelimiter
        $PlatformsExcluded = $ExcludePlatforms -join $AllPartsDelimiter
        if ($PlatformsExcluded -ne '') {
            $Conditions += $CA_CONDITION['DevicePlatforms'].Replace('{Platforms}', "$PlatformsIncluded$ExcludePartsDelimiter$PlatformsExcluded")
        }
        else {
            $Conditions += $CA_CONDITION['DevicePlatforms'].Replace('{Platforms}', $PlatformsIncluded)
        }
    }
    
    # Client application types
    $ClientAppTypes = @($Policy.conditions | Select-Object -ExpandProperty clientAppTypes -ErrorAction Ignore)
    if ($ClientAppTypes.count -gt 0 -and $ClientAppTypes -notcontains 'all') {
        $Conditions += $CA_CONDITION['ClientAppTypes'].Replace('{ClientApps}', $ClientAppTypes -join $AnyPartsDelimiter)
    }

    # Add a notation if device filters are used
    $DeviceFilters = @($Policy.conditions | Select-Object -ExpandProperty devices -ErrorAction Ignore | Select-Object -ExpandProperty deviceFilter -ErrorAction Ignore)
    if ($DeviceFilters.count -gt 0) {
        $Conditions += $CA_CONDITION['DeviceFilters']
    }

    # Authentication flows 
    $AuthenticationFlowTransferMethods = @($Policy.conditions | Select-Object -ExpandProperty authenticationFlows -ErrorAction Ignore | Select-Object -ExpandProperty transferMethods -ErrorAction Ignore)
    if ($AuthenticationFlowTransferMethods.count -gt 0) {
        $Conditions += $CA_CONDITION['AuthenticationFlows']
    }

    # Return conditions
    if ($Conditions.count -gt 0) {
        return $Conditions -join $AllPartsDelimiter
    }

    return $CA_CONDITION['None']
}


<#
    .SYNOPSIS
    Resolve grant and session controls into a readable response string.
    .DESCRIPTION
    Evaluates grant controls (including block and requirement controls) and various session controls, returning a concise, human-readable 
    description of the policy's response behavior.
    .EXAMPLE
    Resolve-CaResponse -Policy $policy
#>
function Resolve-CaResponse {
    [CmdletBinding()]
    param (
        # The policy object to inspect for grant and session controls.
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    # Handle grant controls

    if ($Policy.grantControls?.builtInControls -contains 'block') {
        return $CA_RESPONSE['Block'] 
    }

    $RequirementControls = @()

    $AuthenticationStrength = $Policy.grantControls?.authenticationStrength
    if ($AuthenticationStrength) {
        $RequirementControls += $CA_RESPONSE['AuthenticationStrength'].Replace('{AuthStrength}', $AuthenticationStrength.displayName)
    }

    @('mfa', 'CompliantDevice', 'domainJoinedDevice', 'compliantApplication', 'passwordChange', 'riskRemediation') | ForEach-Object {
        if ($Policy.grantControls?.builtInControls -contains $_) {
            $RequirementControls += $CA_RESPONSE[$_]
        }
    }

    if ($Policy.grantControls?.termsOfUse) {
        $RequirementControls += $CA_RESPONSE['termsOfUse']
    }

    $Response = @()
    if ($RequirementControls.count -gt 0) {
        if ($Policy.grantControls.operator -eq 'OR') {
            $RequirementControlOperator = $AnyPartsDelimiter
        }
        else {
            $RequirementControlOperator = $AllPartsDelimiter
        }
        $Response += "$($CA_RESPONSE['RequirePrefix']) $($RequirementControls -join $RequirementControlOperator)"
    }

    # Handle session controls

    $SessionControls = @()

    if ($Policy.sessionControls?.applicationEnforcedRestrictions?.isEnabled) {
        $SessionControls += $CA_RESPONSE['AppEnforcedRestrictions']
    }

    # Resolve Conditional Access App Control (AKA Cloud App Security) session controls
    $CloudAppSecurity = $Policy.sessionControls?.cloudAppSecurity
    if ($CloudAppSecurity) {
        switch ($CloudAppSecurity.cloudAppSecurityType) {
            'monitorOnly' {
                $SessionControls += $CA_RESPONSE['CloudAppSecurityMonitorOnly']
            }
            'blockDownloads' {
                $SessionControls += $CA_RESPONSE['CloudAppSecurityBlockDownloads']
            }
            'mcasConfigured' {
                $SessionControls += $CA_RESPONSE['CloudAppSecurityCustomPolicy']
            }
            default {
                Write-Warning "Unrecognized Conditional Access App Control mode '$($CloudAppSecurity.cloudAppSecurityType)' in policy '$($Policy.displayName)'"
            }
        }
    }

    $SignInFrequency = $Policy.sessionControls?.signInFrequency
    if ($SignInFrequency) {
        if ($SignInFrequency.frequencyInterval -eq 'timeBased') {
            $FrequencyText = "$($SignInFrequency.value) $($SignInFrequency.type)"
        }
        elseif ($SignInFrequency.frequencyInterval -eq 'everyTime') {
            $FrequencyText = 'Every time'
        }
        else {
            $FrequencyText = 'Unresolved'
        }
        $SessionControls += $CA_RESPONSE['SignInFrequency'].Replace('{SignInFrequency}', $FrequencyText)
    }

    $PersistentBrowser = $Policy.sessionControls?.persistentBrowser
    if ($PersistentBrowser) {
        if ($PersistentBrowser.mode -eq 'never') {
            $SessionControls += $CA_RESPONSE['PersistentBrowserNever']
        }
        else {
            $SessionControls += $CA_RESPONSE['PersistentBrowserAlways']             
        }
    }

    $ContinuousAccessEvaluation = $Policy.sessionControls?.continuousAccessEvaluation
    if ($ContinuousAccessEvaluation) {
        if ($ContinuousAccessEvaluation.mode -eq 'strictLocation') {
            $SessionControls += $CA_RESPONSE['ContinuousAccessEvaluationStrictLocation']
        }
        else {
            $SessionControls += $CA_RESPONSE['ContinuousAccessEvaluationDisabled']             
        }
    }
    if ($Policy.sessionControls?.disableResilienceDefaults -eq $true) {
        $SessionControls += $CA_RESPONSE['DisableResilienceDefaults']
    }

    if ($Policy.sessionControls?.secureSignInSession?.isEnabled -eq $true) {
        $SessionControls += $CA_RESPONSE['RequireTokenProtection']
    }

    # Add session controls to response
    if ($SessionControls.count -gt 0) {
        $Response += $SessionControls -join $AllPartsDelimiter
    }

    # Return responses
    if ($Response.count -gt 0) {
        return $Response -join $AllPartsDelimiter
    }

    return $CA_RESPONSE['Unresolved']
}

<#
    .SYNOPSIS
    Convert text to PascalCase and remove non-alphanumeric characters.
    .DESCRIPTION
    Extracts alphanumeric "words" from the input, capitalizes them appropriately and concatenates them into a PascalCase string. 
    .EXAMPLE
    Convert-ToPascalCase -Text 'All apps'  # -> 'AllApps'
#>
function Convert-ToPascalCase {
    param(
        # The input text to convert to PascalCase.
        [Parameter(Mandatory)]
        [string]
        $Text
    )

    # Extract alphanumeric "words" using the MatchCollection (StrictMode-safe)
    $RegMatches = [System.Text.RegularExpressions.Regex]::Matches($Text, '[A-Za-z0-9]+')
    if ($RegMatches.Count -eq 0) { return '' }

    # Build PascalCase from the matches
    $sb = New-Object System.Text.StringBuilder
    foreach ($m in $RegMatches) {
        $w = $m.Value
        if ($w.Length -eq 1) {
            [void]$sb.Append($w.ToUpperInvariant())
        }
        else {
            [void]$sb.Append($w.Substring(0, 1).ToUpperInvariant())
            [void]$sb.Append($w.Substring(1).ToLowerInvariant())
        }
    }
    return $sb.ToString()
}

<#
    .SYNOPSIS
    Renders a Conditional Access policy name from a pattern and a context map.

    .DESCRIPTION
    Accepts a pattern string containing placeholders (e.g., "{SerialNumber}") and a hashtable
    of values mapping placeholder names to values. When -Condense is used, token values
    (except 'SerialNumber' and 'Persona') are converted to PascalCase and non-alphanumeric
    characters are removed.

    .EXAMPLE
    $ctx = @{ SerialNumber='CA0010'; Persona='Global user'; TargetResource='All apps'; Platform='Any unknown platform'; Response='Block' }
    New-CaPolicyName -Pattern '{SerialNumber} - {Persona} - {TargetResource} - {Platform} - {Response}' -Context $ctx -Condense
#>
function New-CaPolicyName {
    [CmdletBinding()]
    param(
        # Pattern containing placeholders like '{SerialNumber}'.
        [Parameter(Mandatory)]
        [string]
        $Pattern,

        # Hashtable mapping placeholder names to values.
        [Parameter(Mandatory)]
        [hashtable]
        $Context,

        # Convert token values to PascalCase and remove non-alphanumeric characters (excl. SerialNumber & Persona).
        [Parameter()]
        [switch]
        $Condense
    )

    # Placeholder pattern: {Key}
    $placeholder = '\{(?<key>\w+)\}'

    # Replace placeholders with values (optionally condensed)
    $rendered = [System.Text.RegularExpressions.Regex]::Replace(
        $Pattern,
        $placeholder,
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)

            $key = $m.Groups['key'].Value
            $val = if ($Context.ContainsKey($key) -and $null -ne $Context[$key]) {
                [string]$Context[$key]
            }
            else {
                ''
            }

            if ($Condense -and $key -notin @('SerialNumber', 'Persona')) {
                return Convert-ToPascalCase -Text $val
            }
            return $val
        }
    )

    # Clean up redundant delimiters caused by empty components
    # - Collapse repeated separators (space-dash-space, pipes, commas, semicolons)
    $rendered = $rendered -replace '(?<sep>\s*[-|,;]\s*)(?=\s*[-|,;]\s*)', ''
    $rendered = $rendered -replace '(\s*[-|,;]\s*){2,}', ' - '
    $rendered = $rendered -replace '(^\s*[-|,;]\s*|\s*[-|,;]\s*$)', ''
    $rendered = $rendered -replace '\s{2,}', ' '

    return $rendered.Trim()
}
#endregion Helper functions

#region MAIN

# Check if connected to Microsoft Graph
$MgContext = Confirm-GraphConnection -RequiredScopes $GRAPH_SCOPES

# Fetch Conditional Access policies and related objects
$UnfilteredMgPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/policies" -Verbose:$false | Select-Object -ExpandProperty value | Sort-Object -Property createdDateTime
$MgPolicyTemplates = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/templates" -Verbose:$false | Select-Object -ExpandProperty value

# Filter Microsoft-managed policies
$MgPolicies = $UnfilteredMgPolicies | ForEach-Object {
    if ($_.templateId -and $_.templateId -notin $MgPolicyTemplates.id) {
        Write-Verbose "Skipping Microsoft-managed policy: $($_.displayName)"
    }
    else {
        $_
    }
}

# Determine if a serial number standard is in use
$PoliciesWithCaSn = @($MgPolicies.displayName | Select-String -Pattern $CA_SERIAL_NUMBER_REGEX)
if ($PoliciesWithCaSn.count -gt 0) {
    $SerialNumberLength = $SerialNumberPrefix.Length + $PERSONA_SERIAL_DIGITS + $COUNTER_SERIAL_DIGITS
    $SerialNumbersInUse = @($PoliciesWithCaSn.Matches | ForEach-Object { if ($_.Value.Length -eq $SerialNumberLength) { $_.Value } } | Sort-Object -Unique)
    if ($KeepSerialNumbers) {
        Write-Verbose 'Reusing existing serial numbers, even if they do not match the persona.'
    }
    else {
        Write-Verbose 'Reusing existing serial numbers, if they match the persona.'
    }
}
else {
    Write-Verbose 'No serial numbers detected. All policies will get new serials.'
}

# Process each policy
$SuggestedPolicyNames = foreach ($MgPolicy in $MgPolicies) {
    try {
        # Resolve policy name components
        $Persona = Resolve-CaPersona -Policy $MgPolicy
        $NameComponents = @{
            'SerialNumber'   = Resolve-CaSerialNumber -Policy $MgPolicy -Prefix "$SerialNumberPrefix$($Persona.SerialNumberGroup)"
            'Persona'        = $Persona.Name
            'TargetResource' = Resolve-CaTargetResource -Policy $MgPolicy
            'Network'        = Resolve-CaNetwork -Policy $MgPolicy
            'Condition'      = Resolve-CaCondition -Policy $MgPolicy
            'Response'       = Resolve-CaResponse -Policy $MgPolicy
        }

        # Generate suggested policy name
        if ($Condense) {
            $SuggestedPolicyName = New-CaPolicyName -Pattern $NamePattern -Context $NameComponents -Condense
        }
        else {
            $SuggestedPolicyName = New-CaPolicyName -Pattern $NamePattern -Context $NameComponents 
        }

        # Output resultning object
        [PSCustomObject]@{
            Id            = $MgPolicy.id
            Name          = $MgPolicy.displayName
            SuggestedName = $SuggestedPolicyName
        }   

    }
    catch {
        Write-Warning "Error processing policy '$($MgPolicy.displayName)': $($_.Exception.Message)"
    }        
}
$SuggestedPolicyNames | Write-Output 

#endregion MAIN