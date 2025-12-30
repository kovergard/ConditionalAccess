<# 
    WIP
#>
[CmdletBinding()]
param(
    # Pattern for the suggested policy names
    [Parameter()]
    [string]
    $NamePattern = '{SerialNumber} - {Persona} - {TargetResource} - {Platform} - {Response}',

    # Delimiter used when all parts must be satisfied (logical AND)
    [Parameter()]
    [string] 
    $SerialNumberPrefix = 'CA',
 
    # Delimiter used when all parts must be satisfied (logical AND)
    [Parameter()]
    [Alias('AndSeparator', 'RequireAllDelimiter')]
    [string]
    $AllPartsDelimiter = ' and ',

    # Delimiter used when any part may satisfy (logical OR)
    [Parameter()]
    [Alias('OrSeparator', 'MatchAnyDelimiter')]
    [string]
    $AnyPartsDelimiter = ' or '
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

# Serial number regex for detection
$CA_SERIAL_NUMBER_REGEX = "^$($SerialNumberPrefix)\d{2,4}"

# Persona definitions
$CA_PERSONA = @(
    @{
        Name           = 'Global'
        EntraGroupName = 'CA-Persona-Global'
        SerialDigits   = '0'
        MatchAll       = $true
    }
    @{
        Name           = 'Admins'
        EntraGroupName = 'CA-Persona-Admins'
        SerialDigits   = '1'
        MatchRoles     = $true
    }
    @{
        Name           = 'Internals' 
        EntraGroupName = 'CA-Persona-Internals'
        SerialDigits   = '2'
    }
    @{
        Name           = 'Externals' 
        EntraGroupName = 'CA-Persona-Externals'
        SerialDigits   = '3'
    }
    @{
        Name           = 'Guests'
        EntraGroupName = 'CA-Persona-Guests'
        SerialDigits   = '4'
        MatchGuests    = $true
    }
    @{
        Name           = 'GuestAdmins'
        EntraGroupName = 'CA-Persona-GuestAdmins'
        SerialDigits   = '5'
    }
    @{
        Name           = 'Microsoft365ServiceAccounts'
        EntraGroupName = 'CA-Persona-Microsoft365ServiceAccounts'
        SerialDigits   = '6'
    }
    @{
        Name           = 'AzureServiceAccounts'
        EntraGroupName = 'CA-Persona-AzureServiceAccounts'
        SerialDigits   = '7'
    }
    @{
        Name           = 'CorpServiceAccounts'
        EntraGroupName = 'CA-Persona-CorpServiceAccounts'
        SerialDigits   = '8'
    }
    @{
        Name           = 'WorkloadIdentities'
        EntraGroupName = 'CA-Persona-WorkloadIdentities'
        SerialDigits   = '9'
    }
    @{
        Name           = 'Developers'
        EntraGroupName = 'CA-Persona-Developers'
        SerialDigits   = '10'
    }
    @{
        Name           = 'Unknown'
        EntraGroupName = 'CA-Persona-Unknown'
        SerialDigits   = 'CAx'
        MatchUnknown   = $true
    }
)

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
    'Unresolved'                           = 'Unresolved app'
}

$CA_USERACTION = @{
    'urn:user:registerdevice'       = 'Register or join device'
    'urn:user:registersecurityinfo' = 'Register security info' 
    'Unresolved'                    = 'Unresolved user action'
}

$CA_PLATFORM = @{
    'all'          = 'Any platform'
    'android'      = 'Android'
    'iOS'          = 'iOS'
    'linux'        = 'Linux'
    'macOS'        = 'macOS'
    'windowsPhone' = 'Windows Phone'
    'windows'      = 'Windows'
    'Unknown'      = 'Unknown platforms'
    'Unresolved'   = 'Unresolved platform'
}

$CA_RESPONSE = @{

    # Grant controls - block types
    'Block'                                    = 'Block'
    'BlockLocations'                           = "Block locations '{Locations}'"
    'OnlyAllowLocations'                       = "Only allow locations '{Locations}'"
    'BLockLegacyAuthentication'                = 'Block legacy authentication'
    'BlockAuthenticationFlows'                 = 'Block authentication flows'

    # Grant controls - grant types
    'MFA'                                      = 'MFA'
    'AuthenticationStrength'                   = "authentication strength '{AuthStrength}'"
    'ComplientDevice'                          = 'compliant device'
    'DomainJoinedDevice'                       = 'hybrid-joined device'
    #Approved clients apps is retiring
    'AppProtectionPolicy'                      = 'app protection policy'
    #TODO: Risk remidiation - requires P2

    # INSIDER?
    # RISKY SIGN-INS?

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
    #TODO: Disable resilience defaults
    #TODO: Token protection
    #TODO: Use GSA security profile

    # Unresolved
    'Unresolved'                               = 'Unresolved response'
}

#endregion

#region Initialize

$ErrorActionPreference = 'Stop'     # Always stop on errors
Set-StrictMode -Version Latest      # Enforce strict mode

$MgGroupCache = @()                 # Define cache
$SerialNumbersInUse = @()           # Track used serial numbers

#endregion

#region Helper functions

function Convert-ToPascalCaseString {
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
    if ($Policy.conditions.users.includeGuestsOrExternalUsers -or $Policy.conditions.users.includeUsers -contains 'GuestsOrExternalUsers') {
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

function Resolve-CaPlatform {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy
    )

    $IncludePlatforms = $Policy.conditions.platforms?.includePlatforms
    
    if ($Policy.conditions?.devices?.deviceFilter) {
        $DeviceFilterString = " with device filter"
    }
    else {
        $DeviceFilterString = ""
    }

    # If no platforms are specified, all platforms are included
    if ($null -eq $IncludePlatforms -or $IncludePlatforms -contains 'all') {
        $ExcludePlatforms = $Policy.conditions.platforms?.excludePlatforms
        if ($null -ne $ExcludePlatforms -and $ExcludePlatforms.count -gt 0) {
            if ($ExcludePlatforms.count -eq 6) {
                return "$($CA_PLATFORM['Unknown'])$DeviceFilterString"
            }
            $ExcludePlatformsNames = $ExcludePlatforms | ForEach-Object {
                if ($CA_PLATFORM[$_]) {
                    $CA_PLATFORM[$_]
                }
                else {
                    Write-Warning "Unrecognized platform '$_' in policy '$($Policy.displayName)'"
                    $CA_PLATFORM['Unresolved']
                }
            }
            return "$($CA_PLATFORM['all']) except $($ExcludePlatformsNames -join $AllPartsDelimiter)$DeviceFilterString"            
        }
        return "$($CA_PLATFORM['all'])$DeviceFilterString"
    }

    $Platforms = $IncludePlatforms | ForEach-Object {
        if ($CA_PLATFORM[$_]) {
            $CA_PLATFORM[$_]
        }
        else {
            Write-Warning "Unrecognized platform '$_' in policy '$($Policy.displayName)'"
            $CA_PLATFORM['Unresolved']
        }
    }

    # Return included platforms
    return "$($Platforms -join $AllPartsDelimiter)$DeviceFilterString"
}


function Resolve-CaResponse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]
        $Policy,

        [Parameter(Mandatory)]
        [PSCustomObject]
        $NamedLocations
    )

    # BLOCK CONTROLS

    if ($Policy.grantControls?.builtInControls -contains 'block') {

        $Block = @()

        # Location-based blocks
        $IncludeLocations = $Policy.conditions.locations?.includeLocations
        $ExcludeLocations = $Policy.conditions.locations?.excludeLocations
        if ($IncludeLocations -and $IncludeLocations -notcontains 'All') {
            $Locations = ($NamedLocations | Where-Object { $_.id -in $IncludeLocations } | Select-Object -ExpandProperty displayName) -join $AllPartsDelimiter
            $Block += $CA_RESPONSE['BlockLocations'].Replace('{Locations}', $Locations)
        }
        elseif ($ExcludeLocations -and $ExcludeLocations -notcontains 'All') {
            $Locations = ($NamedLocations | Where-Object { $_.id -in $ExcludeLocations } | Select-Object -ExpandProperty displayName) -join $AllPartsDelimiter
            $Block += $CA_RESPONSE['OnlyAllowLocations'].Replace('{Locations}', $Locations)
        }

        # Block legacy authentication  
        if ($Policy.conditions.clientAppTypes -contains 'other' -and $Policy.conditions.clientAppTypes -contains 'exchangeActiveSync') {
            $Block += $CA_RESPONSE['BLockLegacyAuthentication']
        }

        # Block authentication flows
        $TransferMethods = $Policy.conditions | Select-Object -ExpandProperty authenticationFlows -ErrorAction Ignore | Select-Object -ExpandProperty transferMethods -ErrorAction Ignore
        if ($null -ne $TransferMethods -and $TransferMethods.IndexOf('deviceCodeFlow') -ge 0 -and $TransferMethods.Indexof('authenticationTransfer') -ge 0 ) {
            $Block += $CA_RESPONSE['BlockAuthenticationFlows']
        }

        # Normal block control if no specific block reason found
        if ($Block.count -eq 0) {
            $Block = $CA_RESPONSE['Block'] 
        }

        return $Block -join $AllPartsDelimiter
    }

    # REQUIREMENT CONTROLS

    $RequirementControls = @()

    if ($Policy.grantControls?.builtInControls -contains 'mfa') {
        $RequirementControls += $CA_RESPONSE['mfa']
    }

    $AuthenticationStrength = $Policy.grantControls?.authenticationStrength
    if ($AuthenticationStrength) {
        $RequirementControls += $CA_RESPONSE['AuthenticationStrength'].Replace('{AuthStrength}', $AuthenticationStrength.displayName)
    }

    if ($Policy.grantControls?.builtInControls -contains 'compliantDevice') {
        $RequirementControls += $CA_RESPONSE['ComplientDevice']
    }

    if ($Policy.grantControls?.builtInControls -contains 'domainJoinedDevice') {
        $RequirementControls += $CA_RESPONSE['DomainJoinedDevice']
    }

    if ($Policy.grantControls?.builtInControls -contains 'compliantApplication') {
        $RequirementControls += $CA_RESPONSE['AppProtectionPolicy']
    }

    $Controls = @()
    if ($RequirementControls.count -gt 0) {
        if ($Policy.grantControls.operator -eq 'OR') {
            $RequirementControlOperator = $AnyPartsDelimiter
        }
        else {
            $RequirementControlOperator = $AllPartsDelimiter
        }
        $Controls += "Require $($RequirementControls -join $RequirementControlOperator)"
    }

    # SESSION CONTROLS

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

    if ($SessionControls.count -gt 0) {
        $Controls += $SessionControls -join $AllPartsDelimiter
    }


    # Return responses
    if ($Controls.count -gt 0) {
        return $Controls -join $AllPartsDelimiter
    }
    return $CA_RESPONSE['Unresolved']
}



function New-CaPolicyName {
    <#
    .SYNOPSIS
    Renders a Conditional Access policy name from a pattern and a context map.

    .DESCRIPTION
    Accepts a pattern string containing placeholders (e.g., "{SerialNumber}") and a hashtable
    of values. Supports simple format filters like Upper, Lower, Trim, and IfEmpty:Text.

    .EXAMPLE
    $ctx = @{
        SerialNumber   = '010'
        Persona        = 'Global'
        TargetResource = 'All apps'
        Platform       = 'Any unknown platform'
        Response       = 'Block'
    }
    New-CaPolicyName -Pattern 'CA{SerialNumber} - {Persona} - {TargetResource} - {Platform} - {Response}' -Context $ctx
    # -> "CA010 - Global - All apps - Any unknown platform - Block"

    .EXAMPLE
    New-CaPolicyName -Pattern '{Persona} | {TargetResource} | {Response} ({SerialNumber})' -Context $ctx
    # -> "Global | All apps | Block (010)"

    .EXAMPLE
    # Empty values are trimmed automatically
    $ctx.Platform = ''
    New-CaPolicyName -Pattern 'CA{SerialNumber} - {Persona} - {TargetResource} - {Platform} - {Response}' -Context $ctx
    # -> "CA010 - Global - All apps - Block"

    .EXAMPLE
    # Filters
    New-CaPolicyName -Pattern 'CA{SerialNumber} - {Persona|Upper} - {Response|Lower}' -Context $ctx
    # -> "CA010 - GLOBAL - block"

    .EXAMPLE
    # IfEmpty fallback for optional fields
    New-CaPolicyName -Pattern '{Persona} - {TargetResource} - {Platform|IfEmpty:Any platform} - {Response}' -Context $ctx
    # -> "Global - All apps - Any platform - Block"
    #>

    [CmdletBinding()]
    param(
        # Pattern with placeholders, e.g., "CA{SerialNumber} - {Persona} - {Response}"
        [Parameter(Mandatory)]
        [string] $Pattern,

        # Map of values for placeholders
        [Parameter(Mandatory)]
        [hashtable] $Context
    )

    # Regex: {Key} or {Key|Filter[:Arg]}
    $placeholder = '\{(?<key>\w+)(?:\|(?<filter>\w+)(?::(?<arg>[^}]+))?)?\}'

    # Replace placeholders
    $rendered = [System.Text.RegularExpressions.Regex]::Replace($Pattern, $placeholder, {
            param($m)

            $key = $m.Groups['key'].Value
            $filter = $m.Groups['filter'].Value
            $arg = $m.Groups['arg'].Value

            # Fetch value; treat missing as empty
            $val = if ($Context.ContainsKey($key)) { [string]$Context[$key] } else { '' }

            # Apply filter(s) — single filter supported per token for simplicity
            switch ($filter) {
                'Upper' { $val = $val.ToUpperInvariant() }
                'Lower' { $val = $val.ToLowerInvariant() }
                'Trim' { $val = $val.Trim() }
                'IfEmpty' { if ([string]::IsNullOrWhiteSpace($val)) { $val = $arg } }
                default { } # no filter or unsupported filter
            }

            # Return possibly-empty value; we clean delimiters post-process
            return $val
        })

    # Clean up redundant delimiters caused by empty values:
    # Strategy: collapse any "space-dash-space" sequences where a component became empty, then trim.
    # You can expand this to other separators if you use custom punctuation.
    $rendered = $rendered -replace '(?<sep>\s*[-|,;]\s*)(?=\s*[-|,;]\s*)', ''     # remove repeated separators
    $rendered = $rendered -replace '(\s*[-|,;]\s*){2,}', ' - '                    # collapse to single " - "
    $rendered = $rendered -replace '(^\s*[-|,;]\s*|\s*[-|,;]\s*$)', ''            # strip leading/trailing sep
    $rendered = $rendered -replace '\s{2,}', ' '                                  # normalize spaces

    return $rendered.Trim()
}


#endregion

#region MAIN

# Check if connected to Microsoft Graph
$MgContext = Confirm-GraphConnection -RequiredScopes $GRAPH_SCOPES

# Fetch Conditional Access policies and related objects
$UnfilteredMgPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/policies" -Verbose:$false | Select-Object -ExpandProperty value | Sort-Object -Property createdDateTime
$MgPolicyTemplates = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/templates" -Verbose:$false | Select-Object -ExpandProperty value
$MgLocations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/namedLocations" -Verbose:$false | Select-Object -ExpandProperty value

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
$RecommendedPolicyNames = foreach ($MgPolicy in $MgPolicies) {
    try {

        # Write-Host $MgPolicy.displayName -ForegroundColor Cyan

        # Resolve policy name components
        $Persona = Resolve-CaPersona -Policy $MgPolicy
        $NameComponents = @{
            'SerialNumber'   = Resolve-CaSerialNumber -Policy $MgPolicy -Prefix "$SerialNumberPrefix$($Persona.SerialDigits)"
            'Persona'        = $Persona.Name
            'TargetResource' = Resolve-CaTargetResource -Policy $MgPolicy
            'Platform'       = Resolve-CaPlatform -Policy $MgPolicy
            'Response'       = Resolve-CaResponse -Policy $MgPolicy -NamedLocations $MgLocations
        }

        # Generate recommended policy name
        $RecommendedPolicyName = New-CaPolicyName -Pattern $NamePattern -Context $NameComponents

        # Limit name length to maximum 128 characters
        if ($RecommendedPolicyName.Length -gt 128) {
            $RecommendedPolicyName = $RecommendedPolicyName.Substring(0, 126) + '..'
        }

        # Output resultning object
        [PSCustomObject]@{
            #Id                    = $MgPolicy.id
            CurrentPolicyName     = $MgPolicy.displayName
            RecommendedPolicyName = $RecommendedPolicyName
            NameLength            = $RecommendedPolicyName.Length
            #ComplianceStatus      = 'TODO'
        }   

        if ($MgPolicy.displayName -eq 'DUMP') {
        throw "DUMP POLICY"
    }


    }
    catch {
        $_
        $MgPolicy | ConvertTo-Json -Depth 5
        return 
    }        
}
$RecommendedPolicyNames | Write-Output 
#endregion MAIN