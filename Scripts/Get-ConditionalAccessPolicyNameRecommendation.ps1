<# 
    WIP
#>
[CmdletBinding()]
param(
    # Templates string for the suggested policy names
    [Parameter()]
    [string]
    $PolicyNameTemplate = '<SerialNumber> - <Persona> - <TargetResource> - <Platform> - <Response>',

    # Append additional details to the recommended name
    [Parameter()]
    [boolean]
    $AppendAdditionalDetails = $true
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
    'AllUnknown'   = 'Any unknown platform'
    'Unresolved'   = 'Unresolved platform'
}

$CA_RESPONSE = @{

    # Grant controls - block types
    'Block'                                    = 'Block'
    'BlockLocations'                           = 'Block locations: <Locations>'
    'OnlyAllowLocations'                       = 'Only allow locations: <Locations>'
    'BLockLegacyAuthentication'                = 'Block legacy authentication'
    'BlockAuthenticationFlows'                 = 'Block authentication flows'

    # Grant controls - grant types
    'MFA'                                      = 'Require MFA'
    'AuthenticationStrength'                   = 'Require authentication strength: <AuthStrength>'
    'ComplientDevice'                          = 'Require compliant device'
    #TODO: Hybrid joined
    #TODO: Approved clients apps
    'AppProtectionPolicy'                      = 'Require app protection policy'
    #TODO: Risk remidiation

    # Session controls
    'AppEnforcedRestrictions'                  = 'Use app enforced restrictions'
    #TODO: CA App Control
    'SignInFrequency'                          = 'Sign-in frequency: <SignInFrequency>'
    'PersistentBrowserNever'                   = 'Never persist browser'
    'PersistentBrowserAlways'                  = 'Always persist browser'
    'ContinuousAccessEvaluationStrictLocation' = 'Strict location CAE'
    'ContinuousAccessEvaluationDisabled'       = 'Disable CAE'
    #TODO: Disable resilience defaults
    #TODO: Token protection
    #TODO: Use GSA security profile

    # Unresolved
    'Unresolved'                               = 'Unresolved response'
}

$CA_AND_DELIMITER = ' and '
$CA_OR_DELIMITER = ' or '

#endregion

#region Initialize

$ErrorActionPreference = 'Stop'     # Always stop on errors
Set-StrictMode -Version Latest      # Enforce strict mode

$MgGroupCache = @()                 # Define cache
$SerialNumbersInUse = @()           # Track used serial numbers

#endregion

#region Internal functions

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
        return "$($Apps) except $($ExcludeApps -join $CA_AND_DELIMITER)"
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
            Write-Warning "Unrecognized user action '$_' in policy '$($Policy.displayName)'"
            $CA_USERACTION['Unresolved']
        }
    }
    if ($Actions) {
        return $Actions -join $CA_AND_DELIMITER
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
        Write-Warning "Device filter present in policy '$($Policy.displayName)'. Platform resolution may be inaccurate."
    }

    # If no platforms are specified, all platforms are included
    if ($null -eq $IncludePlatforms -or $IncludePlatforms -contains 'all') {
        $ExcludePlatforms = $Policy.conditions.platforms?.excludePlatforms
        if ($null -ne $ExcludePlatforms -and $ExcludePlatforms.count -gt 0) {
            if ($ExcludePlatforms.count -eq 6) {
                return $CA_PLATFORM['AllUnknown']
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
            return "$($CA_PLATFORM['all']) except $($ExcludePlatformsNames -join $CA_AND_DELIMITER)"            
        }
        return $CA_PLATFORM['all']
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
    return $Platforms -join $CA_AND_DELIMITER
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

    $Controls = @()

    # Resolve block controls which could have additional details
    if ($Policy.grantControls?.builtInControls -contains 'block') {

        # Location-based blocks
        $IncludeLocations = $Policy.conditions.locations?.includeLocations
        $ExcludeLocations = $Policy.conditions.locations?.excludeLocations
        if ($IncludeLocations -and $IncludeLocations -notcontains 'All') {
            $Locations = ($NamedLocations | Where-Object { $_.id -in $IncludeLocations } | Select-Object -ExpandProperty displayName) -join $CA_AND_DELIMITER
            $Controls += $CA_RESPONSE['BlockLocations'].Replace('<Locations>', $Locations)
        }
        elseif ($ExcludeLocations -and $ExcludeLocations -notcontains 'All') {
            $Locations = ($NamedLocations | Where-Object { $_.id -in $ExcludeLocations } | Select-Object -ExpandProperty displayName) -join $CA_AND_DELIMITER
            $Controls += $CA_RESPONSE['OnlyAllowLocations'].Replace('<Locations>', $Locations)
        }

        # Block legacy authentication  
        if ($Policy.conditions.clientAppTypes -contains 'other' -and $Policy.conditions.clientAppTypes -contains 'exchangeActiveSync') {
            $Controls += $CA_RESPONSE['BLockLegacyAuthentication']
        }

        # Block authentication flows
        $TransferMethods = $Policy.conditions | Select-Object -ExpandProperty authenticationFlows -ErrorAction Ignore | Select-Object -ExpandProperty transferMethods -ErrorAction Ignore
        if ($null -ne $TransferMethods -and $TransferMethods.IndexOf('deviceCodeFlow') -ge 0 -and $TransferMethods.Indexof('authenticationTransfer') -ge 0 ) {
            $Controls += $CA_RESPONSE['BlockAuthenticationFlows']
        }

        # Normal block control if no specific block reason found
        if ($Controls.count -eq 0) {
            $Controls = $CA_RESPONSE['Block'] 
        }

        return $Controls -join $CA_AND_DELIMITER
    }

    # Resolve requirement controls
    if ($Policy.grantControls?.builtInControls -contains 'mfa') {
        $Controls += $CA_RESPONSE['mfa']
    }

    $AuthenticationStrength = $Policy.grantControls?.authenticationStrength
    if ($AuthenticationStrength) {
        $Controls += $CA_RESPONSE['AuthenticationStrength'].Replace('<AuthStrength>', $AuthenticationStrength.displayName)
    }

    if ($Policy.grantControls?.builtInControls -contains 'compliantDevice') {
        $Controls += $CA_RESPONSE['ComplientDevice']
    }

    if ($Policy.grantControls?.builtInControls -contains 'compliantApplication') {
        $Controls += $CA_RESPONSE['AppProtectionPolicy']
    }

    # Resolve session controls
    if ($Policy.sessionControls?.applicationEnforcedRestrictions?.isEnabled) {
        $Controls += $CA_RESPONSE['AppEnforcedRestrictions']
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
        $Controls += $CA_RESPONSE['SignInFrequency'].Replace('<SignInFrequency>', $FrequencyText)
    }

    $PersistentBrowser = $Policy.sessionControls?.persistentBrowser
    if ($PersistentBrowser) {
        if ($PersistentBrowser.mode -eq 'never') {
            $Controls += $CA_RESPONSE['PersistentBrowserNever']
        }
        else {
            $Controls += $CA_RESPONSE['PersistentBrowserAlways']             
        }
    }

    $ContinuousAccessEvaluation = $Policy.sessionControls?.continuousAccessEvaluation
    if ($ContinuousAccessEvaluation) {
        if ($ContinuousAccessEvaluation.mode -eq 'strictLocation') {
            $Controls += $CA_RESPONSE['ContinuousAccessEvaluationStrictLocation']
        }
        else {
            $Controls += $CA_RESPONSE['ContinuousAccessEvaluationDisabled']             
        }
    }

    # Return responses
    if ($Controls.count -gt 0) {
        return $Controls
    }
    return $CA_RESPONSE['Unresolved']
}

#endregion

#region MAIN

# Check if connected to Microsoft Graph
$MgContext = Confirm-GraphConnection -RequiredScopes $GRAPH_SCOPES

# Fetch Conditional Access policies and related objects
$UnfilteredMgPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$GRAPH_VERSION/identity/conditionalAccess/policies" -Verbose:$false | Select-Object -ExpandProperty value | Sort-Object -Property displayName
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
    
        if ($RecommendedPolicyName.Contains('<TargetResource>')) {
            $TargetResource = Resolve-CaTargetResource -Policy $MgPolicy
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<TargetResource>', $TargetResource
        }

        if ($RecommendedPolicyName.Contains('<Platform>')) {
            $Platform = Resolve-CaPlatform -Policy $MgPolicy
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Platform>', $Platform
        }

        if ($RecommendedPolicyName.Contains('<Response>')) {
            $Response = Resolve-CaResponse -Policy $MgPolicy -NamedLocations $MgLocations
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Response>', $Response -join $CA_AND_DELIMITER
        }
        
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
    }
    catch {
        $_
        $MgPolicy | ConvertTo-Json -Depth 5
        return 
    }        
}

#endregion MAIN