<# 
    WIP
#>
[CmdletBinding()]
param(
    # Templates string for the suggested policy names
    [Parameter()]
    [string]
    $PolicyNameTemplate = '<SerialNumber>-<Persona>-<TargetResource>-<Platform>-<Response>',

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
    'All'                                  = 'AllApps' 
    'Office365'                            = 'Office365' 
    'MicrosoftAdminPortals'                = 'AdminPortals' 
    '00000002-0000-0ff1-ce00-000000000000' = 'EXO' 
    '00000003-0000-0ff1-ce00-000000000000' = 'SPO' 
    '00000003-0000-0000-c000-000000000000' = 'MicrosoftGraph' 
    '00000009-0000-0000-c000-000000000000' = 'PowerBI'   
    '0000000a-0000-0000-c000-000000000000' = 'Intune'
    '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Teams'               
    'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'IntuneEnrollment'            
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'AzureResourceManager' 
    '499b84ac-1321-427f-aa17-267ca6975798' = 'AzureDevOps'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'AzureCLI' 
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'AzurePowerShell'
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'AzurePortal'
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'GraphCLI'
    '2793995e-0a7d-40d7-bd35-6968ba142197' = 'MyApps'
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
    'Block'                                    = 'Block'
    'BlockSpecifiedLocations'                  = 'BlockSpecifiedLocations'
    'AllowOnlySpecifiedLocations'              = 'AllowOnlySpecifiedLocations'
    'BlockPlatforms'                           = 'BlockSpecifiedPlatforms'
    'BlockApplications'                        = 'BlockSpecifiedApps'
    'BLockLegacyAuthentication'                = 'BlockLegacyAuth'
    'BlockAuthenticationFlows'                 = 'BlockAuthFlows'
    'MFA'                                      = 'MFA'
    'AuthenticationStrength'                   = 'AuthStrength'
    'ComplientDevice'                          = 'CompliantDevice'
    'AppEnforcedRestrictions'                  = 'AppEnforcedRestrictions'
    'AppProtectionPolicy'                      = 'AppProtectionPolicy'
    'SignInFrequency'                          = 'SignInFrequency'
    'PersistentBrowserNever'                   = 'NeverPersistBrowser'
    'PersistentBrowserAlways'                  = 'AlwaysPersistBrowser'
    'ContinuousAccessEvaluationStrictLocation' = 'StrictLocationCAE'
    'ContinuousAccessEvaluationDisabled'       = 'DisableCAE'
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
    $ExcludeApps = $Policy.conditions.applications.excludeApplications | ForEach-Object {
        if ($CA_APP[$_]) {
            $CA_APP[$_]
        }
        else {
            Write-Warning "Unrecognized Exclude AppId '$_' in policy '$($Policy.displayName)'"
            'UnknownApp'
        }
    }

    # Check for excludes if All apps are included
    if ($Apps -contains $CA_APP['All'] -and $ExcludeApps) {
        return "$($Apps)Except$($ExcludeApps -join $CA_AND_DELIMITER)"
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
        $ExcludePlatforms = $Policy.conditions.platforms?.excludePlatforms
        if ($null -ne $ExcludePlatforms -and $ExcludePlatforms.count -gt 0) {
            $ExcludePlatformsNames = $ExcludePlatforms | ForEach-Object {
                if ($CA_PLATFORM[$_]) {
                    $CA_PLATFORM[$_]
                }
                else {
                    Write-Warning "Unrecognized platform '$_' in policy '$($Policy.displayName)'"
                    'UnknownPlatform'
                }
            }
            return "$($CA_PLATFORM['all'])Except$($ExcludePlatformsNames -join $CA_AND_DELIMITER)"            
        }
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
    $AdditionalDetails = @()

    # Resolve block controls
    if ($Policy.grantControls?.builtInControls -contains 'block') {
        $BlockControls = @()

        # Location-based blocks
        $IncludeLocations = $Policy.conditions.locations?.includeLocations
        $ExcludeLocations = $Policy.conditions.locations?.excludeLocations
        if ($IncludeLocations -and $IncludeLocations -notcontains 'All') {
            $BlockControls += $CA_RESPONSE['BlockSpecifiedLocations']
            $AdditionalDetails += $NamedLocations | Where-Object { $_.id -in $IncludeLocations } | Select-Object -ExpandProperty displayName
        }
        elseif ($ExcludeLocations -and $ExcludeLocations -notcontains 'All') {
            $BlockControls += $CA_RESPONSE['AllowOnlySpecifiedLocations']
            $AdditionalDetails += $NamedLocations | Where-Object { $_.id -in $ExcludeLocations } | Select-Object -ExpandProperty displayName
        }

        # Block legacy authentication  
        if ($Policy.conditions.clientAppTypes -contains 'other' -and $Policy.conditions.clientAppTypes -contains 'exchangeActiveSync') {
            $BlockControls += $CA_RESPONSE['BLockLegacyAuthentication']
        }

        # Block authentication flows
        $TransferMethods = $Policy.conditions | Select-Object -ExpandProperty authenticationFlows -ErrorAction Ignore | Select-Object -ExpandProperty transferMethods -ErrorAction Ignore
        if ($null -ne $TransferMethods -and $TransferMethods.IndexOf('deviceCodeFlow') -ge 0 -and $TransferMethods.Indexof('authenticationTransfer') -ge 0 ) {
            $BlockControls += $CA_RESPONSE['BlockAuthenticationFlows']
        }

        # BLock platforms
        $IncludePlatforms = $Policy.conditions.platforms?.includePlatforms
        if ($IncludePlatforms) {
            $BlockControls += $CA_RESPONSE['BlockPlatforms']
        }

        # Block applications
        $IncludeApps = $Policy.conditions.applications?.includeApplications
        $ExcludeApps = $Policy.conditions.applications?.excludeApplications
        if ($IncludeApps -notcontains 'All' -or ($IncludeApps -contains 'All' -and $ExcludeApps)) {
            $BlockControls += $CA_RESPONSE['BlockApplications']
        }

        # Handle unknown block case
        if ($BlockControls.count -eq 0) {
            throw 'UNKNOWN BLOCK'
            #            $BlockControls += $CA_RESPONSE['Block'] 
        }

        $Controls += $BlockControls
    }

    # Resolve requirement controls
    if ($Policy.grantControls?.builtInControls -contains 'mfa') {
        $Controls += $CA_RESPONSE['mfa']
    }

    $AuthenticationStrength = $Policy.grantControls?.authenticationStrength
    if ($AuthenticationStrength) {
        $Controls += $CA_RESPONSE['AuthenticationStrength']
        $AdditionalDetails += $AuthenticationStrength.displayName
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
        $Controls += $CA_RESPONSE['SignInFrequency']
        if ($SignInFrequency.frequencyInterval -eq 'timeBased') {
            $AdditionalDetails += "$($SignInFrequency.value) $($SignInFrequency.type)"
        }
        elseif ($SignInFrequency.frequencyInterval -eq 'everyTime') {
            $AdditionalDetails += 'Every time'
        }
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

    # Add additional details that is not necessarily tied to a specific type of control
    if ($Policy.conditions?.devices?.deviceFilter) {
        $AdditionalDetails += 'DeviceFilter'
    }

    # Return responses
    if ($Controls.count -gt 0) {
        return [PSCustomObject]@{
            Controls          = $Controls
            AdditionalDetails = $AdditionalDetails
        }
    }

    throw 'UNRESOLVED RESPONSE'
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
            $RecommendedPolicyName = $RecommendedPolicyName -replace '<Response>', $Response.Controls -join $CA_AND_DELIMITER
            if ($AppendAdditionalDetails -and $Response.AdditionalDetails.count -gt 0) {
                $RecommendedPolicyName += "-$($Response.AdditionalDetails -join '-')"
            }
        }
        

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
        $MgPolicy | ConvertTo-Json -Depth 5
        return 
    }        
}

#endregion MAIN