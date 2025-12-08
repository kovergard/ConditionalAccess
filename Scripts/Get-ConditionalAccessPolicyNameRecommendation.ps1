<# 
    WIP
#>

#requires -version 7.5.0
[CmdletBinding()]

# Always stop on errors
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Define variables
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
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
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
        try {
            $SpLookup = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'"
            return $SpLookup.value.displayName
        }
        catch {
            return 'Unknown app'
        }        
    }

    # Resolve user action
    if ($Applications.includeUserActions) {
        if ($Applications.includeUserActions -contains 'urn:user:registerdevice' ) {
            return 'Register or join device'
        }
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

    # Resolve grant controls
    $GrantControls = $Policy | Select-Object -ExpandProperty grantControls
    $BuiltInControls = $GrantControls | Select-Object -ExpandProperty builtInControls
    if ($BuiltInControls) {
        if ($BuiltInControls -contains 'block') {
            return 'Block Access'
        }
        if ($BuiltInControls -contains 'mfa') {
            return 'Require MFA'
        }
        if ($BuiltInControls -contains 'compliantApplication') {
            return 'Require App Protection Policy'
        }
    }
    $AuthenticationStrength = $GrantControls | Select-Object -ExpandProperty authenticationStrength
    if ($AuthenticationStrength) {
        return "Authentication Stength '$($AuthenticationStrength.displayName)'"
    }



    # Resolve session controls
    $SessionControls = $Policy | Select-Object -ExpandProperty sessionControls
    $ApplicationEnforcedRestrictions = $SessionControls | Select-Object -ExpandProperty applicationEnforcedRestrictions
    if ($ApplicationEnforcedRestrictions) {
        if ($ApplicationEnforcedRestrictions.isEnabled) {
            return 'Use App Enforced Restrictions'
        }
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
    else {
        return 'Specific Users'
    }

}

#endregion

#region MAIN

# Check if connected to Microsoft Graph
$MgContext = Confirm-GraphConnection -RequiredScopes 'Policy.Read.All', 'Application.Read.All'

$MgPolicies = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' | Select-Object -ExpandProperty value # | Sort-Object -Property displayName
#$MgPolicies[0] | ConvertTo-Json -Depth 4
#throw 'STOP'
foreach ($MgPolicy in $MgPolicies) {
    try {
        if ($MgPolicy.templateId) {
            Write-Verbose "Skipping Microsoft-managed policy '$($MgPolicy.displayName)'"
            continue
        }
        Write-Host $MgPolicy.displayName -ForegroundColor Green
        #$SerialNumber = Resolve-CaSerialNumber -Policy $MgPolicy
        $SerialNumber = 'CA123'
        $CloudApp = Resolve-CaApplication -Policy $MgPolicy
        $Response = Resolve-CaResponse -Policy $MgPolicy
        $Principal = Resolve-CaPrincipal -Policy $MgPolicy
        $Conditions = 'SOME CONDITIONS'

        $RecommendedPolicyName = $PolicyNameTemplate -replace '<SerialNumber>', $SerialNumber -replace '<CloudApp>', $CloudApp -replace '<Response>', $Response -replace '<Principal>', $Principal -replace '<Conditions>', $Conditions

        [PSCustomObject]@{
            #Id                    = $MgPolicy.id
            #CurrentPolicyName     = $MgPolicy.displayName
            RecommendedPolicyName = $RecommendedPolicyName
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