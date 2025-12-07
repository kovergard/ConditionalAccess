<# 
    WIP
#>

#requires -version 7.5.0
[CmdletBinding()]

# Always stop on errors
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Define variables
$PolicyNameTemplate = '<SN> - <CloudApp>: <Response> For <Principal> When <Conditions>'


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

    # Determine cloud app
    if ($Applications.includeApplications) {
        $AppId = $Applications.includeApplications
        if ($AppId -contains 'All') {
            return 'All cloud apps'
        }
        elseif ($AppId.count -gt 1) {
            return 'Multiple apps'
        }
        else {
            try {
                $SpLookup = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'"
                return $SpLookup.value.displayName
            }
            catch {
                return 'Unknown app'
            }        
        }
    }

    # Determine user action
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

    if ($Policy.grantControls.builtInControls -contains 'block') {
        return 'Block Access'
    }
    if ($Policy.grantControls.builtInControls -contains 'mfa') {
        return 'Require MFA'
    }
    else {
        return 'Other Control'
    }

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

$MaxPoliciesToProcess = 100

Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' | Select-Object -ExpandProperty value | ForEach-Object {
    if ($MaxPoliciesToProcess -gt 0) {
        try {
            $Policy = $_
            # $Policy | ConvertTo-Json -Depth 4

            $CloudApp = Resolve-CaApplication -Policy $Policy
            $Response = Resolve-CaResponse -Policy $Policy
            $Principal = Resolve-CaPrincipal -Policy $Policy
            $Conditions = 'SOME CONDITIONS'

            $RecommendedPolicyName = $PolicyNameTemplate -replace '<SN>', 'CAxx' -replace '<CloudApp>', $CloudApp -replace '<Response>', $Response -replace '<Principal>', $Principal -replace '<Conditions>', $Conditions

            <#
        `
            -replace '<SN>', ($Policy.displayName -split ' - ')[0] `
            -replace '<MFA' } else { 'Other Control' }) `
            -replace '<Pricipal>', (if ($Policy.conditions.users.includeRoles) { 'Admins' } else { 'Users' }) `
            -replace '<Conditions>', (if ($Policy.conditions.clientAppTypes -contains 'all') { 'All client apps' } else { ($Policy.conditions.clientAppTypes -join ', ') })
#>
            [PSCustomObject]@{
                CurrentPolicyName     = $Policy.displayName
                RecommendedPolicyName = $RecommendedPolicyName
                ComplianceStatus      = 'TODO'
            }
            
        }
        catch {
            $_
            $Policy | ConvertTo-Json -Depth 4
            throw 'STOP'
            
        }        
    
        $MaxPoliciesToProcess--
    }
}


<#>
{
  "id": "e21a7b5e-c28a-4bc8-8b39-4d1b37342134",
  "sessionControls": null,
  "templateId": "c7503427-338e-4c5e-902d-abe252abfb43",
  "state": "enabled",
  "conditions": {
    "insiderRiskLevels": null,
    "signInRiskLevels": [],
    "devices": null,
    "locations": null,
    "userRiskLevels": [],
    "applications": {
      "applicationFilter": null,
      "excludeApplications": [],
      "includeUserActions": [],
      "includeAuthenticationContextClassReferences": [],
      "includeApplications": [
        "All"
      ]
    },
    "authenticationFlows": null,
    "clientAppTypes": [
      "all"
    ],
    "clientApplications": null,
    "platforms": null,
    "users": {
      "includeGroups": [],
      "excludeRoles": [],
      "excludeGuestsOrExternalUsers": null,
      "includeUsers": [],
      "excludeUsers": [
        "d6b47455-b4ff-4cbe-85a9-66eb1242c5fb"
      ],
      "includeGuestsOrExternalUsers": null,
      "includeRoles": [
        "62e90394-69f5-4237-9190-012177145e10",
        "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
        "29232cdf-9323-42fd-ade2-1d097af3e4de",
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",
        "fe930be7-5e62-47db-91af-98c3a49a38b1",
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
        "158c047a-c907-4556-b7ef-446551a6b5f7",
        "966707d0-3269-4727-9be2-8c3a10f19b9d",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
        "e8611ab8-c189-46e8-94e1-60213ab1f814"
      ],
      "excludeGroups": []
    },
    "servicePrincipalRiskLevels": []
  },
  "displayName": "Require multifactor authentication for admins",
  "grantControls": {
    "termsOfUse": [],
    "authenticationStrength": null,
    "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('e21a7b5e-c28a-4bc8-8b39-4d1b37342134')/grantControls/authenticationStrength/$entity",
    "builtInControls": [
      "mfa"
    ],
    "operator": "OR",
    "customAuthenticationFactors": []
  },
  "createdDateTime": "2025-12-02T13:33:40.5769848Z",
  "modifiedDateTime": null
}
#>