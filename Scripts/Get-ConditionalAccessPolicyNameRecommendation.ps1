<# 
    WIP
#>

#requires -version 7.5.0
[CmdletBinding()]

# Always stop on errors
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Define variables

#region Internal functions

function Test-GraphConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $RequiredScopes
    )

    # Check if Graph module is installed
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host 'Microsoft Graph PowerShell module is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' -ForegroundColor Red
        return $false
    }

    # Check if connected
    $MgContext = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $MgContext) {
        Write-Host "Not connected to Microsoft Graph. Please run Connect-MgGraph -Scopes $($RequiredScopes -join ', ')" -ForegroundColor Red
        return $false
    }

    # Check scopes
    $MissingScopes = $RequiredScopes | Where-Object { $_ -notin $MgContext.Scopes }
    if ($MissingScopes) {
        Write-Host "Missing required Graph scopes: $($MissingScopes -join ', ')" -ForegroundColor Red
        return $false
    }

    Write-Verbose 'Connected to Microsoft Graph with required scopes.'
    return $true
}

#endregion

#region MAIN

# Check if connected to Microsoft Graph
if (-not (Test-GraphConnection -RequiredScopes 'Policy.Read.ConditionalAccess')) { return }

'srudd goest here'