<#
.SYNOPSIS
Short description
.DESCRIPTION
Long description
.EXAMPLE
Example of how to use this cmdlet
.EXAMPLE
Another example of how to use this cmdlet
.INPUTS
Inputs to this cmdlet (if any)
.OUTPUTS
Output from this cmdlet (if any)
.NOTES
General notes
.COMPONENT
The component this cmdlet belongs to
.ROLE
The role this cmdlet belongs to
.FUNCTIONALITY
The functionality that best describes this cmdlet
#>
#requires -version 7.5.0
[CmdletBinding()]
param (
    # Path to the folder with output from EntraExporter
    [Parameter(Mandatory)]
    [string]
    $Path
)

# Always stop on errors
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Define variables
$NeededScopes = "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All", "Group.ReadWrite.All"
$CaChildPath = "Identity\Conditional\AccessPolicies"

# Ensure that Microsoft.Graph is available
if (-not (Get-InstalledModule -Name Microsoft.Graph -ErrorAction SilentlyContinue)) {
    Write-Warning "This script uses the Microsoft.Graph module. Please make sure it is installed."
    return
}

# Ensure a Graph connection exists with the right permissions
$MgContext = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $MgContext) {
    Write-Warning "Please run Connect-MgGraph before running this script."
    return
}
$MissingScopes = Compare-Object -ReferenceObject $MgContext.Scopes -DifferenceObject $NeededScopes | Where-Object {$_.SideIndicator -eq '=>'} | Select-Object -ExpandProperty InputObject
if ($MissingScopes) {
    Write-Warning "Missing the following scopes in Graph: $($MissingScopes -join ', ')"
    return
}

# Import Conditional Access JSON files exported by EntraExporter
$CaJsonPath = Join-Path -Path $Path -ChildPath $CaChildPath -ErrorAction SilentlyContinue
$CaJsonFiles = Get-ChildItem -Path $CaJsonPath -Filter '*.json' -File -Recurse
$CaPolicies = $CaJsonFiles | ForEach-Object {
    try {
        Get-Content -Path $_.FullName | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not import JSON from file $_.FullName. "
    }
}
if ($null -eq $CaPolicies)
{
    Write-Warning "No policies could be imported from $CaJsonPath"
    return
}
Write-Host "Found $($CaPolicies.count) Conditional Access policies in $CaJsonPath" -ForegroundColor Green

# Get names of existing Conditional Access policies
$ExistingCaPolicyNames = @(Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' | Select-Object -ExpandProperty value | Select-Object -ExpandProperty displayName)
$ExistingCaPolicies = Compare-Object -ReferenceObject $ExistingCaPolicyNames -DifferenceObject $CaPolicies.displayName | Where-Object {$_.SideIndicator -eq '=='} | Select-Object -ExpandProperty InputObject
if ($ExistingCaPolicies) {
    Write-Host "The following Conditional Access policies already exists, and will be skipped during import:"
    $ExistingCaPolicies | ForEach-Object {
        Write-Host " - $_"
    }
    $CaPolicies = $CaPolicies | Where-Object {$_.displayName -notin $ExistingCaPolicyNames}
}
Write-Host "Importing $($CaPolicies.count) Conditional Access policies" -ForegroundColor Green

