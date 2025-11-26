<#

    I might write a specialized function for this, but at this point, just use EntraExporter

    Install-Module EntraExporter
    Connect-EntraExporter
    Export-Entra -Path .\EntraExporter\ -Type ConditionalAccess,Groups
    Disconnect-MgGraph

#>
Write-Host "This function has not been implemented ." -ForegroundColor Green