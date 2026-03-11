<#
.SYNOPSIS
  Deploy persona-based Conditional Access policies with automatic placeholder resolution.

.DESCRIPTION
  - Identifies {{placeholders}} in policy JSON files (. \Policies\**\*.json)
  - Ensures all {GroupId_*} placeholders have corresponding .\Groups\*.json, creates or reuses Entra ID groups, and resolves IDs
  - Ensures all {NamedLocationId_*} placeholders have corresponding .\Locations\*.json, creates or reuses Named Locations, and resolves IDs
  - Replaces placeholders in policy JSON and creates CA policies if not already present (by displayName)

.PREREQUISITES
  Connect-MgGraph must have been run with appropriate scopes:
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Directory.ReadWrite.All"

.PARAMETER PoliciesRoot
  Root folder containing policy JSON files (recursively). Default: .\Policies

.PARAMETER GroupsRoot
  Folder containing group JSON files. Default: .\Groups

.PARAMETER LocationsRoot
  Folder containing named location JSON files. Default: .\Locations
#>

param(
    [string]$PoliciesRoot = '.\Policies',
    [string]$GroupsRoot = '.\Groups',
    [string]$LocationsRoot = '.\Locations'
)

# -------- Helpers --------

function Write-Info { param([string]$m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Warn { param([string]$m) Write-Warning $m }
function Write-Err { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

# Generic Graph wrapper using Invoke-MgGraphRequest (approved verb)
function Invoke-GraphJson {
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')] [string]$Method,
        [Parameter(Mandatory = $true)] [string]$Uri,
        [Parameter(Mandatory = $false)] [object]$Body
    )
    if ($PSBoundParameters.ContainsKey('Body')) {
        return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 50) -ContentType 'application/json' -OutputType PSObject
    }
    else {
        return Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType PSObject
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { throw "File not found: $Path" }
    Get-Content -Path $Path -Raw | ConvertFrom-Json
}

function Read-TextFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { throw "File not found: $Path" }
    Get-Content -Path $Path -Raw
}

function Resolve-GroupId {
    param([Parameter(Mandatory = $true)][string]$GroupJsonPath)
    $groupObj = Read-JsonFile -Path $GroupJsonPath
    if (-not $groupObj.displayName) { throw "Group JSON missing 'displayName': $GroupJsonPath" }

    $safeName = $groupObj.displayName.Replace("'", "''")
    $existing = Invoke-GraphJson -Method GET -Uri "/v1.0/groups`?$select=id,displayName&`$filter=displayName eq '$safeName'"
    if ($existing.value -and $existing.value.Count -ge 1) {
        $match = $existing.value | Where-Object { $_.displayName -eq $groupObj.displayName } | Select-Object -First 1
        if ($match) {
            Write-Info "Group exists: '$($groupObj.displayName)' → $($match.id)"
            return $match.id
        }
    }

    Write-Info "Creating group: '$($groupObj.displayName)'"
    $created = Invoke-GraphJson -Method POST -Uri '/v1.0/groups' -Body $groupObj
    if (-not $created.id) { throw "Failed to create group: $($groupObj.displayName)" }
    Write-Info "Created group: '$($groupObj.displayName)' → $($created.id)"
    return $created.id
}

function Resolve-NamedLocationId {
    param([Parameter(Mandatory = $true)][string]$LocationJsonPath)
    $locObj = Read-JsonFile -Path $LocationJsonPath
    if (-not $locObj.displayName) { throw "Location JSON missing 'displayName': $LocationJsonPath" }
    if (-not $locObj.'@odata.type') { throw "Location JSON missing '@odata.type' (e.g., #microsoft.graph.ipNamedLocation): $LocationJsonPath" }

    $all = Invoke-GraphJson -Method GET -Uri '/v1.0/identity/conditionalAccess/namedLocations'
    $existing = $all.value | Where-Object { $_.displayName -eq $locObj.displayName } | Select-Object -First 1
    if ($existing) {
        Write-Info "Named location exists: '$($locObj.displayName)' → $($existing.id)"
        return $existing.id
    }

    Write-Info "Creating named location: '$($locObj.displayName)'"
    $created = Invoke-GraphJson -Method POST -Uri '/v1.0/identity/conditionalAccess/namedLocations' -Body $locObj
    if (-not $created.id) { throw "Failed to create named location: $($locObj.displayName)" }
    Write-Info "Created named location: '$($locObj.displayName)' → $($created.id)"
    return $created.id
}

# --- RENAMED to approved verb: Update ---
function Update-JsonWithPlaceholders {
    param(
        [Parameter(Mandatory = $true)][string]$JsonText,
        [Parameter(Mandatory = $true)][hashtable]$ReplacementMap
    )
    $out = $JsonText
    foreach ($k in $ReplacementMap.Keys) {
        # Replace {{Token}} with actual value
        $token = "{{${k}}}"
        $out = $out -replace [regex]::Escape($token), $ReplacementMap[$k]
    }
    return $out
}

# --- RENAMED to approved verb: New ---
function New-CaPolicyIfAbsent {
    param([Parameter(Mandatory = $true)][psobject]$PolicyObject)

    if (-not $PolicyObject.displayName) { throw "Policy object missing 'displayName'." }

    if (-not $script:ExistingPolicies) {
        $script:ExistingPolicies = @()
        $page = Invoke-GraphJson -Method GET -Uri "/v1.0/identity/conditionalAccess/policies?$select=id,displayName"
        $script:ExistingPolicies += $page.value
        while ($page.'@odata.nextLink') {
            $page = Invoke-GraphJson -Method GET -Uri $page.'@odata.nextLink'
            $script:ExistingPolicies += $page.value
        }
    }

    $already = $script:ExistingPolicies | Where-Object { $_.displayName -eq $PolicyObject.displayName } | Select-Object -First 1
    if ($already) {
        Write-Info "Policy already exists, skipping: '$($PolicyObject.displayName)' (Id: $($already.id))"
        return $already.id
    }

    Write-Info "Creating policy: '$($PolicyObject.displayName)'"
    $PolicyObject.PSObject.Properties.Remove('id')
    $PolicyObject.PSObject.Properties.Remove('createdDateTime')
    $PolicyObject.PSObject.Properties.Remove('modifiedDateTime')
    $PolicyObject.PSObject.Properties.Remove('deletedDateTime')

    $PolicyObject | ConvertTo-Json -Depth 4 | Write-Host -ForegroundColor Gray
#    throw "FULL STOP"

    $created = Invoke-GraphJson -Method POST -Uri '/v1.0/identity/conditionalAccess/policies' -Body $PolicyObject
    if (-not $created.id) { throw "Failed to create policy: $($PolicyObject.displayName)" }

    $script:ExistingPolicies += [pscustomobject]@{ id = $created.id; displayName = $created.displayName }
    Write-Info "Created policy: '$($created.displayName)' → $($created.id)"
    return $created.id
}

# -------- Main --------

$placeholderPattern = '\{\{([A-Za-z0-9_]+)\}\}'

if (-not (Test-Path $PoliciesRoot)) { throw "Policies root not found: $PoliciesRoot" }
if (-not (Test-Path $GroupsRoot)) { Write-Warn "Groups root not found: $GroupsRoot (group creation will fail for placeholders needing files)"; }
if (-not (Test-Path $LocationsRoot)) { Write-Warn "Locations root not found: $LocationsRoot (location creation will fail for placeholders needing files)"; }

Write-Info "Scanning policies in '$PoliciesRoot' for placeholders…"
$policyFiles = Get-ChildItem -Path $PoliciesRoot -Filter *.json -Recurse | Sort-Object FullName
if (-not $policyFiles) { throw "No policy JSON files found under $PoliciesRoot" }

$allPlaceholders = [System.Collections.Generic.HashSet[string]]::new()
$policyTextMap = @{}
foreach ($pf in $policyFiles) {
    $txt = Read-TextFile -Path $pf.FullName
    $policyTextMap[$pf.FullName] = $txt
    $phMatches = [regex]::Matches($txt, $placeholderPattern)
    foreach ($m in $phMatches) { $null = $allPlaceholders.Add($m.Groups[1].Value) }
}
Write-Info ('Found {0} unique placeholders' -f $allPlaceholders.Count)

$groupTokens = $allPlaceholders.Where({ $_ -like 'GroupId_*' })
$locationTokens = $allPlaceholders.Where({ $_ -like 'NamedLocationId_*' })

Write-Info ('Group placeholders: {0}' -f ($groupTokens -join ', '))
Write-Info ('Location placeholders: {0}' -f ($locationTokens -join ', '))

$missingGroupFiles = @()
$missingLocationFiles = @()
$groupTokenToFile = @{}
foreach ($gt in $groupTokens) {
    $name = $gt -replace '^GroupId_', ''
    $path = Join-Path $GroupsRoot "$name.json"
    if (-not (Test-Path $path)) { $missingGroupFiles += $path } else { $groupTokenToFile[$gt] = $path }
}
$locationTokenToFile = @{}
foreach ($lt in $locationTokens) {
    $name = $lt -replace '^NamedLocationId_', ''
    $path = Join-Path $LocationsRoot "$name.json"
    if (-not (Test-Path $path)) { $missingLocationFiles += $path } else { $locationTokenToFile[$lt] = $path }
}

if ($missingGroupFiles.Count -or $missingLocationFiles.Count) {
    Write-Err 'Missing definition files:'
    if ($missingGroupFiles.Count) {
        Write-Host '  Groups:' -ForegroundColor Yellow
        $missingGroupFiles | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    }
    if ($missingLocationFiles.Count) {
        Write-Host '  Locations:' -ForegroundColor Yellow
        $missingLocationFiles | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    }
    throw 'Aborting due to missing group/location definition files.'
}

$replacementMap = @{}
foreach ($gt in $groupTokens) {
    $gid = Resolve-GroupId -GroupJsonPath $groupTokenToFile[$gt]
    $replacementMap[$gt] = $gid
}
foreach ($lt in $locationTokens) {
    $lid = Resolve-NamedLocationId -LocationJsonPath $locationTokenToFile[$lt]
    $replacementMap[$lt] = $lid
}

foreach ($pf in $policyFiles) {
    Write-Info "Processing policy file: $($pf.FullName)"
    $raw = $policyTextMap[$pf.FullName]

    # Updated function name here
    $patched = Update-JsonWithPlaceholders -JsonText $raw -ReplacementMap $replacementMap

    try { $polObj = $patched | ConvertFrom-Json -Depth 50 }
    catch { Write-Err "Invalid JSON after replacement in file: $($pf.FullName)"; throw }

    if (-not $polObj.displayName) {
        Write-Err "Policy JSON lacks 'displayName' after replacement: $($pf.FullName)"
        continue
    }

    # Updated function name here
    New-CaPolicyIfAbsent -PolicyObject $polObj | Out-Null
}

Write-Host "`nDeployment complete." -ForegroundColor Green