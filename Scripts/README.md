
# Conditional Access Scripts

This directory contains PowerShell scripts for managing Microsoft Entra ID Conditional Access policies via Microsoft Graph.

## Scripts

### Get-ConditionalAccessPolicyNameSuggestion.ps1

Suggests standardized names for Conditional Access policies based on their configuration.

**Requirements:**
- PowerShell 7.4.0 or later
- Microsoft.Graph.Authentication module
- Active Microsoft Graph connection with scopes: `Policy.Read.All`, `Application.Read.All`, `Group.Read.All`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NamePattern` | string | `'{SerialNumber} - {Persona} - {TargetResource} - {Network} - {Condition} - {Response}'` | Pattern for suggested policy names |
| `SerialNumberPrefix` | string | `'CA'` | Prefix for new serial numbers |
| `AllPartsDelimiter` | string | `' and '` | Delimiter for AND logic |
| `AnyPartsDelimiter` | string | `' or '` | Delimiter for OR logic |
| `ExcludePartsDelimiter` | string | `' except '` | Delimiter for exclusions |
| `KeepSerialNumbers` | switch | `$false` | Preserve existing serial numbers |
| `Condense` | switch | `$false` | Convert parts to PascalCase |

**Examples:**

```powershell
# Run with defaults
.\Get-ConditionalAccessPolicyNameSuggestion.ps1

# Condense names and keep existing serial numbers
.\Get-ConditionalAccessPolicyNameSuggestion.ps1 -Condense -KeepSerialNumbers

# Custom name pattern
.\Get-ConditionalAccessPolicyNameSuggestion.ps1 -NamePattern '{SerialNumber} | {Persona} | {TargetResource}'
```

**Output:**

Returns suggested policy names with components:
- **SerialNumber**: Unique identifier (e.g., CA0001)
- **Persona**: User category (Global, Admins, Internals, Externals, Guests, etc.)
- **TargetResource**: Applications or user actions
- **Network**: Named locations or network type
- **Condition**: Risk levels, platforms, client apps
- **Response**: Block or require controls

---

### Import-ConditionalAccessPolicy.ps1

Imports Conditional Access policies exported by EntraExporter into Entra ID.

**Requirements:**
- PowerShell 7.5.0 or later
- Microsoft.Graph module
- Active Microsoft Graph connection with scopes: `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess`, `Application.Read.All`, `Group.ReadWrite.All`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `Path` | string | Yes | Path to EntraExporter output folder |

**Expected Directory Structure:**

```
<Path>/
├── Identity/Conditional/AccessPolicies/   (policy JSON files)
├── Identity/Conditional/NamedLocations/   (location JSON files)
└── Groups/                                 (group JSON files)
```

**Examples:**

```powershell
# Connect to Graph first
Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess, Group.ReadWrite.All, `
    Application.Read.All, Policy.Read.All

# Import policies
.\Import-ConditionalAccessPolicy.ps1 -Path 'C:\temp\EntraExporter\Output'
```

**Features:**

- Creates missing security groups referenced by policies
- Creates named locations (except builtin: 'All', 'AllTrusted')
- Maps exported IDs to newly created/imported IDs
- Adjusts authentication strength object shape
- Handles Continuous Access Evaluation (CAE) report-only restrictions
- Skips policies that already exist

---

## Prerequisites

Install Microsoft Graph PowerShell module:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

Connect to Microsoft Graph before running scripts:

```powershell
Connect-MgGraph -Scopes Policy.Read.All, Policy.ReadWrite.ConditionalAccess, `
    Application.Read.All, Group.ReadWrite.All
```
