
# Conditional Access Migration

This directory contains PowerShell scripts for migrating Conditional Access policies from one tenant to another using Microsoft Graph.

## Scripts

### Import-ConditionalAccessPolicy.ps1

Imports Conditional Access policies into Entra ID.

Before using this script to import the policies into the target tenant, you must to use [EntraExporter](https://github.com/microsoft/EntraExporter) or similar to export the policies and associated groups from the source tenant.

**Requirements:**
- PowerShell 7.5.0 or later
- Microsoft.Graph module
- Active Microsoft Graph connection with scopes: `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess`, `Application.Read.All`, `Group.ReadWrite.All`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `Path` | string | Yes | Path to EntraExporter output folder |

**Expected Directory Structure:**

The import expects the following folders from EntraExporter. These are the standard folders created during export.

```
<Path>/
├── Identity/Conditional/AccessPolicies/   (policy JSON files)
├── Identity/Conditional/NamedLocations/   (location JSON files)
└── Groups/                                (group JSON files)
```

**Examples:**

```powershell
# Connect to Graph first
Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess, Group.ReadWrite.All, Application.Read.All, Policy.Read.All

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
Connect-MgGraph -Scopes Policy.Read.All, Policy.ReadWrite.ConditionalAccess, Application.Read.All, Group.ReadWrite.All
```
