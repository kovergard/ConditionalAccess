
# Conditional Access Naming

This directory contains PowerShell scripts for handling naming of Conditional Access policies.

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

