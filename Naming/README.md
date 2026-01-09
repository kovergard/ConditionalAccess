# Conditional Access Naming

Ensuring that Conditional Access policies have names that reflects their purpose can take a lot of time, clicking around in the web portal.

This folder contains scripts to make this easier.

## Get-ConditionalAccessPolicyNameSuggestion.ps1

This script provides suggestions for Conditional Access policy names by looking at the content of the policy.

Since it only makes suggestions, only Graph read permissions are needed.

### Requirements

The following must be in place before executing the script.
- PowerShell 7.4.0 or later
- Microsoft.Graph.Authentication module
- An active Microsoft Graph connection with scopes: `Policy.Read.All`, `Application.Read.All`, `Group.Read.All`

### Parameters

The script can be run without any parameters, which will produce names based on a standard pattern. But you can modify the content in the name by using the parameters. See examples below for different modifications.

| Parameter               | Type   | Default                                                                                  | Description                        |
| ----------------------- | ------ | ---------------------------------------------------------------------------------------- | ---------------------------------- |
| `NamePattern`           | string | `'{SerialNumber} - {Persona} - {TargetResource} - {Network} - {Condition} - {Response}'` | Pattern for suggested policy names |
| `SerialNumberPrefix`    | string | `'CA'`                                                                                   | Prefix for new serial numbers      |
| `AllPartsDelimiter`     | string | `' and '`                                                                                | Delimiter for AND logic            |
| `AnyPartsDelimiter`     | string | `' or '`                                                                                 | Delimiter for OR logic             |
| `ExcludePartsDelimiter` | string | `' except '`                                                                             | Delimiter for exclusions           |
| `KeepSerialNumbers`     | switch | `$false`                                                                                 | Preserve existing serial numbers   |
| `Condense`              | switch | `$false`                                                                                 | Convert parts to PascalCase        |

### Name pattern components

The following components can be used in the name pattern. You do not have to use them all - if you dont wan't serial numbers, simply omit it from the `-NamePattern` parameter.

**Please note:** Settings related to Global Secure Access is not yet resolved.

---

**SerialNumber**

A recommended unique identifier for the policy. This makes it easier to identify specific policies during implementation and troubleshooting, instead of matching a long a complex name. 

By default, serial numbers are generated using `CA{PersonaSerialNumber}{Counter}`, so the first policy in the Admin persona would have the serial number CA0101.

The "CA" prefix can be changed using the `-SerialNumberPrefix` parameter.

---

**Persona**

The persona component uses definitions from the [Conditional Access Guidance for Zero Trust](https://github.com/microsoft/ConditionalAccessforZeroTrustResources) repository. Further explanation of the persona concept can be found there.

If possible, the script matches a policy to a persona using an Entra ID group with a name matching `CA-Persona-{PersonaName}`. If such a group is not found, the policy will be assigned to a persona based on the criteria in the Backup Match column.

If you want to use other groups, you will have to edit the `$CA_PERSONA` variable directly in the script.

| Persona                     | Serial | Entra ID Group Name                    | Backup Match      | Description                                                                                   |
| --------------------------- | ------ | -------------------------------------- | ----------------- | --------------------------------------------------------------------------------------------- |
| Global                      | 00     | CA-Persona-Global                      | All users         | Global is used for policies that should apply across all personas, unless explicitly excluded |
| Admins                      | 01     | CA-Persona-Admins                      | All roles         | All non-guest accounts that have privileged access                                            |
| Internals                   | 02     | CA-Persona-Internals                   |                   | Internal non-admin employee accounts, except developers                                       |
| Externals                   | 03     | CA-Persona-Externals                   |                   | External users with an internal non-admin account, like consultants and similar               |
| Guests                      | 04     | CA-Persona-Guests                      | All guests        | All non-admin guest accounts                                                                  |
| GuestAdmins                 | 05     | CA-Persona-GuestAdmins                 |                   | All admin guest accounts                                                                      |
| Microsoft365ServiceAccounts | 06     | CA-Persona-Microsoft365ServiceAccounts |                   | Cloud-native user-based service accounts used to access Microsoft 365 services                |
| AzureServiceAccounts        | 07     | CA-Persona-AzureServiceAccounts        |                   | Cloud-native user-based service accounts used to access  Microsoft Azure (IaaS/PaaS) services |
| CorpServiceAccounts         | 08     | CA-Persona-CorpServiceAccounts         |                   | Service account synchronized from on-premises AD used to access Azure/M365. Should be avoided |
| WorkloadIdentities          | 09     | CA-Persona-WorkloadIdentities          |                   | Entra ID service principals and managed identities                                            |
| Developers                  | 10     | CA-Persona-Developers                  |                   | Internal or external developers                                                               |
| Agents                      | 11     | CA-Persona-Agents                      | All agents        | AI Agents                                                                                     |

---

**TargetResource**

Contain application names ('All apps', 'Office 365' and similar) or user actions ('Register or join device' or 'Register security info').

Application names are resolved using the `$CA_APP` table, so additional applications can be added there if necessary.

---

**Network**

Contains the name of the network defined in the policy (or 'Any network' if not defined). 

Named locations will be shown using their display name.

---

**Condition**

Contain risks, platforms, client apps, device filters and authentication flows as defined on the Conditions section of the policy.

Device filters are stored as strings in Graph, and is thus difficult to parse, a simple 'Device filters applied' text will be inserted if device filters has been used.

Network is not included here, as it has been moved it a dedicated component.

---

**Response**

This combines the different settings under the Access controls section - both Grant and Session controls.

Depending on the policy, the response can range from a simple 'Block' to longer responses like 'Require MFA and password change and Sign-in frequency Every time'.

---

### Examples

```powershell
# Connect to MS Graph 
Connect-MgGraph -Scopes Policy.Read.All,Application.Read.All,Group.Read.All

# Run with default options.
.\Get-ConditionalAccessPolicyNameSuggestion.ps1
```
![image](./images/NameSuggestion-Default.png)

The default name pattern uses serial numbers and personas from the Conditional Access Guidance for Zero Trust framework.

Notice that the serial number is kept for `CA0315: Require TOU for consultants accessing SharePoint` since it matches the right persona group and format. However, the `CA11 - Allow login without MFA from Factories` policy is assigned a new serial number, since it is not the right length.

```powershell
# Condense components and keep existing serial numbers
.\Get-ConditionalAccessPolicyNameSuggestion.ps1 -Condense -KeepSerialNumbers
```

![image](./images/NameSuggestion-Condense-KeepSerial.png)

The `-Condense` switch removes all spacing and special characters inside each component, and converts the component to PascalCase string like `RequireMfaOrCompliantDeviceOrHybridJoinedDevice`.

Note that `CA11 - Allow login without MFA from Factories` keeps its serial number, even if it doesn't match the right format. This is because of the `-KeepSerialNumbers` switch.

```powershell
# Compact name pattern
.\Get-ConditionalAccessPolicyNameSuggestion.ps1 -NamePattern '{SerialNumber}-{Persona}-{TargetResource}-{Network}-{Condition}-{Response}' -Condense
```
![image](./images/NameSuggestion-CustomCondensed.png)

The combination of the `-NamePattern` parameter and the `-Condense` switch makes for a single long string without any spaces or special characters apart from the dash separating the components. 

```powershell
# Another custom name pattern
.\Get-ConditionalAccessPolicyNameSuggestion.ps1 -NamePattern '{SerialNumber} - {TargetResource}: {Response} For {Persona} On {Network} When {Condition}'
```

![image](./images/NameSuggestion-CustomMicrosoft.png)

The use `-NamePattern` here makes for names that are akin to what is currently recommended on [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access#set-naming-standards-for-your-policies).

### Ideas for future improvements

* Add an option to use Entra ID group names instead of personas in the suggested name.
* Make it possible to modify groups for `$CA_PERSONA` without editing the script directly.
* Create a fallback resolution of applications names using Graph, if the application is not in the `$CA_APP` table
* Add resolution of Global Secure Access settings


---

