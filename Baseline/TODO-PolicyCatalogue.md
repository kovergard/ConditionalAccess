# Conditional Access Policy Catalogue

This document lists all Conditional Access (CA) policies in this repository, their intent, and their role in the overall design.

Policy names are authoritative and follow the naming grammar:

`CA{Serial}-{Persona}-{Scope}-{Condition}-{Control}`

***

## CA0xx – Global (Baseline Invariants)

> Foundational protections that apply to nearly all users.  
> These policies establish minimum security guarantees and are intentionally simple and stable.

| Policy                                                      | Intent                                                                                               |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **CA000-Global-AllApps-Always-RequireMfa**                  | Baseline MFA requirement for all users. Serves as the global “seatbelt” and last‑resort safety net.  |
| **CA010-Global-AllApps-Always-BlockLegacyAuth**             | Blocks legacy authentication protocols (basic auth). Prevents MFA bypass and password spray attacks. |
| **CA020-Global-AllApps-HighRiskSignIn-Block**               | Blocks sign-ins flagged as **high sign-in risk** by Entra ID Identity Protection.                    |
| **CA030-Global-AllApps-HighUserRisk-RequirePasswordChange** | Forces password change for users flagged as **high user risk** (compromised identity remediation).   |

***

## CA1xx – Admin (Privileged Internal Admins)

> Role‑based guardrails that protect **all privileged roles**, regardless of persona group assignment.  
> These policies must never be removed or weakened.

| Policy                                                          | Intent                                                                                     |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| **CA100-Admin-AllApps-Always-RequireMfa**                       | Baseline MFA requirement for all privileged roles. Ensures no admin operates without MFA.  |
| **CA110-Admin-AdminPortals-Always-RequireStrongAuth**           | Requires **Authentication Strength (MFA)** for access to Microsoft admin portals.          |
| **CA120-Admin-PimActivation-Always-RequireStrongAuth**          | Enforces strong authentication during **PIM role activation**.                             |
| **CA130-Admin-AdminPortals-Always-RequirePhishingResistantMfa** | Target state: admin portals require **phishing‑resistant MFA**.                            |
| **CA140-Admin-AdminPortals-Always-ShortSession**                | Reduces token lifetime for admin portals (short sign‑in frequency, no persistent browser). |
| **CA150-Admin-AdminPortals-Always-RequireTokenProtection**      | Future‑facing control to mitigate token theft and replay using token protection.           |

***

## CA2xx – KnowledgeWorker (Internal Users)

> Default internal user posture.  
> Builds on Global by adding device trust and providing a path to stronger authentication over time.

| Policy                                                 | Intent                                                                                         |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| **CA200-KnowledgeWorker-AllApps-Always-RequireMfa**    | Persona‑level MFA anchor for internal users, allowing future divergence from Global if needed. |
| **CA210-KnowledgeWorker-M365-CompliantDevice-Require** | Requires **compliant devices** for Microsoft 365 workloads.                                    |
| **CA220-KnowledgeWorker-AllApps-HighRiskSignIn-Block** | Blocks high‑risk sign‑ins for Knowledge Workers (persona‑scoped anchor).                       |
| **CA230-KnowledgeWorker-M365-RequireStrongAuth**       | Planned upgrade: require **Authentication Strength (MFA)** for M365 access.                    |
| **CA240-KnowledgeWorker-M365-ShortSession**            | Optional hardening: shorter browser sessions for M365.                                         |

***

## CA3xx – Production (Frontline / Blue‑Collar)

> Users in constrained environments where MFA may be weak or absent.  
> Security is enforced through **environmental controls**: location, device, and app scope.

| Policy                                               | Intent                                                                                          |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **CA300-Production-AllApps-AllowedLocationsOnly**    | Blocks Production sign-ins from all locations except approved named locations.                  |
| **CA310-Production-ApprovedApps-Only**               | Restricts Production users to an explicit allowlist of approved applications.                   |
| **CA320-Production-AllApps-CompliantDevice-Require** | Requires compliant devices for Production access.                                               |
| **CA330-Production-AllApps-RequireHybridJoined**     | Fallback path allowing **Hybrid Azure AD joined** devices when compliance is not yet universal. |
| **CA340-Production-AllApps-Always-SessionLeniency**  | Optional session leniency (longer sessions, persistent browser) for constrained environments.   |

***

## CA4xx – ExternalUser (Guests / Partners)

> Non‑employee identities with unmanaged devices and external identity lifecycle.  
> Access is tightly scoped and admin surfaces are blocked by default.

| Policy                                                  | Intent                                                                     |
| ------------------------------------------------------- | -------------------------------------------------------------------------- |
| **CA400-ExternalUser-AllApps-Always-RequireMfa**        | Requires MFA for all guest sign-ins.                                       |
| **CA410-ExternalUser-AdminPortals-Always-Block**        | Blocks guest access to Microsoft admin portals by default.                 |
| **CA420-ExternalUser-AllApps-HighRiskSignIn-Block**     | Blocks high‑risk sign-ins for external users.                              |
| **CA430-ExternalUser-M365-BrowserOnly**                 | Optional shaping: allow M365 access via browser only (paired with CA431).  |
| **CA431-ExternalUser-M365-NonBrowser-Block**            | Companion policy blocking non‑browser M365 access for guests.              |
| **CA440-ExternalUser-ApprovedApps-Only**                | Strict allowlist: guests can access only explicitly approved applications. |
| **CA450-ExternalUser-AllApps-Always-RequireTermsOfUse** | Optional enforcement of Terms of Use for external users.                   |

***

## CA5xx – ExternalAdmin (Privileged External Users)

> External administrators with privileged access but weaker governance.  
> These policies **add hardening** on top of CA1xx without affecting internal admins.

| Policy                                                                   | Intent                                                                          |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| **CA500-ExternalAdmin-AdminPortals-Always-RequireStrongAuth**            | Requires Authentication Strength (MFA) for external admins at admin portals.    |
| **CA510-ExternalAdmin-PimActivation-Always-RequirePhishingResistantMfa** | Requires phishing‑resistant MFA during PIM role activation for external admins. |
| **CA520-ExternalAdmin-AdminPortals-Always-ShortSession**                 | Short session lifetime for external admin portal access.                        |
| **CA530-ExternalAdmin-AdminPortals-Always-RequirePhishingResistantMfa**  | Target state: admin portals require phishing‑resistant MFA for external admins. |
| **CA540-ExternalAdmin-AdminPortals-Always-RequireTokenProtection**       | Future hardening: require token protection for external admin access.           |

***

## CA6xx – Service Accounts (Non‑Human)

> Non‑interactive identities used for automation.  
> Interactive sign-in is not permitted except via tightly controlled exceptions.

| Policy                                                  | Intent                                                                                          |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **CA600-Service-AllApps-Always-BlockInteractiveSignIn** | Blocks all interactive sign-ins for service identities.                                         |
| **CA610-Service-Office365-Always-Block**                | Explicitly blocks service account access to Microsoft 365 workloads.                            |
| **CA620-Service-AllApps-HighRiskSignIn-Block**          | Blocks high‑risk sign-ins for service accounts (defense in depth).                              |
| **CA630-Service-Interactive-TrustedLocationsOnly**      | Exception pattern: allows limited interactive sign-in from trusted locations only (time‑bound). |

***

## Design Notes (Normative)

*   **CA0xx and CA1xx are non‑negotiable guardrails**
*   **CA5xx never targets roles**, only the ExternalAdmin group
*   **Missing persona assignment must degrade safely**, never weaken admin protection
*   **Serial numbers are immutable** and never reused
*   Policies in `disabled` state document **target posture**, not enforcement
