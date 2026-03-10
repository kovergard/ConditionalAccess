
# Conditional Access Persona Catalogue

## Purpose

This document defines the **personas used for Conditional Access (CA) policies**.

Personas represent **security postures**, not job titles.  
Each persona defines:
- Who the account represents
- How the persona is determined
- How the persona is assigned
- Which Conditional Access policy serial numbers apply

This document is **normative**.  
Any new Conditional Access policy **must** map to one of the personas defined here.

---

## Persona overview

- Global (invariants)  
- Admin (internal privileged)  
- KnowledgeWorker  
- Production  
- ExternalUser  
- ExternalAdmin  
- Service  
- BreakGlass


## Naming and Numbering Conventions

### Policy naming format

All Conditional Access policies MUST follow this naming format:

    CA{Serial}-{Persona}-{Scope}-{Condition}-{Control}

Where:
- `{Serial}` is the persona-bound serial number (e.g. 0xx, 1xx)
- `{Persona}` is the persona name as defined in this document
- `{Scope}` is the application scope or user action
- `{Condition}` is the triggering condition, or `Always`
- `{Control}` is the enforced requirement

### Persona group naming

Persona assignment groups MUST follow this format:

    CA-Persona-{PersonaName}

---

# Personas (in policy order)

---

## 1. Global

### Serial number range
**CA0xx**

### Persona name
`Global`

### Description
Foundational identity protections that apply to **nearly all identities** in the tenant.  
Global policies define **security invariants** that should always hold unless explicitly and narrowly compensated elsewhere.

Global is **not a user persona**. It is a baseline protection layer.

### How to determine if an account fits
- Applies to all users by default
- Explicit exclusions only for:
  - BreakGlass accounts
  - Certain Service accounts (documented exceptions)

### Assignment method
- **No group**
- Targeted directly in Conditional Access using:
  - `All users`
  - Explicit exclusions

### Notes
- Global policies must be:
  - Few
  - Stable
  - Boring
- If a control is controversial, it does not belong in Global
- Global must never depend on persona group hygiene

---

## 2. Admin (Privileged Admins)

### Serial number range
**CA1xx**

### Persona name
`Admin`

### Description
Internal users with **privileged roles** that can materially impact tenant security or availability.

This persona represents **trusted, governed administrators**.

### How to determine if an account fits
- Tenant-native user (`userType = Member`)
- Assigned or eligible for Entra ID privileged roles
- Identity lifecycle governed by standard internal processes (HR, device management, etc.)

### Assignment method
- **Primary enforcement is role-based**
- Optional group for additional hardening or reporting:

    CA-Persona-Admin

### Notes
- Privileged access must **never rely solely on group membership**
- At least one **role-targeted Conditional Access policy** is mandatory
- Admin persona policies always **add controls**, never weaken Global

---

## 3. KnowledgeWorker

### Serial number range
**CA2xx**

### Persona name
`KnowledgeWorker`

### Description
Standard internal users with interactive sign-ins from diverse locations and devices, accessing collaboration and productivity workloads.

This is the **default internal human persona**.

### How to determine if an account fits
- Tenant-native user (`userType = Member`)
- Human user
- Not a service account
- Not Production
- Not primarily holding privileged roles

### Assignment method
**Static group with nested sources (recommended)**

    CA-Persona-KnowledgeWorker

Group population via:
- Nested license groups
- Nested dynamic groups (HR-driven attributes)
- Limited manual assignment

### Notes
- Most users should end up here automatically
- CA policies should target this group, not dynamic logic directly
- This persona must never weaken Global protections

---

## 4. Production

### Serial number range
**CA3xx**

### Persona name
`Production`

### Description
Users operating in **constrained, controlled environments** where strong MFA is impractical or impossible.  
Security is enforced primarily through **environmental controls**.

Examples:
- Factory floor users
- Retail / POS
- Shared kiosks
- Frontline / blue-collar roles

### How to determine if an account fits
- Human user
- Fixed location(s)
- Limited application set
- Operational continuity prioritized over identity assurance

### Assignment method
**Explicit static group only**

    CA-Persona-Production

### Notes
- This persona explicitly accepts **higher identity risk**
- Compensating controls (IP, device, app scope) are mandatory
- Membership should be small and reviewed regularly

---

## 5. ExternalUser

### Serial number range
**CA4xx**

### Persona name
`ExternalUser`

### Description
Non-employee users authenticated in the tenant, where identity lifecycle and device posture are **not controlled** by the organization.

### How to determine if an account fits
- `userType = Guest`
- No privileged role assignments

### Assignment method
- **No group required**
- Targeted directly in Conditional Access using:
  - *Include guests and external users*

### Notes
- This persona is **automatic**
- External users should never inherit internal relaxations
- Admin access is blocked by default

---

## 6. ExternalAdmin

### Serial number range
**CA5xx**

### Persona name
`ExternalAdmin`

### Description
Privileged users whose identity lifecycle or device posture is **not fully governed** by the tenant.

Account origin is irrelevant — guest or tenant-native.

### Assignment method
**Explicit static group with PIM (strongly recommended)**

    CA-Persona-ExternalAdmin

### Notes
- Missing membership must not remove baseline admin protection
- Role-based admin CA policies provide the safety net
- This persona adds hardening, not eligibility

---

## 7. Service

### Serial number range
**CA6xx**

### Persona name
`Service`

### Assignment method

    CA-Persona-Service

### Notes
- Interactive sign-in should be blocked
- Long-term goal is workload identities

---

## 8. BreakGlass

### Serial number range
**CA9xx**

### Persona name
`BreakGlass`

### Assignment method

    CA-Persona-BreakGlass

### Notes
- Very limited membership
- Excluded from most CA policies
- Sign-ins monitored and tested regularly

---

## End of document
