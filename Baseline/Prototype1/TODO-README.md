
# Conditional Access Baseline (Persona‑Based)

This repository contains a **persona‑based Conditional Access (CA) baseline** for Microsoft Entra ID, designed as a **starting point for overhauling legacy or ad‑hoc CA configurations**.

The design prioritizes:
- Clear security intent
- Safe failure modes
- Role‑based guardrails for privileged access
- Incremental hardening without tenant lockout risk

This is **not** a one‑click “secure everything” solution.  
It is a **reference architecture** meant to be adapted per tenant.

---

## Design Principles (Read This First)

- **Personas represent security postures, not job titles**
- **Global policies establish invariants** (baseline guarantees)
- **Privileged access is always protected by role‑based policies**
- **Groups add hardening, never baseline protection**
- **Fail closed for privilege, fail open (with baseline protections) for productivity**
- **No per‑policy exclusion groups** (exclusions are structural and persona‑based)
- **Serial numbers are immutable and never reused**

These principles are defined normatively in the **Design Manifest**.

---

## Repository Structure

### `/docs/`
Authoritative documentation for the framework:

- **CA-Design-Manifest.md**  
  Non‑negotiable rules, guardrails, naming grammar, and operational principles.

- **CA-Persona-Catalogue.md**  
  Definition of all personas, assignment rules, and serial number ranges.

- **CA-Policy-Catalogue.md**  
  Concise index of every policy (intent, scope, and role in the design).

- **CA-Exclusions-Ledger.md** *(optional)*  
  Time‑bound, documented exceptions (if used).

- **CA-Runbook-BreakGlass.md** *(recommended)*  
  Operational procedures for emergency access accounts.

---

### `/policies/`
Import‑ready Conditional Access policies (JSON), grouped by persona.

- **global/** – CA0xx baseline invariants  
- **admin/** – CA1xx privileged admin guardrails  
- **knowledgeworker/** – CA2xx internal user policies  
- **production/** – CA3xx frontline / blue‑collar controls  
- **externaluser/** – CA4xx guest access restrictions  
- **externaladmin/** – CA5xx hardened external admin controls  
- **service/** – CA6xx non‑human identity protections  
- **breakglass/** – CA9xx canary and validation policies

Each JSON file represents **one policy** and is designed to be imported individually.

---

## Policy Naming & Numbering

All policies follow this grammar:

`CA{Serial}-{Persona}-{Scope}-{Condition}-{Control}`

Examples:
- `CA010-Global-AllApps-Always-BlockLegacyAuth`
- `CA120-Admin-PimActivation-Always-RequireStrongAuth`
- `CA310-Production-ApprovedApps-Only`

Serial ranges map directly to personas:
- CA0xx – Global
- CA1xx – Admin
- CA2xx – KnowledgeWorker
- CA3xx – Production
- CA4xx – ExternalUser
- CA5xx – ExternalAdmin
- CA6xx – Service
- CA9xx – BreakGlass

See **CA-Persona-Catalogue.md** for details.

---

## How to Use This Repository

1. **Read the Design Manifest**  
   Do not deploy anything before understanding the guardrails.

2. **Review the Persona Catalogue**  
   Decide which personas apply to your tenant and how users are assigned.

3. **Import policies in `reportOnly`**  
   Validate impact using Entra ID sign‑in logs.

4. **Enable incrementally**  
   Start with CA0xx → CA1xx → user personas → Production / External.

5. **Document deviations**  
   If you diverge from the baseline, record *why*.

---

## What This Baseline Does *Not* Do

- It does **not** enforce perfect structure automatically  
- It does **not** replace identity governance or access reviews  
- It does **not** assume mature MFA or device compliance everywhere  

Instead, it provides **safe defaults and clear evolution paths**.

---

## Intended Audience

- Identity / Security Architects
- Entra ID / IAM engineers
- Security operations teams
- Auditors reviewing Conditional Access design

---

## License / Use

This baseline is provided as a **reference design**.  
You are expected to adapt it to:
- Regulatory requirements
- Operational constraints
- Tenant maturity

---

## One‑Sentence Summary

> *This repository defines a persona‑based Conditional Access framework that is safe by default, resilient to human error, and designed to evolve without breaking tenants.*
