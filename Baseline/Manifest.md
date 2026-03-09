# Conditional Access (CA) Design Manifest

Audience: Architects, IAM engineers, security operations, and platform admins  
Purpose: Define the non‑negotiable principles, guardrails, and operating rules for designing, deploying, and evolving Conditional Access policies.

This manifest is **normative**. If any artifact (policy, process, exception) conflicts with this document, the artifact must be changed.

---

## 1) First Principles (Non‑Negotiable)

1. Personas capture risk acceptance, not job titles. Every human identity must belong to **exactly one** human persona at a time.
2. Global is a baseline contract, not a persona. It contains **few, stable invariants** (e.g., MFA baseline, risk controls, legacy auth block).
3. Privileged access is always protected by **role‑based guardrails**. Group membership must **never** be the only protection for admins.
4. **Fail closed for privilege**; **fail open (with baseline protections) for productivity**. Outages must not depend on perfect persona classification.
5. **No per‑policy exclusion groups.** Exclusions are **persona‑based and structural**, not tactical or user‑specific.
6. Policy names must be self‑descriptive. Anyone should understand a policy’s intent without opening it.
7. Serials are immutable and never reused. Deprecate with tombstones; do not renumber.

---

## 2) Policy Grammar (Canonical Naming)

All Conditional Access policies **must** follow:

    CA{Serial}-{Persona}-{Scope}-{Condition}-{Control}

- `{Serial}`: persona‑bound 3‑digit ID (e.g., 0xx, 1xx), spaced in steps of 10 for future insertion (…00, 10, 20…).  
- `{Persona}`: Global | Admin | KnowledgeWorker | Production | ExternalUser | ExternalAdmin | Service | BreakGlass  
- `{Scope}`: Application scope (AllApps, AdminPortals, M365, SensitiveApps, ApprovedApps) **or** Action scope (PimActivation, SecurityInfoRegistration, etc.).  
- `{Condition}`: Trigger like `Always` (default), `HighRiskSignIn`, `HighUserRisk`, `CompliantDevice`, `AllowedLocationsOnly`, `BrowserOnly`.  
- `{Control}`: Enforcement such as `BlockLegacyAuth`, `RequireMfa`, `RequireStrongAuth`, `RequirePhishingResistantMfa`, `RequirePasswordChange`, `ShortSession`.

Rules:
- `Condition` is **mandatory**; use `Always` if no extra gating applies.  
- **Exactly one** `Condition` token per policy—split policies rather than stacking conditions.  
- Always use `AllApps` (never `AnyApp`).  
- PascalCase tokens; no internal dashes inside tokens.  
- Action‑scoped policies **replace** AppScope with Action scope (do not append `AllApps`).

---

## 3) Serial Number Ranges (Persona Binding)

- **CA0xx** → Global (invariants)  
- **CA1xx** → Admin (internal privileged)  
- **CA2xx** → KnowledgeWorker  
- **CA3xx** → Production  
- **CA4xx** → ExternalUser  
- **CA5xx** → ExternalAdmin  
- **CA6xx** → Service  
- **CA9xx** → BreakGlass

Spacing rule: Use anchors at …00, 10, 20…. Insert pilots/overlays at …05, 15, 25…. Never reuse retired numbers.

---

## 4) Exclusions Policy

Allowed (structural):
- BreakGlass (explicit, minimal, tested)  
- Service from interactive human policies  
- Production from baseline MFA **only** when compensated by IP/device/app scoping  
- Role exclusions only when fully protected by a stronger role‑based policy elsewhere

Forbidden (tactical):
- Per‑policy “exclude” groups (e.g., CA-Exclude-MFA)  
- User‑specific one‑offs without expiry and ticket linkage  
- Excluding privileged roles from admin guardrails

Temporary exceptions (last resort):
- Use one central, time‑bound group `CA-Temporary-Exceptions`  
- Require ticket reference, owner, expiry ≤ 30 days, and weekly review  
- Never applicable to admin guardrails or Global risk blocks

---

## 5) Assignment & Guardrails

- **Global:** Targets All users with explicit structural exclusions only.  
- **KnowledgeWorker:** `CA-Persona-KnowledgeWorker` (static group; nest dynamic/license groups).  
- **Production:** `CA-Persona-Production` (explicit static; small; reviewed).  
- **ExternalUser:** Target by condition (Include guests and external users)—no group required.  
- **Admin Guardrail:** **Role‑targeted CA** (IncludeRoles for all privileged roles).  
- **ExternalAdmin:** `CA-Persona-ExternalAdmin` (explicit; PIM for Groups recommended).  
- **Service:** `CA-Persona-Service` (static/dynamic), interactive sign‑in blocked.  
- **BreakGlass:** `CA-Persona-BreakGlass` (2 accounts max; monitored; tested).

Safety Net (mandatory):  
At least one role‑targeted policy:

    CA150-Admin-AllApps-Always-RequireStrongAuth

Ensures all role holders are protected—independent of group hygiene.

---

## 6) Authentication Strength Strategy

- **Global:** `RequireMfa` (classic MFA), not Strength.  
- **Admin / ExternalAdmin:** Prefer **Authentication Strength** controls to enable clean uplift to **Phishing‑resistant** later without touching Global/user policies.  
- **Roadmap:** Pilot Strength uplift at …15 serials → graduate to …30 anchors.

---

## 7) Change Management & Operations

- **States:** New policies start `reportOnly` → validate → `enabled`.  
- **Blast radius:** CA0xx/CA1xx changes require formal change review and rollback plan.  
- **Tombstones:** Retire by setting `state: disabled` and marking “Retired” in catalogue; never delete IDs silently.  
- **Changelogs:** Every policy change links to a ticket with owner, reason, and risk assessment.  
- **Access reviews:** Quarterly for Production, ExternalAdmin, BreakGlass, Service.
- **BreakGlass drills:** Monthly - Verify sign‑in succeeds when a blocking misconfiguration is simulated.

---

## 8) Rollout & Testing

1. Shadow in `reportOnly` with sign‑in logs/KQL dashboards.  
2. Targeted pilot: IT + security champions.  
3. Progressive enable by persona → low‑risk apps → sensitive scopes.  
4. Fail‑safe windows with extended helpdesk coverage.  
5. Backout plan documented per policy (how to disable safely without breaking guardrails).

