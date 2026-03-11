# DEPLOYMENT.md — Conditional Access Baseline Rollout Guide

This guide describes a **safe, phased deployment** of the persona‑based Conditional Access (CA) baseline contained in this repository.

> **Read first:**  
> - `/docs/CA-Design-Manifest.md` (non‑negotiable principles)  
> - `/docs/CA-Persona-Catalogue.md` (who, how assigned)  
> - `/docs/CA-Policy-Catalogue.md` (what each policy does)

---

## 0) Prerequisites & Tenant Hygiene

- **Break‑glass**
  - Create **2 cloud‑only** break‑glass accounts with long, strong passwords.
  - Add them to `CA-Persona-BreakGlass`.
  - Configure **alerting** for any sign‑in by these accounts.
  - **Exclude** `CA-Persona-BreakGlass` from *all* enforcement policies.

- **Persona groups**
  - Create the following (or confirm they exist):  
    `CA-Persona-Admin`, `CA-Persona-KnowledgeWorker`, `CA-Persona-Production`,  
    `CA-Persona-ExternalAdmin`, `CA-Persona-Service`, `CA-Persona-BreakGlass`
  - Populate **KnowledgeWorker** by *nesting* license/dynamic groups.  
  - Keep **Production** explicit & small; review membership.

- **Named locations**
  - Define `TrustedNetworks` (CIDR ranges) for Production (and Service exceptions if used).

- **Admin role IDs**
  - Resolve directory role definition IDs if you plan to update CA1xx (see Admin JSON placeholders in `/policies/admin/`).

- **Comms & helpdesk**
  - Publish the rollout plan and a simple “What to expect” for prompts/sign‑in behavior.
  - Ensure helpdesk has “how to identify CA blocks” steps.

---

## 1) Import Policies (Report‑only)

> Import **one JSON at a time**. Use Microsoft Graph:
>
> `POST https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`  
> `Content-Type: application/json`
>
> Replace placeholders (group IDs, named location IDs, terms of use IDs, app IDs) before import.

**Import Order (recommended):**

1. **Global**: CA010 → CA000 → CA020 → CA030
2. **Admin**: CA100 → CA110 → CA120 (CA130–CA150 can be imported disabled)
3. **KnowledgeWorker**: CA210 (plus CA200, CA220 if you keep anchors; CA230–CA250 optional)
4. **Production**: CA300 → CA310 → CA320 → (optional CA330) → (optional CA340)
5. **ExternalUser**: CA410 → CA400 → CA420 → (optional CA430–CA450)
6. **ExternalAdmin**: CA500 → CA510 → CA520 → (optional CA530–CA540)
7. **Service**: CA600 → CA610 → CA620 → (optional CA630)
8. **BreakGlass**: CA900 → CA910 → CA920 (Report‑only canaries)

All imported policies should initially be **`state: "enabledForReportingButNotEnforced"`** (except those already **`disabled`** as future markers).

---

## 2) Validation (Report‑only Analysis)

Use **Entra ID → Sign‑in logs** (Add columns: *Client app*, *Conditional Access*, *Result*, *Authentication requirement*).

**What to verify per layer:**

- **Global (CA0xx)**
  - CA010 **would block** legacy auth attempts (clientAppTypes = other).
  - CA000 **would require MFA** for typical sign‑ins (except BreakGlass/Service).
  - CA020/CA030 **would block/remediate** on test high‑risk events (if possible in a lab).

- **Admin (CA1xx)**
  - For accounts holding roles, CA100/110/120 appear under “Report‑only (would apply)”.
  - No unexpected hits for non‑admin users.

- **KnowledgeWorker (CA2xx)**
  - CA210 **would require compliant device** on M365 for KW users.
  - Confirm app scope is correct (`Office365`).

- **Production (CA3xx)**
  - CA300 **would block** from non‑trusted networks.
  - CA310 **would block** all apps except your approved list.
  - CA320 **would require compliant device**; if hybrid fallback planned, CA330 “ready”.

- **ExternalUser (CA4xx)**
  - CA410 **would block** admin portals for guests; confirm **exclude** `CA-Persona-ExternalAdmin` if you allow vetted external admins.
  - CA400 **would require MFA** for guests.

- **ExternalAdmin (CA5xx)**
  - For users in `CA-Persona-ExternalAdmin`, CA500/520 appear in report‑only on admin portals.
  - CA510 shows for PIM activation (test in lab).

- **Service (CA6xx)**
  - CA600 **would block** any interactive sign-ins by service accounts.

- **BreakGlass (CA9xx canaries)**
  - **No** CA9xx policy should appear as *“reportOnlyFailure”* when testing break‑glass sign‑in; if it does, fix exclusions.

> **Tip:** Save useful filters as **workbooks**. Review daily during rollout.

---

## 3) Enablement (Phased)

Enable in **small batches**, with helpdesk coverage.

**Phase A — Guardrails**
1. **Global**: Enable CA010 (legacy block) → CA000 (MFA) → CA020/CA030 (risk)
2. **Admin**: Enable CA100/110/120

**Phase B — Users**
3. **KnowledgeWorker**: Enable CA210 (M365 compliant device) after device readiness signal is green

**Phase C — Production**
4. **Production**: Enable CA300 (location), CA310 (apps), **then** CA320 (device)
   - If and only if compensated by these controls, exclude Production from Global MFA (CA000), as documented in the Manifest.
   - Keep CA330 (hybrid fallback) **disabled** unless explicitly needed.

**Phase D — External**
5. **ExternalUser**: Enable CA410 (admin portals block), CA400 (MFA), CA420 (risk)
6. **ExternalAdmin**: Enable CA500 (strong auth), CA520 (short session). Keep CA530/540 disabled as target state.

**Phase E — Service**
7. **Service**: Enable CA600 (block interactive), optionally CA610/620.

**Phase F — Canaries**
8. **BreakGlass**: Keep CA900/910/920 **report‑only** permanently.

After each enablement, monitor sign‑in logs closely for 24–72 hours.

---

## 4) Rollback

If a policy causes unexpected impact:

1. **Disable the specific policy** (set `state: "disabled"`), do **not** delete it.  
2. Communicate to stakeholders; capture the reason in the change ticket.  
3. Verify recovery in sign‑in logs.  
4. Adjust scope/conditions; re‑introduce via `reportOnly` → enable when validated.

> **Do not** remove Admin (CA1xx) guardrails unless under a break‑glass‑level incident with a clearly documented backout plan.

---

## 5) Exceptions (Time‑Bound)

- Use **one central exception group** (e.g., `CA-Temporary-Exceptions`) if absolutely required.
- Document in `/docs/CA-Exclusions-Ledger.md`: requester, ticket, owner, scope, start, **expiry ≤ 30 days**, review status.
- Never use exceptions to bypass **Admin guardrails** or **Global risk blocks**.

---

## 6) Post‑Deployment Monitoring

Create alerts/dashboards for:

- **Privileged sign-ins not satisfying CA1xx** (should be impossible)
- **Guest with privileged role** not in `CA-Persona-ExternalAdmin` (reduced hardening)
- **Service** accounts attempting interactive sign‑in
- Any **BreakGlass** sign‑in (page)
- Policies stuck in **reportOnly** > 30 days

**Suggested KQL (examples)** are included in `/docs/CA-Monitoring-KQL.md`.

---

## 7) Access Reviews & Hygiene

Quarterly:
- Review membership of `CA-Persona-Production`, `CA-Persona-ExternalAdmin`, `CA-Persona-Service`, `CA-Persona-BreakGlass`.
- Validate **TrustedNetworks** named location entries.
- Re‑run **BreakGlass drill** (verify sign‑in succeeds; canaries do not apply beyond report‑only).

---

## 8) Change Management

- All changes require a ticket with: **owner, rationale, blast radius, rollback**.
- Update `/docs/CA-Policy-Catalogue.md` when adding/removing policies.
- **Never reuse serial numbers**; deprecate by disabling and marking “Retired” in the catalogue.

---

## Quick Checklists

**Go‑Live Day Checklist**
- [ ] Helpdesk on standby; comms sent
- [ ] BreakGlass tested this week
- [ ] Named locations verified
- [ ] Sign‑in logs workbook pinned
- [ ] Backout steps documented per policy

**Production Persona Enablement**
- [ ] CA300 Enabled (locations)  
- [ ] CA310 Enabled (apps allowlist)  
- [ ] CA320 Enabled (device)  
- [ ] (Optional) Exclude Production from Global MFA only now  
- [ ] Monitor 72h

---

## FAQ (Short)

- **Why report‑only first?**  
  CA has **no precedence**; multiple policies combine. Report‑only shows impact without enforcement.

- **How do I express “Compliant OR Hybrid‑Joined”?**  
  With **two policies** (CA320 + CA330). OR logic cannot be expressed inside a single policy.

- **Can I rely on WHfB as MFA for shared accounts?**  
  Treat it as **password elimination**, not identity assurance. Keep compensating controls; do **not** weaken Production constraints because WHfB “satisfies MFA”.

---

## Support & Ownership

- **Architecture:** Security Architecture / IAM  
- **Operations:** Identity Platform Team  
- **Monitoring:** SecOps / SOC  
- **Document owners:** Listed at top of each file in `/docs/`

---
``