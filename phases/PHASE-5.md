# Phase 5 — Risk Synthesis & Scoring

**NIST Function**: IDENTIFY (ID.RA — Risk Assessment) + GOVERN
**Depends on**: All phase-4x-state.json files

---

## Objective

Aggregate all findings from phases 4a–4f into:
1. A scored finding list (per finding)
2. A project-level security score (0–100)
3. Threat-model-weighted priorities (from phase 0.5)
4. Program-level KPIs
5. Top 10 prioritized remediation actions

---

## Step 1 — Aggregate All Findings

Read all state files:
- `scan-output/phases/phase-4a-state.json`
- `scan-output/phases/phase-4b-state.json`
- `scan-output/phases/phase-4c-state.json`
- `scan-output/phases/phase-4d-state.json`
- `scan-output/phases/phase-4e-state.json`
- `scan-output/phases/phase-4f-state.json`

Combine all `findings` arrays into a master list.

---

## Step 2 — Apply Scoring Model

### Per-Finding Severity Score

| Severity | Base Score | Examples |
|----------|-----------|---------|
| CRITICAL | 10 | `allUsers` on bucket, `roles/owner` on SA, SSH open `0.0.0.0/0`, SA key age > 365d, Cloud Build SA has `roles/editor`, active SCC THREAT finding |
| HIGH | 7 | `roles/editor` primitive role, no org policy guardrails, CRITICAL CVE in deployed image, no log sinks, unused SA with active keys |
| MEDIUM | 4 | SA unused 90d, firewall rule 0 hits, secret no rotation, no VPC Flow Logs, no budget alerts |
| LOW | 1 | Old key < 180d, image not latest minor, log retention < 90d |

### Threat-Model Multiplier (from Phase 0.5)

If a finding affects a resource that sits on a **viable attack path** identified in Phase 0.5:
- Multiply the finding score × 1.5 (round up)
- Add tag: `threat_model_amplified: true`

This means a MEDIUM (4) finding on a path to a crown jewel becomes effectively HIGH (6).

### Project Score Calculation

```
max_possible_score = count(all_findings) × 10
actual_penalty = sum(finding.score for each finding)
project_score = max(0, 100 - round((actual_penalty / max_possible_score) × 100))
```

Score bands:
- 90–100: EXCELLENT
- 75–89: GOOD
- 60–74: NEEDS IMPROVEMENT
- 40–59: POOR
- 0–39: CRITICAL RISK

---

## Step 3 — CIS GCP Coverage Report

Map each finding (or absence of finding) to CIS GCP Benchmark v2.x controls.
Track:

```json
{
  "cis_coverage": {
    "L1_total": 50,
    "L1_passing": 35,
    "L1_failing": 10,
    "L1_not_checked": 5,
    "L1_coverage_pct": 70,
    "L2_total": 30,
    "L2_passing": 15,
    "L2_failing": 8,
    "L2_not_checked": 7,
    "L2_coverage_pct": 50
  }
}
```

---

## Step 4 — Program KPIs

Calculate and record as baseline:

```json
{
  "kpis": {
    "pct_projects_no_primitive_roles": 0,
    "pct_projects_no_user_managed_sa_keys": 0,
    "pct_projects_no_public_buckets": 0,
    "pct_projects_scc_enabled": 0,
    "pct_projects_log_sink_configured": 0,
    "critical_findings_count": 0,
    "high_findings_count": 0,
    "total_findings_count": 0,
    "mttr_baseline_days": null,
    "scan_date": "<ISO8601>"
  }
}
```

---

## Step 5 — Top 10 Remediation Actions

Select the 10 highest-impact findings considering:
1. Score (CRITICAL first)
2. Threat-model amplification
3. Remediation effort (lower effort = higher priority at equal score)

Format each as:

```markdown
### 🔴 #1 — <Title>
**Internal ID**: GCP-IAM-01
**Severity**: CRITICAL (score: 15 — threat amplified)
**CIS Control**: 1.5
**NIST Function**: PROTECT

**What**: Cloud Build default SA has roles/editor
**Why it matters**: Full project read/write from CI/CD. Compromise = full takeover.
**Blast radius**: All resources in project

**Fix**:
gcloud projects remove-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:PROJECT_NUMBER@cloudbuild.gserviceaccount.com" \
  --role="roles/editor"
# Replace with: roles/run.developer, roles/artifactregistry.writer (minimum needed)

**Effort**: 30 minutes
**Risk if not fixed**: Critical
**Review date if accepted**: <90 days from now>
```

---

## Step 6 — Quick Wins

Separately list all findings that are:
- Score >= HIGH
- Remediation effort < 5 minutes
- Fixable with a single gcloud command

---

## ⛔ HUMAN GATE — REVIEW GATE

```
════════════════════════════════════════════════════════
  HUMAN GATE: REVIEW GATE
════════════════════════════════════════════════════════

  Phase 5 complete. Risk synthesis ready for review.

  Project Security Score: XX/100 (<band>)
  Critical Findings: N
  High Findings: N
  Total Findings: N
  CIS L1 Coverage: N%

  Review the full findings at:
  scan-output/phases/phase-5-human.md

  YOU MUST:
  1. Review all CRITICAL and HIGH findings
  2. Confirm no false positives before remediation docs are published
  3. Record your name as reviewer
  4. Tell me: "Gate cleared, reviewer: [your name], continue to phase 6"

  I will not generate public remediation docs until you confirm.
════════════════════════════════════════════════════════
```

---

## Output

- `scan-output/phases/phase-5-human.md` — full scored findings narrative
- `scan-output/phases/phase-5-state.json` — all findings with scores, KPIs, coverage
- `scan-output/audit/security-kpis.md` — KPI baseline document
- `scan-output/audit/compliance-mapping.md` — NIST + CIS control mapping
