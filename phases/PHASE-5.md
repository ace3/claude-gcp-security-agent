# Phase 5 -- Risk Synthesis & Remediation

**NIST Function**: IDENTIFY (ID.RA -- Risk Assessment) + GOVERN
**Depends on**: All phase state files (phase-1 through phase-4)

---

## Objective

Aggregate all findings from phases 2-4 into:
1. A scored finding list
2. A project-level security score (0-100)
3. Top remediation actions prioritized by impact
4. Quick wins list
5. Final documentation (after REVIEW GATE is cleared)

---

## Step 1 -- Aggregate All Findings

Read all state files:
- `scan-output/phases/phase-2-state.json`
- `scan-output/phases/phase-3-state.json`
- `scan-output/phases/phase-4-state.json`

Combine all `findings` arrays into a master list.

---

## Step 2 -- Apply Scoring Model

### Per-Finding Severity Score

| Severity | Base Score | Examples |
|----------|-----------|---------|
| CRITICAL | 10 | Firebase Admin SDK SA has `roles/editor`, open Firestore rules, `allUsers` on bucket, SA key age > 365d |
| HIGH | 7 | Human user with `roles/editor`, storage using legacy ACLs, no App Check, authentication-only rules with no granular checks |
| MEDIUM | 4 | No MFA in Firebase Auth, rules missing data validation, SA key age > 90d |
| LOW | 1 | Google APIs SA has `roles/editor` (expected), informational findings |

### Project Score Calculation

```
max_possible_score = count(all_findings) * 10
actual_penalty = sum(finding.score for each finding)
project_score = max(0, 100 - round((actual_penalty / max_possible_score) * 100))
```

Score bands:
- 90-100: EXCELLENT
- 75-89: GOOD
- 60-74: NEEDS IMPROVEMENT
- 40-59: POOR
- 0-39: CRITICAL RISK

---

## Step 3 -- Generate Remediation Commands

For each finding, provide an exact remediation command. Key patterns:

### FB-IAM-01: Firebase Admin SDK SA has roles/editor
```bash
# Remove roles/editor from Firebase Admin SDK SA
gcloud projects remove-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:firebase-adminsdk-xxxxx@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/editor"

# Replace with minimum required role:
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:firebase-adminsdk-xxxxx@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/firebase.sdkAdminServiceAgent"
```

### FB-IAM-02: App Engine default SA has roles/editor
```bash
gcloud projects remove-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$PROJECT_ID@appspot.gserviceaccount.com" \
  --role="roles/editor"

# Replace with specific roles based on what services use this SA.
# Analyze audit logs to determine actual permissions needed.
```

### FB-IAM-04/05: Human user has roles/editor or roles/owner
```bash
gcloud projects remove-iam-policy-binding $PROJECT_ID \
  --member="user:email@example.com" \
  --role="roles/editor"

# Replace with granular roles:
# roles/firebase.admin       (Firebase-specific admin)
# roles/firebase.developAdmin (Firebase development)
# roles/firebase.viewer       (read-only)
```

### FB-IAM-07: SA has user-managed keys
```bash
# Delete user-managed key and migrate to Workload Identity Federation
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SA_EMAIL
```

### FB-RULES-01/03/05: Open security rules
Provide corrected rules content in the remediation, e.g.:
```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.auth != null
        && request.auth.uid == resource.data.userId;
    }
  }
}
```

### FB-PUB-02: Storage bucket publicly accessible
```bash
gcloud storage buckets update gs://BUCKET_NAME \
  --no-public-access
```

---

## Step 4 -- Quick Wins

List all findings that are:
- Severity >= HIGH
- Fixable with a single gcloud command
- Remediation effort < 5 minutes

---

## Step 5 -- Write Phase State

`scan-output/phases/phase-5-state.json`:

```json
{
  "phase": "5",
  "timestamp": "<ISO8601>",
  "project_id": "<PROJECT_ID>",
  "status": "COMPLETE",
  "findings": [],
  "risk_summary": {
    "project_score": 0,
    "score_band": "CRITICAL RISK",
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "total_findings": 0,
    "top_remediation_ids": []
  }
}
```

---

## HUMAN GATE -- REVIEW GATE

```
================================================================
  HUMAN GATE: REVIEW GATE
================================================================

  Phase 5 complete. Risk synthesis ready for review.

  Project Security Score: XX/100 (<band>)
  Critical Findings: N
  High Findings: N
  Total Findings: N

  Review: scan-output/phases/phase-5-human.md

  YOU MUST:
  1. Review all CRITICAL and HIGH findings
  2. Confirm no false positives
  3. Tell me: "Gate cleared, reviewer: [your name], generate final docs"

  I will not generate remediation docs until you confirm.
================================================================
```

---

## After Gate Cleared -- Generate Final Documentation

### 00-overview.md (Executive Summary)
- Project name, scan date, reviewer
- Security score with band
- Finding count by severity
- Top 5 risks summary
- Recommended next steps

### remediation-plan.md
- All findings sorted by severity (CRITICAL first)
- Each finding includes: description, impact, remediation command, rollback command, effort estimate
- WARNING for each Firebase default SA remediation: removing `roles/editor` may break
  services that depend on broad permissions. Recommended approach:
  1. Audit what the SA actually accesses (via audit logs)
  2. Grant specific replacement roles
  3. Remove `roles/editor`
  4. Monitor for errors

### quick-wins.md
- Filtered list of HIGH+ findings fixable in < 5 minutes with single commands
- Formatted as a runnable checklist

### SCAN-INTEGRITY.md
- Scan metadata (project, timestamp, reviewer, active gcloud account)
- Phase completion status
- SHA256 hashes of all output files

---

## Output

- `scan-output/phases/phase-5-human.md` -- full scored findings narrative
- `scan-output/phases/phase-5-state.json` -- all findings with scores
- `scan-output/docs/00-overview.md` -- executive summary
- `scan-output/docs/remediation-plan.md` -- prioritized remediation
- `scan-output/docs/quick-wins.md` -- quick wins runbook
- `scan-output/SCAN-INTEGRITY.md` -- scan integrity record
