# Phase 6 — Full Output Generation

**NIST Function**: All (documentation layer)
**Depends on**: Phase 5 REVIEW GATE cleared + reviewer name confirmed

---

## Objective

Generate all final documentation files from the structured phase state data.
Read from JSON state files — do not re-run gcloud commands.
Every doc references the internal finding IDs from Phase 5.

---

## Documents to Generate

### docs/00-overview.md — Executive Summary

```markdown
# GCP Security Audit — Executive Summary

**Project**: <PROJECT_ID>
**Scan Date**: <DATE>
**Reviewer**: <NAME>
**Security Score**: XX/100 (<band>)

## Risk Summary

| Severity | Count | Top Example |
|----------|-------|-------------|
| 🔴 CRITICAL | N | ... |
| 🟠 HIGH | N | ... |
| 🟡 MEDIUM | N | ... |
| 🟢 LOW | N | ... |

## Public-Facing Resources
<list all resources exposed to internet>

## Immediate Actions Required
<top 3 CRITICAL findings with one-line fix>

## CIS GCP Coverage: L1: N% · L2: N%
```

---

### docs/remediation-plan.md

Full top-10 list from Phase 5 Step 5, expanded with:
- Rollback plan for each fix
- Testing step to confirm fix applied
- Owner field (blank — for human to fill)
- Target date field (blank)

---

### docs/quick-wins.md

All HIGH+ findings fixable in < 5 minutes, formatted as a runbook:
```markdown
## Quick Wins — Fix in < 5 minutes

Estimated total time to complete all: ~N minutes

### 1. Revoke public bucket access (2 min)
...
### 2. Remove allUsers firewall rule (1 min)
...
```

---

### Mermaid Diagrams

Generate all diagrams listed below using data from state files.
Each diagram file is standalone Markdown with a single Mermaid block.

**Required diagrams:**

1. `diagrams/network-topology.md` — VPC/subnet/VM layout with firewall exposure
2. `diagrams/cicd-pipeline.md` — Source → Build → Registry → Cloud Run
3. `diagrams/connectivity-map.md` — Instance-to-instance + service-to-service
4. `diagrams/public-access-map.md` — All internet-facing entry points
5. `diagrams/service-account-map.md` — SA → resource bindings
6. `diagrams/cross-project-trust-map.md` — Cross-project SA access
7. `diagrams/blast-radius-map.md` — Per-SA blast radius
8. `diagrams/attack-paths.md` — Viable attack paths from threat model
9. `diagrams/sa-risk-matrix.md` — Quadrant: permissions vs activity

**Diagram conventions:**
- 🔴 = CRITICAL risk resource
- 🟠 = HIGH risk resource  
- ✅ = healthy / no finding
- 🔒 = properly restricted
- ⚠️ = warning / medium risk
- Dashed arrows = blocked/restricted paths
- Solid arrows = active/open paths

---

### IR Documents

**ir/plan.md** — Incident Response Plan skeleton:
```markdown
# Incident Response Plan — <PROJECT_ID>

## Roles & Responsibilities
| Role | Name | Contact |
|------|------|---------|
| IR Lead | TBD | |
| Platform Owner | TBD | |
| Security Contact | TBD | |

## Severity Definitions
...

## Escalation Path
...

## Communication Templates
...

## Post-Incident Review Process
...
```

**ir/playbooks/iam-escalation.md:**
```markdown
# Playbook: Suspicious IAM Change

## Trigger
Alert fires on SetIamPolicy event OR manual detection.

## Immediate Steps (first 15 minutes)
1. Identify who made the change:
   gcloud logging read 'protoPayload.methodName="SetIamPolicy"' \
     --freshness=1h --format=json | jq '.[0].protoPayload.authenticationInfo'

2. Identify what was changed:
   <check audit log for delta>

3. If change is unauthorized — revoke immediately:
   gcloud projects remove-iam-policy-binding ...

4. If SA key was created — rotate:
   gcloud iam service-accounts keys disable KEY_ID --iam-account=SA_EMAIL

## Escalation
...

## Evidence to Preserve
...
```

**ir/playbooks/public-exposure.md** — Steps for public bucket/VM exposure
**ir/playbooks/credential-compromise.md** — Key revocation, token rotation, blast radius scoping

---

## Output Checklist

After Phase 6, verify all files exist:

```bash
find scan-output/ -name "*.md" -o -name "*.json" | sort
```

Expected file count: ~35 files

---
---

# Phase 7 — Scan Integrity Record

**NIST Function**: GOVERN
**Depends on**: Phase 6 complete

---

## Objective

Produce a tamper-evident record of the scan. This makes the output
defensible in an audit context and creates a baseline for future scans.

---

## Step 1 — Compute File Hashes

```bash
# Cross-platform SHA256 wrapper (macOS: shasum -a 256; Linux: sha256sum)
_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

# Hash all output files
find scan-output/ -type f | sort | while IFS= read -r FILE; do
  _sha256 "$FILE"
done > scan-output/MANIFEST.sha256

# Hash the CLAUDE.md that drove the scan
_sha256 CLAUDE.md >> scan-output/MANIFEST.sha256

# Hash each phase file
for PHASE in phases/PHASE-*.md; do
  _sha256 "$PHASE" >> scan-output/MANIFEST.sha256
done
```

---

## Step 2 — Generate SCAN-INTEGRITY.md

Write to `scan-output/SCAN-INTEGRITY.md`:

```markdown
# Scan Integrity Record

| Field | Value |
|-------|-------|
| Project ID | <PROJECT_ID> |
| Scan Start | <ISO8601> |
| Scan End | <ISO8601> |
| Scanner SA | gcp-doc-scanner@<PROJECT_ID>.iam.gserviceaccount.com |
| Claude Model | <CLAUDE_MODEL_ID> |
| CLAUDE.md SHA256 | <hash> |
| Reviewer | <NAME> |
| Review Date | <DATE> |
| Total Findings | N (N critical, N high, N medium, N low) |
| Security Score | XX/100 |
| CIS L1 Coverage | N% |
| CIS L2 Coverage | N% |
| Output Files | N files (see MANIFEST.sha256) |

## Phase Completion Status

| Phase | Status | Duration |
|-------|--------|----------|
| Phase 0 | ✅ Complete | Xm |
| Phase 0.5 | ✅ Complete | Xm |
| Phase 1 | ✅ Complete | Xm |
| Phase 2 | ✅ Complete | Xm |
| Phase 3 | ✅ Complete | Xm |
| Phase 4a | ✅ Complete | Xm |
| Phase 4b | ✅ Complete | Xm |
| Phase 4c | ✅ Complete | Xm |
| Phase 4d | ✅ Complete | Xm |
| Phase 4e | ✅ Complete | Xm |
| Phase 4f | ✅ Complete | Xm |
| Phase 5 | ✅ Complete | Xm |
| Phase 6 | ✅ Complete | Xm |
| Phase 7 | ✅ Complete | Xm |

## Human Gate Records

| Gate | Cleared By | Timestamp |
|------|-----------|-----------|
| Permission Gate (Phase 2) | <NAME> | <ISO8601> |
| Review Gate (Phase 5) | <NAME> | <ISO8601> |

## Manifest
See MANIFEST.sha256 for SHA256 hashes of all output files.
To verify integrity: sha256sum --check MANIFEST.sha256

## Next Scan
Recommended cadence:
- Light scan (phases 4b, 4e): Weekly
- Full scan (all phases): Monthly
- Next full scan due: <DATE + 30 days>
```

---

## Step 3 — Final Summary Print

Print to console:

```
════════════════════════════════════════════════════════
  GCP SECURITY AUDIT COMPLETE
════════════════════════════════════════════════════════

  Project:        <PROJECT_ID>
  Security Score: XX/100 (<band>)

  Findings:
    🔴 Critical: N
    🟠 High:     N
    🟡 Medium:   N
    🟢 Low:      N

  CIS Coverage:  L1: N% · L2: N%
  Output files:  N files in scan-output/
  Integrity:     scan-output/SCAN-INTEGRITY.md

  Top 3 Actions:
  1. <CRITICAL finding #1>
  2. <CRITICAL finding #2>
  3. <HIGH finding #1>

  Full remediation plan: scan-output/docs/remediation-plan.md
  Quick wins (< 5 min):  scan-output/docs/quick-wins.md

════════════════════════════════════════════════════════
```
