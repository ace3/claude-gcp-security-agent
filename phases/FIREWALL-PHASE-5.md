# Firewall Phase 5 -- Risk Synthesis & Remediation

**NIST Function**: IDENTIFY (ID.RA -- Risk Assessment) + GOVERN
**Depends on**: All phase state files (phase-1 through phase-4)

---

## Objective

Aggregate all findings from phases 2-4 into:
1. A scored finding list
2. A project-level firewall security score (0-100)
3. Top remediation actions prioritized by impact
4. Quick wins list
5. Final documentation (after REVIEW GATE is cleared)

---

## Step 1 -- Aggregate All Findings

Read all state files:
- `scan-output-firewall/phases/phase-2-state.json`
- `scan-output-firewall/phases/phase-3-state.json`
- `scan-output-firewall/phases/phase-4-state.json`

Combine all `findings` arrays into a master list.

---

## Step 2 -- Apply Scoring Model

### Per-Finding Severity Score

| Severity | Base Score | Examples |
|----------|-----------|---------|
| CRITICAL | 10 | 0.0.0.0/0 ingress, SSH/RDP from anywhere, allow-all traffic, database ports exposed |
| HIGH | 7 | Broad port ranges, no-target permissive rules, instance with public IP + permissive ingress |
| MEDIUM | 4 | Default SSH/RDP rules active, priority conflicts, instance with public IP |
| LOW | 1 | Disabled rules present, orphaned tags |

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

### FW-VPC-01: 0.0.0.0/0 Ingress Rule
```bash
# Restrict source ranges to trusted CIDRs
gcloud compute firewall-rules update RULE_NAME \
  --source-ranges="OFFICE_CIDR,VPN_CIDR" \
  --project=$PROJECT_ID
```

### FW-VPC-02: Allow-All Traffic Rule
```bash
# Option A: Delete the rule
gcloud compute firewall-rules delete RULE_NAME --project=$PROJECT_ID

# Option B: Restrict to specific protocols/ports
gcloud compute firewall-rules update RULE_NAME \
  --allow=tcp:80,tcp:443 \
  --project=$PROJECT_ID
```

### FW-VPC-04: SSH from 0.0.0.0/0
```bash
# Delete the open SSH rule
gcloud compute firewall-rules delete RULE_NAME --project=$PROJECT_ID

# Replace with IAP-based SSH access (recommended)
gcloud compute firewall-rules create allow-ssh-via-iap \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges="35.235.240.0/20" \
  --target-tags=allow-ssh \
  --project=$PROJECT_ID

# Ensure IAP API is enabled
gcloud services enable iap.googleapis.com --project=$PROJECT_ID
```

### FW-VPC-05: RDP from 0.0.0.0/0
```bash
# Delete the open RDP rule
gcloud compute firewall-rules delete RULE_NAME --project=$PROJECT_ID

# Replace with IAP-based RDP access
gcloud compute firewall-rules create allow-rdp-via-iap \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:3389 \
  --source-ranges="35.235.240.0/20" \
  --target-tags=allow-rdp \
  --project=$PROJECT_ID
```

### FW-VPC-06: No Target Tags
```bash
# Add target tags to scope the rule
gcloud compute firewall-rules update RULE_NAME \
  --target-tags=APPROPRIATE_TAG \
  --project=$PROJECT_ID
```

### FW-VPC-07: Default SSH/RDP Rules
```bash
# Delete default rules
gcloud compute firewall-rules delete default-allow-ssh --project=$PROJECT_ID
gcloud compute firewall-rules delete default-allow-rdp --project=$PROJECT_ID
```

### FW-VPC-10: Database Ports Exposed
```bash
# Restrict to application server CIDR only
gcloud compute firewall-rules update RULE_NAME \
  --source-ranges="APP_SERVER_SUBNET_CIDR" \
  --project=$PROJECT_ID
```

### FW-NET-01: Instance with Public IP + Permissive Ingress
```bash
# Remove external IP (if not needed)
gcloud compute instances delete-access-config INSTANCE_NAME \
  --zone=ZONE \
  --access-config-name="External NAT" \
  --project=$PROJECT_ID

# Or restrict the firewall rule (see FW-VPC-01 remediation)
```

---

## Step 4 -- Quick Wins

List all findings that are:
- Severity >= HIGH
- Fixable with a single gcloud command
- Remediation effort < 5 minutes

Typical quick wins for firewall audits:
- Delete `default-allow-ssh` and `default-allow-rdp`
- Restrict 0.0.0.0/0 rules to specific CIDRs
- Add target tags to untargeted rules
- Disable allow-all rules while investigating

---

## Step 5 -- Write Phase State

`scan-output-firewall/phases/phase-5-state.json`:

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

  Phase 5 complete. Firewall risk synthesis ready for review.

  Firewall Security Score: XX/100 (<band>)
  Critical Findings: N
  High Findings: N
  Total Findings: N

  Review: scan-output-firewall/phases/phase-5-human.md

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
- Firewall security score with band
- Finding count by severity
- Top 5 risks summary
- Network topology summary (number of VPCs, instances, rules)
- Recommended next steps

### remediation-plan.md
- All findings sorted by severity (CRITICAL first)
- Each finding includes: description, impact, affected resources, remediation command, rollback command, effort estimate
- WARNING for IAP migration: switching from direct SSH/RDP to IAP requires:
  1. Enable IAP API
  2. Create IAP firewall rules (source: 35.235.240.0/20)
  3. Grant IAP tunnel user role to users who need access
  4. Test connectivity before deleting old rules

### quick-wins.md
- Filtered list of HIGH+ findings fixable in < 5 minutes with single commands
- Formatted as a runnable checklist with `[ ]` checkboxes

### SCAN-INTEGRITY.md
- Scan metadata (project, timestamp, reviewer, active gcloud account)
- Phase completion status
- SHA256 hashes of all output files

---

## Output

- `scan-output-firewall/phases/phase-5-human.md` -- full scored findings narrative
- `scan-output-firewall/phases/phase-5-state.json` -- all findings with scores
- `scan-output-firewall/docs/00-overview.md` -- executive summary
- `scan-output-firewall/docs/remediation-plan.md` -- prioritized remediation
- `scan-output-firewall/docs/quick-wins.md` -- quick wins runbook
- `scan-output-firewall/SCAN-INTEGRITY.md` -- scan integrity record
