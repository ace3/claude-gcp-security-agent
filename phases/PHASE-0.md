# Phase 0 — Governance & Landing Zone

**NIST Function**: GOVERN + IDENTIFY
**CIS Controls**: Section 1 (IAM), org-level policies
**Depends on**: gcloud auth with org-level viewer access (or project-level viewer minimum)

---

## Objective

Check the GCP platform design itself before examining individual services.
A misconfigured landing zone makes every downstream control unreliable.

---

## Step 1 — Resource Hierarchy

```bash
# Check if an Organization exists
gcloud organizations list --format=json

# List folders under the org
gcloud resource-manager folders list --organization=$ORG_ID --format=json

# List all projects under org
gcloud projects list --filter="parent.id=$ORG_ID" --format=json

# Check project labels (data classification, environment tagging)
gcloud projects describe $PROJECT_ID --format=json
```

**Evaluate:**
- [ ] Organization node exists (not orphan projects)
- [ ] Folder structure reflects environments: prod / nonprod / sandbox
- [ ] Shared infrastructure projects exist: logging, KMS, secrets
- [ ] Projects have `environment` and `owner` labels
- [ ] No projects with `lifecycleState: DELETE_REQUESTED` still active

**Flag as CRITICAL if:** No org node — all IAM and org policy controls are unavailable.

---

## Step 2 — Essential Contacts

```bash
gcloud essential-contacts list --project=$PROJECT_ID --format=json
gcloud essential-contacts list --organization=$ORG_ID --format=json 2>/dev/null
```

**Evaluate:**
- [ ] Security contact configured at org or project level
- [ ] Technical contact configured
- [ ] Billing contact configured

**Flag as HIGH if:** No security contact — Google cannot notify you of security incidents.

---

## Step 3 — Org Policy Baseline

```bash
# List all org policies set on the project
gcloud org-policies list --project=$PROJECT_ID --format=json

# Describe each critical policy
POLICIES=(
  "constraints/iam.disableServiceAccountKeyCreation"
  "constraints/iam.disableServiceAccountKeyUpload"
  "constraints/iam.allowedPolicyMemberDomains"
  "constraints/compute.vmExternalIpAccess"
  "constraints/compute.requireOsLogin"
  "constraints/compute.skipDefaultNetworkCreation"
  "constraints/storage.uniformBucketLevelAccess"
  "constraints/storage.publicAccessPrevention"
  "constraints/run.allowedIngress"
  "constraints/run.allowedVPCEgress"
  "constraints/gcp.restrictCmekCryptoKeyProjects"
  "constraints/gcp.restrictNonCmekServices"
  "constraints/cloudkms.allowedProtectionLevels"
  "constraints/cloudkms.minimumDestroyScheduledDuration"
  "constraints/compute.restrictXpnProjectLienRemoval"
  "constraints/resourcemanager.allowedExportDestinations"
)

for policy in "${POLICIES[@]}"; do
  echo "=== $policy ==="
  gcloud org-policies describe $policy --project=$PROJECT_ID --format=json 2>/dev/null \
    || echo "NOT SET"
done
```

**Evaluate each policy:**

| Policy | Expected State | Severity if Missing |
|--------|---------------|---------------------|
| `iam.disableServiceAccountKeyCreation` | ENFORCED | HIGH |
| `iam.disableServiceAccountKeyUpload` | ENFORCED | HIGH |
| `iam.allowedPolicyMemberDomains` | Set to corp domain | HIGH |
| `compute.vmExternalIpAccess` | DENY ALL or allowlist | MEDIUM |
| `compute.requireOsLogin` | ENFORCED | MEDIUM |
| `compute.skipDefaultNetworkCreation` | ENFORCED | MEDIUM |
| `storage.uniformBucketLevelAccess` | ENFORCED | MEDIUM |
| `storage.publicAccessPrevention` | ENFORCED | HIGH |
| `run.allowedIngress` | internal / internal-and-cloud-load-balancing | MEDIUM |
| `gcp.restrictNonCmekServices` | Set for sensitive projects | LOW |
| `cloudkms.allowedProtectionLevels` | HSM for sensitive data | LOW |
| `cloudkms.minimumDestroyScheduledDuration` | >= 7 days | MEDIUM |

---

## Step 4 — Default Network Check

```bash
# Default VPC should not exist in production projects
gcloud compute networks list --project=$PROJECT_ID --format=json | \
  jq '.[] | select(.name == "default")'
```

**Flag as MEDIUM if:** Default network still exists — it has permissive firewall rules by default.

---

## Step 5 — Super Admin / Primitive Role Check

```bash
# Check for primitive roles at project level (owner, editor, viewer)
gcloud projects get-iam-policy $PROJECT_ID --format=json | \
  jq '.bindings[] | select(.role | test("roles/owner|roles/editor"))'

# Check for org-level owner bindings
gcloud organizations get-iam-policy $ORG_ID --format=json 2>/dev/null | \
  jq '.bindings[] | select(.role == "roles/owner")' 2>/dev/null
```

**Flag as CRITICAL if:** Any non-break-glass account has `roles/owner` or `roles/editor` at project/org level.

---

## Output

Write to:
- `scan-output/phases/phase-0-human.md` — narrative report of all findings
- `scan-output/phases/phase-0-state.json` — structured findings using schema in `schemas/finding.schema.json`
- `scan-output/audit/org-policy-gaps.md` — current vs target posture table with fix commands
