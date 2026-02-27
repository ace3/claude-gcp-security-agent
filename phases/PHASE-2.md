# Phase 2 — Permission Request Generation

**NIST Function**: GOVERN (GV.PO — Policy)
**Depends on**: `scan-output/phases/phase-1-state.json`
**Scanner SA needed**: NOT YET — this phase generates the grant commands

---

## Objective

Read Phase 1 output. Generate the exact minimum IAM roles needed for the enabled
services only. Produce a grant script and a human checklist.
Never request roles for disabled services.

---

## Service → Role Mapping

```
compute.googleapis.com          → roles/compute.viewer
                                  roles/recommender.firewallViewer
run.googleapis.com              → roles/run.viewer
                                  roles/vpcaccess.viewer
storage.googleapis.com          → roles/storage.objectViewer
                                  roles/storage.legacyBucketReader
cloudbuild.googleapis.com       → roles/cloudbuild.builds.viewer
artifactregistry.googleapis.com → roles/artifactregistry.reader
containeranalysis.googleapis.com→ roles/containeranalysis.occurrencesViewer
binaryauthorization.googleapis.com → roles/binaryauthorization.policyViewer
sqladmin.googleapis.com         → roles/cloudsql.viewer
redis.googleapis.com            → roles/redis.viewer
bigquery.googleapis.com         → roles/bigquery.metadataViewer
bigtable.googleapis.com         → roles/bigtable.viewer
spanner.googleapis.com          → roles/spanner.viewer
pubsub.googleapis.com           → roles/pubsub.viewer
secretmanager.googleapis.com    → roles/secretmanager.viewer
cloudkms.googleapis.com         → roles/cloudkms.viewer
container.googleapis.com        → roles/container.viewer
dns.googleapis.com              → roles/dns.reader
monitoring.googleapis.com       → roles/monitoring.viewer
logging.googleapis.com          → roles/logging.viewer
securitycenter.googleapis.com   → roles/securitycenter.findingsViewer
recommender.googleapis.com      → roles/recommender.iamViewer
iam.googleapis.com              → roles/iam.serviceAccountViewer
orgpolicy.googleapis.com        → roles/orgpolicy.policyViewer
accesscontextmanager.googleapis.com → roles/accesscontextmanager.policyReader
billingbudgets.googleapis.com   → roles/billing.viewer
cloudfunctions.googleapis.com   → roles/cloudfunctions.viewer
appengine.googleapis.com        → roles/appengine.appViewer
eventarc.googleapis.com         → roles/eventarc.viewer
workflows.googleapis.com        → roles/workflows.viewer
```

**Always include regardless of enabled services:**
```
roles/viewer                    ← base project metadata
roles/iam.securityReviewer      ← IAM bindings across all resources
```

---

## Step 1 — Read Phase 1 State

Read `scan-output/phases/phase-1-state.json` and extract `enabled_services`.

---

## Step 2 — Generate Outputs

### 2a. Permission Table

Write to `scan-output/phases/phase-2-human.md`:

```markdown
## Permissions Required for Project: <PROJECT_ID>
## Generated: <TIMESTAMP>

Based on enabled services discovered in Phase 1.

| # | Service | Role | What It Reads | Sensitivity |
|---|---------|------|---------------|-------------|
| 1 | Compute | roles/compute.viewer | VMs, disks, firewalls, VPCs | Low |
...

**Total roles to grant: N**
**Always-on roles: roles/viewer, roles/iam.securityReviewer**
```

### 2b. Grant Script

Write to `scan-output/phases/grant-permissions.sh`:

```bash
#!/bin/bash
# GCP Security Scanner — Permission Grant Script
# Generated: <TIMESTAMP>
# Project: <PROJECT_ID>
# Review this script before running. Each grant is commented.

set -euo pipefail

PROJECT_ID="<PROJECT_ID>"
SA_NAME="gcp-doc-scanner"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "=== GCP Security Scanner — Permission Grant ==="
echo "Project:  $PROJECT_ID"
echo "SA email: $SA_EMAIL"
echo ""

# ── Step 0: Reset impersonation so all grants run as the human account ─────────
# A previous run may have left auth/impersonate_service_account set in gcloud
# config. All add-iam-policy-binding calls MUST run as the human operator.
echo "Clearing any active impersonation (grants must run as human user)..."
gcloud config unset auth/impersonate_service_account 2>/dev/null || true
echo "  Active account: $(gcloud config get-value account)"
echo ""

# ── Step 1: Create service account ─────────────────────────────────────────
echo "Creating service account (skip if already exists)..."
gcloud iam service-accounts create "$SA_NAME" \
  --display-name="GCP Security Scanner (read-only)" \
  --description="Scanner SA for security audit — read-only, keyless impersonation only" \
  --project="$PROJECT_ID" 2>/dev/null || echo "  SA already exists, skipping create."

echo ""

# ── Step 2: Grant always-on roles ───────────────────────────────────────

# Always-on: base metadata
echo "Granting roles/viewer (base project metadata)..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/viewer" \
  --condition=None

# Always-on: IAM visibility
echo "Granting roles/iam.securityReviewer (IAM policy visibility)..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/iam.securityReviewer" \
  --condition=None

echo ""

# ── Step 3: Grant service-specific roles (enabled services only) ────────────

# <one block per enabled service, with comment>

# ── Step 4: Grant serviceAccountTokenCreator to the human operator ──────────
# Required for keyless impersonation. Without this the human user cannot
# generate tokens for the scanner SA and all impersonated calls will fail
# with PERMISSION_DENIED / iam.serviceAccounts.getAccessToken.
HUMAN_ACCOUNT=$(gcloud config get-value account)
echo "Granting roles/iam.serviceAccountTokenCreator to ${HUMAN_ACCOUNT}..."
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --member="user:${HUMAN_ACCOUNT}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project="$PROJECT_ID"

echo ""

# ── Step 5: Enable keyless impersonation in gcloud config ───────────────────
echo "Configuring keyless impersonation (no key file created)..."
gcloud config set project "$PROJECT_ID"
gcloud config set auth/impersonate_service_account "$SA_EMAIL"

echo ""
echo "=== Done ==="
echo "Scanner SA is configured for keyless impersonation."
echo "Run scan-output/phases/verify-permissions.sh to confirm all roles took effect."
echo "Then tell Claude: \"Gate cleared, continue to phase 3\""
```

### 2c. Verification Script

Write to `scan-output/phases/verify-permissions.sh`:

```bash
#!/bin/bash
# GCP Security Scanner — Permission Verification Script
# Run after grant-permissions.sh to confirm all roles applied

set -euo pipefail

PROJECT_ID="<PROJECT_ID>"
SA_EMAIL="gcp-doc-scanner@${PROJECT_ID}.iam.gserviceaccount.com"
IMPER="--impersonate-service-account=${SA_EMAIL}"

PASS=0
FAIL=0

# Always start as human — capability tests pass explicit impersonation flag
gcloud config unset auth/impersonate_service_account 2>/dev/null || true

echo "=== GCP Security Scanner — Permission Verification ==="
echo "SA:      $SA_EMAIL"
echo "Human:   $(gcloud config get-value account)"
echo "Project: $PROJECT_ID"
echo ""

run_test() {
  local TEST_NAME="$1"
  shift
  if "$@" > /dev/null 2>&1; then
    echo "PASS  $TEST_NAME"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $TEST_NAME"
    FAIL=$((FAIL + 1))
  fi
}

# Tests use explicit $IMPER flag to verify SA capabilities regardless of
# ambient gcloud config state.
echo "--- Base roles ---"
run_test "roles/viewer" \
  gcloud projects describe "$PROJECT_ID" $IMPER
run_test "roles/iam.securityReviewer" \
  gcloud projects get-iam-policy "$PROJECT_ID" --limit=1 $IMPER

echo ""
echo "--- Service roles ---"
# <one run_test block per service-specific role, with $IMPER flag>

echo ""
echo "=== Summary ==="
echo "PASS: $PASS  FAIL: $FAIL"

# IAM policy read runs as human (no impersonation) to list what the SA was granted
echo ""
echo "=== Granted roles for SA (read as human) ==="
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:${SA_EMAIL}" \
  --format="table(bindings.role)"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "WARNING: $FAIL test(s) failed. Resolve before telling Claude to continue."
  exit 1
else
  echo ""
  echo "All tests passed. You may tell Claude: \"Gate cleared, continue to phase 3\""
fi
```

### 2d. Human Checklist

Append to `scan-output/phases/phase-2-human.md`:

```markdown
## Pre-Scan Checklist

Complete all items before proceeding to Phase 3.

### Service Account Setup
- [ ] Service account `gcp-doc-scanner@PROJECT.iam.gserviceaccount.com` created
- [ ] `gcloud config set auth/impersonate_service_account gcp-doc-scanner@PROJECT.iam.gserviceaccount.com` set
- [ ] No user-managed SA key created for scanner SA

### Roles Granted (tick each after running grant-permissions.sh)
- [ ] roles/viewer
- [ ] roles/iam.securityReviewer
<one line per required role>

### Verification
- [ ] `verify-permissions.sh` run successfully
- [ ] `gcloud compute instances list` returns data (not permission error)
- [ ] Reviewer name recorded: _______________

### Ready to proceed
- [ ] ALL above items checked
- [ ] Tell Claude: "Gate cleared, continue to phase 3"
```

---

## Step 3 — Write Phase State

`scan-output/phases/phase-2-state.json`:

```json
{
  "phase": "2",
  "timestamp": "<ISO8601>",
  "project_id": "<PROJECT_ID>",
  "sa_email": "gcp-doc-scanner@<PROJECT_ID>.iam.gserviceaccount.com",
  "roles_requested": [
    "roles/viewer",
    "roles/iam.securityReviewer"
  ],
  "roles_per_service": {
    "compute.googleapis.com": ["roles/compute.viewer"],
    "run.googleapis.com": ["roles/run.viewer"]
  },
  "scripts_generated": [
    "scan-output/phases/grant-permissions.sh",
    "scan-output/phases/verify-permissions.sh"
  ]
}
```

---

## ⛔ HUMAN GATE — PERMISSION GATE

```
════════════════════════════════════════════════════════
  HUMAN GATE: PERMISSION GATE
════════════════════════════════════════════════════════

  Phase 2 complete. I have generated:
  ✅ Permission table: scan-output/phases/phase-2-human.md
  ✅ Grant script:     scan-output/phases/grant-permissions.sh
  ✅ Verify script:    scan-output/phases/verify-permissions.sh
  ✅ Checklist:        (in phase-2-human.md)

  YOU MUST NOW:
  1. Review the permission table — confirm all roles are acceptable
  2. Run: bash scan-output/phases/grant-permissions.sh
  3. Run: bash scan-output/phases/verify-permissions.sh
  4. Complete the checklist in phase-2-human.md
  5. Tell me: "Gate cleared, continue to phase 3"

  I will not proceed until you confirm.
════════════════════════════════════════════════════════
```
