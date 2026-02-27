# Phase 3 — Permission Verification

**NIST Function**: GOVERN
**Depends on**: Human having run grant-permissions.sh and confirmed gate cleared
**Scanner SA needed**: YES — activates and tests the SA for the first time

---

## Objective

Verify every granted role actually works before beginning the real scan.
Catch permission gaps now, not mid-scan. Log all failures cleanly.

---

## Step 1 — Activate Scanner SA

```bash
export CLOUDSDK_CORE_PROJECT="$PROJECT_ID"

# Validate PROJECT_ID before using it in shell commands
if ! [[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
  echo "Invalid PROJECT_ID format: $PROJECT_ID" >&2
  exit 1
fi

SCANNER_SA="gcp-doc-scanner@${PROJECT_ID}.iam.gserviceaccount.com"

# Keyless auth path (recommended): impersonate the scanner SA
gcloud config set project "$PROJECT_ID"
gcloud config set auth/impersonate_service_account "$SCANNER_SA"

# Optional legacy fallback only if impersonation cannot be used:
# gcloud auth activate-service-account --key-file=./gcp-scanner-key.json
```

---

## Step 2 — Test Each Permission

Run one test command per role. Record PASS or FAIL for each.

```bash
echo "=== Permission Verification ==="
echo "SA: $(gcloud config get-value account)"
echo "Project: $PROJECT_ID"
echo ""

run_test() {
  local TEST_NAME="$1"
  shift
  if "$@" > /dev/null 2>&1; then
    echo "✅ PASS  $TEST_NAME"
    echo "{\"test\": \"$TEST_NAME\", \"status\": \"PASS\"}"
  else
    echo "❌ FAIL  $TEST_NAME"
    echo "{\"test\": \"$TEST_NAME\", \"status\": \"FAIL\"}"
  fi
}

# Base
run_test "roles/viewer"                 gcloud projects describe "$PROJECT_ID"
run_test "roles/iam.securityReviewer"   gcloud projects get-iam-policy "$PROJECT_ID" --limit=1

# Compute (if enabled)
run_test "roles/compute.viewer"         gcloud compute instances list --limit=1
run_test "roles/recommender.firewallViewer" \
  gcloud recommender recommendations list --recommender=google.compute.firewall.Recommender \
  --project="$PROJECT_ID" --location=global --limit=1

# Cloud Run (if enabled)
run_test "roles/run.viewer"             gcloud run services list --platform=managed --limit=1

# Cloud Storage (if enabled)
run_test "roles/storage.legacyBucketReader" \
  gcloud storage buckets list --limit=1

# Cloud Build (if enabled)
run_test "roles/cloudbuild.builds.viewer" \
  gcloud builds list --limit=1

# Artifact Registry (if enabled)
run_test "roles/artifactregistry.reader" \
  gcloud artifacts repositories list --limit=1

# IAM
run_test "roles/iam.serviceAccountViewer" \
  gcloud iam service-accounts list --limit=1

# Secret Manager (if enabled)
run_test "roles/secretmanager.viewer"   gcloud secrets list --limit=1

# Logging
run_test "roles/logging.viewer"         \
  gcloud logging read 'timestamp>="2020-01-01T00:00:00Z"' --limit=1

# Monitoring
run_test "roles/monitoring.viewer"      \
  gcloud monitoring dashboards list --limit=1

# KMS (if enabled)
run_test "roles/cloudkms.viewer"        \
  gcloud kms keyrings list --location=global --limit=1

# Recommender (IAM)
run_test "roles/recommender.iamViewer"  \
  gcloud recommender recommendations list \
  --recommender=google.iam.policy.Recommender \
  --project="$PROJECT_ID" --location=global --limit=1

# Org policy
run_test "roles/orgpolicy.policyViewer" \
  gcloud org-policies list --project="$PROJECT_ID" --limit=1

# SCC (if enabled)
run_test "roles/securitycenter.findingsViewer" \
  gcloud scc findings list "projects/$PROJECT_ID" --limit=1
```

---

## Step 3 — Evaluate Results

```
If ALL tests PASS:
  → Write phase-3-state.json with status: "READY"
  → Proceed to Phase 4a automatically

If 1-3 tests FAIL:
  → Write phase-3-state.json with status: "PARTIAL"
  → List failed permissions
  → Note which Phase 4 sub-phases will be skipped or degraded
  → Ask human: "N permission tests failed. Proceed with partial scan? (yes/no)"

If >3 tests FAIL or core roles fail (roles/viewer, roles/iam.securityReviewer):
  → Write phase-3-state.json with status: "BLOCKED"
  → Stop and print remediation instructions
  → Do not proceed to Phase 4
```

---

## Step 4 — Write Phase State

`scan-output/phases/phase-3-state.json`:

```json
{
  "phase": "3",
  "timestamp": "<ISO8601>",
  "project_id": "<PROJECT_ID>",
  "sa_email": "gcp-doc-scanner@<PROJECT_ID>.iam.gserviceaccount.com",
  "status": "READY | PARTIAL | BLOCKED",
  "tests": [
    {"test": "roles/viewer", "status": "PASS"},
    {"test": "roles/compute.viewer", "status": "FAIL"}
  ],
  "passed_count": 0,
  "failed_count": 0,
  "skipped_phases": [],
  "scan_integrity": {
    "claude_md_hash": "<sha256 of CLAUDE.md>",
    "scan_start": "<ISO8601>"
  }
}
```

---

## Output

- `scan-output/phases/phase-3-human.md` — verification report
- `scan-output/phases/phase-3-state.json` — pass/fail per permission
- `scan-output/errors/permission-errors.log` — details of any failures
