# Phase 1 — Service Discovery

**NIST Function**: IDENTIFY (ID.AM — Asset Management)
**CIS Controls**: Prerequisite to all
**Depends on**: Standard gcloud auth (no scanner SA needed yet)
**Permissions needed**: `serviceusage.services.list` (included in roles/viewer)

---

## Objective

Discover which GCP services are enabled in this project.
This drives Phase 2 — only request permissions for services that are actually enabled.
Never assume. Never request excess permissions.

---

## Step 1 — Run Service Discovery

```bash
PROJECT_ID="YOUR_PROJECT_ID"

echo "=== GCP Service Discovery ==="
echo "Project: $PROJECT_ID"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Full list of services to check
SERVICES=(
  # Compute & Network
  "compute.googleapis.com"
  "container.googleapis.com"
  "run.googleapis.com"
  "cloudfunctions.googleapis.com"
  "appengine.googleapis.com"
  "vpcaccess.googleapis.com"
  "servicenetworking.googleapis.com"
  "dns.googleapis.com"
  "networkconnectivity.googleapis.com"
  "iap.googleapis.com"
  "cloudarmor.googleapis.com"
  # Storage & Data
  "storage.googleapis.com"
  "sqladmin.googleapis.com"
  "bigtable.googleapis.com"
  "datastore.googleapis.com"
  "firestore.googleapis.com"
  "redis.googleapis.com"
  "bigquery.googleapis.com"
  "spanner.googleapis.com"
  # CI/CD & Containers
  "cloudbuild.googleapis.com"
  "artifactregistry.googleapis.com"
  "containeranalysis.googleapis.com"
  "binaryauthorization.googleapis.com"
  # Identity & Security
  "iam.googleapis.com"
  "secretmanager.googleapis.com"
  "cloudkms.googleapis.com"
  "accesscontextmanager.googleapis.com"
  "orgpolicy.googleapis.com"
  "recommender.googleapis.com"
  "securitycenter.googleapis.com"
  # Messaging & Integration
  "pubsub.googleapis.com"
  "eventarc.googleapis.com"
  "workflows.googleapis.com"
  # Observability
  "logging.googleapis.com"
  "monitoring.googleapis.com"
  "cloudtrace.googleapis.com"
  "clouddebugger.googleapis.com"
  # Billing
  "cloudbilling.googleapis.com"
  "billingbudgets.googleapis.com"
)

ENABLED=()
DISABLED=()

for SERVICE in "${SERVICES[@]}"; do
  STATUS=$(gcloud services list \
    --project="$PROJECT_ID" \
    --filter="name:$SERVICE" \
    --format="value(state)" 2>/dev/null)

  if [ "$STATUS" = "ENABLED" ]; then
    ENABLED+=("$SERVICE")
    echo "✅ ENABLED   $SERVICE"
  else
    DISABLED+=("$SERVICE")
    echo "⬜ DISABLED  $SERVICE"
  fi
done

echo ""
echo "=== Summary ==="
echo "Enabled:  ${#ENABLED[@]}"
echo "Disabled: ${#DISABLED[@]}"
echo ""
ENABLED_SERVICES_JSON=$(printf '%s\n' "${ENABLED[@]}" | jq -R . | jq -s .)
echo "Enabled services JSON: $ENABLED_SERVICES_JSON"
```

---

## Step 2 — Write Phase State

After running the discovery, write `scan-output/phases/phase-1-state.json`:

```json
{
  "phase": "1",
  "timestamp": "<ISO8601>",
  "project_id": "<PROJECT_ID>",
  "enabled_services": [
    "compute.googleapis.com",
    "run.googleapis.com"
  ],
  "disabled_services": [
    "container.googleapis.com"
  ],
  "summary": {
    "enabled_count": 0,
    "disabled_count": 0
  }
}
```

---

## Output

- `scan-output/phases/phase-1-human.md` — readable service inventory
- `scan-output/phases/phase-1-state.json` — machine-readable for Phase 2 consumption

**No findings generated in this phase. Output is purely informational.**
