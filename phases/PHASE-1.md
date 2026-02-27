# Phase 1 -- Firebase Discovery

**NIST Function**: IDENTIFY (ID.AM -- Asset Management)
**Depends on**: Current gcloud user authentication
**Permissions needed**: `serviceusage.services.list`, `firebase.projects.get` (included in roles/viewer)

---

## Objective

Discover the Firebase project configuration: which Firebase services are enabled,
what apps are registered, which service accounts exist (especially Firebase-created ones),
and what data stores are in use. This drives all subsequent audit phases.

---

## Step 1 -- Verify Authentication

```bash
echo "=== Pre-flight Check ==="
echo "Active account: $(gcloud auth list --filter=status:ACTIVE --format='value(account)')"
echo "Active project: $(gcloud config get-value project 2>/dev/null)"
echo ""

# Verify project access
gcloud projects describe $PROJECT_ID --format=json
```

If this fails, stop and instruct the user to run `gcloud auth login` and `gcloud config set project $PROJECT_ID`.

---

## Step 2 -- Firebase Service Discovery

```bash
echo "=== Firebase Service Discovery ==="
echo "Project: $PROJECT_ID"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

FIREBASE_SERVICES=(
  # Core Firebase
  "firebase.googleapis.com"
  "firebasehosting.googleapis.com"
  "firebasestorage.googleapis.com"
  "firebaseauth.googleapis.com"
  "firebasedatabase.googleapis.com"
  "firebaserules.googleapis.com"
  "firebaseextensions.googleapis.com"
  "firebaseappcheck.googleapis.com"
  "firebaseremoteconfig.googleapis.com"
  "fcm.googleapis.com"
  # Data stores
  "firestore.googleapis.com"
  "storage.googleapis.com"
  # Compute (Firebase-adjacent)
  "cloudfunctions.googleapis.com"
  "run.googleapis.com"
  # Identity
  "identitytoolkit.googleapis.com"
  "iam.googleapis.com"
  "cloudresourcemanager.googleapis.com"
  # Supporting
  "secretmanager.googleapis.com"
  "logging.googleapis.com"
  "cloudbuild.googleapis.com"
)

ENABLED=()
DISABLED=()

for SERVICE in "${FIREBASE_SERVICES[@]}"; do
  STATUS=$(gcloud services list \
    --project="$PROJECT_ID" \
    --filter="name:$SERVICE" \
    --format="value(state)" 2>/dev/null)

  if [ "$STATUS" = "ENABLED" ]; then
    ENABLED+=("$SERVICE")
    echo "ENABLED   $SERVICE"
  else
    DISABLED+=("$SERVICE")
    echo "DISABLED  $SERVICE"
  fi
done

echo ""
echo "=== Summary ==="
echo "Enabled:  ${#ENABLED[@]}"
echo "Disabled: ${#DISABLED[@]}"
```

---

## Step 3 -- Firebase App Registration

```bash
echo "=== Firebase Apps ==="

# Android apps
gcloud firebase android apps list --project=$PROJECT_ID --format=json 2>/dev/null || echo "No Android apps or firebase CLI unavailable"

# iOS apps
gcloud firebase ios apps list --project=$PROJECT_ID --format=json 2>/dev/null || echo "No iOS apps or firebase CLI unavailable"

# Web apps
gcloud firebase web apps list --project=$PROJECT_ID --format=json 2>/dev/null || echo "No Web apps or firebase CLI unavailable"
```

---

## Step 4 -- Service Account Inventory

```bash
echo "=== Service Account Inventory ==="

# List all service accounts
gcloud iam service-accounts list --project=$PROJECT_ID --format=json

# Highlight Firebase-related SAs:
# - firebase-adminsdk-xxxxx@PROJECT_ID.iam.gserviceaccount.com  (Firebase Admin SDK)
# - PROJECT_ID@appspot.gserviceaccount.com                      (App Engine default / Firebase)
# - PROJECT_NUMBER@cloudservices.gserviceaccount.com             (Google APIs SA)
# - PROJECT_ID@gcf-admin-robot.iam.gserviceaccount.com           (Cloud Functions)
# - service-PROJECT_NUMBER@gcf-admin-robot.iam.gserviceaccount.com
# - service-PROJECT_NUMBER@firebase-rules.iam.gserviceaccount.com
# - service-PROJECT_NUMBER@gcp-sa-firebasestorage.iam.gserviceaccount.com

gcloud iam service-accounts list --project=$PROJECT_ID --format=json | \
  jq '[.[] | select(.email | test("firebase|appspot|gcf-admin|cloudservices|cloudbuild"))] |
  {firebase_related_sas: [.[].email], total_sas: length}'
```

---

## Step 5 -- Data Store Discovery

```bash
echo "=== Firestore Databases ==="
gcloud firestore databases list --project=$PROJECT_ID --format=json 2>/dev/null || echo "No Firestore databases found"

echo ""
echo "=== Storage Buckets ==="
# Firebase creates specific buckets:
# - PROJECT_ID.appspot.com          (default Firebase Storage)
# - PROJECT_ID.firebaseapp.com      (Firebase Hosting)
# - staging.PROJECT_ID.appspot.com
# - us.artifacts.PROJECT_ID.appspot.com  (Container Registry)
gcloud storage buckets list --project=$PROJECT_ID --format=json 2>/dev/null || echo "No buckets found"

echo ""
echo "=== Realtime Database Instances ==="
ACCESS_TOKEN=$(gcloud auth print-access-token)
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://firebasedatabase.googleapis.com/v1beta/projects/$PROJECT_ID/locations/-/instances" 2>/dev/null | jq . || echo "No RTDB instances or API not enabled"
```

---

## Step 6 -- Write Phase State

After running discovery, write `scan-output/phases/phase-1-state.json`:

```json
{
  "phase": "1",
  "timestamp": "<ISO8601>",
  "project_id": "<PROJECT_ID>",
  "status": "COMPLETE",
  "enabled_services": ["firebase.googleapis.com", "..."],
  "disabled_services": ["..."],
  "firebase_services": ["firebase.googleapis.com", "..."],
  "firebase_apps": [
    {"platform": "android", "app_id": "...", "display_name": "..."}
  ],
  "service_accounts": [
    {"email": "...", "firebase_related": true}
  ],
  "data_stores": {
    "firestore_databases": [],
    "rtdb_instances": [],
    "storage_buckets": []
  },
  "summary": {
    "enabled_count": 0,
    "disabled_count": 0,
    "firebase_sa_count": 0,
    "total_sa_count": 0
  }
}
```

---

## Output

- `scan-output/phases/phase-1-human.md` -- readable Firebase service inventory
- `scan-output/phases/phase-1-state.json` -- machine-readable for subsequent phases

**No findings generated in this phase. Output is purely informational.**
