# Phase 4 -- Public Exposure & Resource Audit

**NIST Function**: PROTECT (PR.AC, PR.DS) + DETECT (DE.CM)
**Depends on**: `scan-output/phases/phase-1-state.json`
**Permissions needed**: `storage.buckets.getIamPolicy`, `cloudfunctions.functions.getIamPolicy`, `logging.logEntries.list`

---

## Objective

Identify publicly accessible resources, check Firebase Auth configuration, verify
App Check enforcement, and review recent audit logs for suspicious IAM activity.

---

## Step 1 -- allUsers/allAuthenticatedUsers in Project IAM

```bash
echo "=== Public Bindings in Project IAM ==="
gcloud projects get-iam-policy $PROJECT_ID --format=json | \
  jq '[.bindings[] | select(.members[] | test("allUsers|allAuthenticatedUsers"))]'
```

---

## Step 2 -- Firebase Storage Bucket Public Access

```bash
echo "=== Storage Bucket Security ==="

gcloud storage buckets list --project=$PROJECT_ID --format="value(name)" | \
while IFS= read -r BUCKET; do
  echo "=== Bucket: $BUCKET ==="

  # Check IAM for public access
  PUBLIC=$(gcloud storage buckets get-iam-policy "gs://$BUCKET" --format=json 2>/dev/null | \
    jq '[.bindings[] | select(.members[] | test("allUsers|allAuthenticatedUsers"))]' 2>/dev/null)
  if [ "$PUBLIC" != "[]" ] && [ -n "$PUBLIC" ] && [ "$PUBLIC" != "null" ]; then
    echo "PUBLIC ACCESS DETECTED: $BUCKET"
    echo "$PUBLIC"
  fi

  # Check bucket configuration
  gcloud storage buckets describe "gs://$BUCKET" --format=json 2>/dev/null | \
    jq '{name: .name,
         publicAccessPrevention: .iamConfiguration.publicAccessPrevention,
         uniformBucketLevelAccess: .iamConfiguration.uniformBucketLevelAccess.enabled,
         location: .location}'
done
```

---

## Step 3 -- Cloud Functions Public Invocation

```bash
echo "=== Cloud Functions Security ==="

# Cloud Functions v1 (often used as Firebase Functions)
gcloud functions list --project=$PROJECT_ID --format=json 2>/dev/null

# Check each function for public invoker
gcloud functions list --project=$PROJECT_ID --format="value(name,region)" 2>/dev/null | \
while IFS=$'\t' read -r NAME REGION; do
  if [ -n "$NAME" ]; then
    POLICY=$(gcloud functions get-iam-policy "$NAME" \
      --region="$REGION" --format=json 2>/dev/null)
    PUBLIC=$(echo "$POLICY" | \
      jq '[.bindings[] | select(.members[] | test("allUsers|allAuthenticatedUsers")) |
      select(.role | test("invoker"))]' 2>/dev/null)
    if [ "$PUBLIC" != "[]" ] && [ -n "$PUBLIC" ] && [ "$PUBLIC" != "null" ]; then
      echo "PUBLIC FUNCTION: $NAME ($REGION)"
      echo "$PUBLIC"
    fi
  fi
done

# Cloud Functions v2 (Cloud Run backed)
gcloud functions list --gen2 --project=$PROJECT_ID --format=json 2>/dev/null || true
```

---

## Step 4 -- Firebase Hosting

```bash
echo "=== Firebase Hosting ==="

ACCESS_TOKEN=$(gcloud auth print-access-token)

# List Firebase Hosting sites
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://firebasehosting.googleapis.com/v1beta1/projects/$PROJECT_ID/sites" | jq . 2>/dev/null

# Hosting sites expose which Functions/Cloud Run services are publicly routable
# via rewrites. Document each hosting site and its rewrite targets.
```

---

## Step 5 -- Firebase Auth Configuration

```bash
echo "=== Firebase Auth Configuration ==="

ACCESS_TOKEN=$(gcloud auth print-access-token)

# Identity Toolkit (Firebase Auth) config
AUTH_CONFIG=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://identitytoolkit.googleapis.com/admin/v2/projects/$PROJECT_ID/config" 2>/dev/null)

echo "$AUTH_CONFIG" | jq . 2>/dev/null || echo "Firebase Auth not configured or API not enabled"

# Extract key security settings:
# - Sign-in providers enabled
# - Email enumeration protection
# - MFA configuration
# - Authorized domains
echo "--- Sign-in Providers ---"
echo "$AUTH_CONFIG" | jq '.signIn' 2>/dev/null

echo "--- Authorized Domains ---"
echo "$AUTH_CONFIG" | jq '.authorizedDomains' 2>/dev/null

echo "--- MFA Config ---"
echo "$AUTH_CONFIG" | jq '.mfa' 2>/dev/null
```

---

## Step 6 -- Firebase App Check

```bash
echo "=== Firebase App Check ==="

ACCESS_TOKEN=$(gcloud auth print-access-token)

# Check if App Check is configured
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://firebaseappcheck.googleapis.com/v1/projects/$PROJECT_ID/apps" | jq . 2>/dev/null || \
  echo "App Check not configured or API not enabled"
```

---

## Step 7 -- Audit Log Review

```bash
echo "=== Recent IAM Changes (last 30 days) ==="

# IAM policy changes
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy" AND resource.type="project"' \
  --project=$PROJECT_ID \
  --freshness=30d \
  --limit=50 \
  --format=json 2>/dev/null | \
  jq '[.[] | {timestamp, who: .protoPayload.authenticationInfo.principalEmail,
  resource: .resource.type}]' 2>/dev/null || echo "Could not read audit logs"

echo ""
echo "=== SA Key Creation Events (last 30 days) ==="

gcloud logging read \
  'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' \
  --project=$PROJECT_ID \
  --freshness=30d \
  --format=json 2>/dev/null | \
  jq '[.[] | {timestamp, who: .protoPayload.authenticationInfo.principalEmail,
  sa: .protoPayload.request.name}]' 2>/dev/null || echo "Could not read audit logs"
```

---

## Evaluation Criteria

| Finding | Severity | Internal ID |
|---------|----------|-------------|
| allUsers/allAuthenticatedUsers in project IAM | CRITICAL | FB-PUB-01 |
| Firebase Storage bucket publicly accessible | CRITICAL | FB-PUB-02 |
| Firebase Storage bucket uses legacy ACLs (not uniform) | HIGH | FB-PUB-03 |
| Firebase Storage bucket public access prevention not enforced | HIGH | FB-PUB-04 |
| Cloud Function has allUsers invoker | HIGH | FB-PUB-05 |
| Firebase Auth email enumeration not protected | MEDIUM | FB-AUTH-01 |
| Firebase Auth no MFA configured | MEDIUM | FB-AUTH-02 |
| Firebase App Check not configured | MEDIUM | FB-AUTH-03 |
| No authorized domain restrictions in Firebase Auth | HIGH | FB-AUTH-04 |
| Recent IAM policy change granting legacy roles | HIGH | FB-LOG-01 |
| Recent SA key creation event | HIGH | FB-LOG-02 |

---

## Output

- `scan-output/phases/phase-4-human.md` -- public exposure analysis report
- `scan-output/phases/phase-4-state.json` -- structured findings
- `scan-output/docs/03-public-exposure.md` -- public access findings document
