# Phase 3 -- Firebase Security Rules Audit

**NIST Function**: PROTECT (PR.AC -- Access Control, PR.DS -- Data Security)
**Depends on**: `scan-output/phases/phase-1-state.json` (to know which data stores are enabled)
**Permissions needed**: `firebaserules.releases.get`, `firebaserules.rulesets.get`

---

## Objective

Audit Firebase Security Rules for Firestore, Realtime Database, and Cloud Storage.
Overly permissive rules are one of the most common Firebase security vulnerabilities.
Rules that allow public or any-authenticated-user access can expose entire databases.

**Key principle:** Legacy roles (`roles/editor`, `roles/owner`) bypass Firebase Security Rules entirely.
This means even well-written rules are ineffective if SAs or users hold these roles.
Phase 2 findings compound Phase 3 findings.

---

## Step 1 -- Firestore Security Rules

```bash
echo "=== Firestore Security Rules ==="

ACCESS_TOKEN=$(gcloud auth print-access-token)

# Check if Firestore release exists
FIRESTORE_RELEASE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://firebaserules.googleapis.com/v1/projects/$PROJECT_ID/releases/cloud.firestore" 2>/dev/null)

if echo "$FIRESTORE_RELEASE" | jq -e '.rulesetName' > /dev/null 2>/dev/null; then
  RULESET_NAME=$(echo "$FIRESTORE_RELEASE" | jq -r '.rulesetName')
  echo "Firestore ruleset: $RULESET_NAME"

  # Fetch the actual rules source
  RULES_SOURCE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://firebaserules.googleapis.com/v1/$RULESET_NAME" | \
    jq -r '.source.files[].content')
  echo "--- Firestore Rules Content ---"
  echo "$RULES_SOURCE"
else
  echo "No Firestore rules deployed or API not enabled"
fi
```

**Evaluate Firestore rules for:**

| Pattern | Severity | Internal ID |
|---------|----------|-------------|
| `allow read, write: if true;` | CRITICAL | FB-RULES-01 |
| `allow read, write: if request.auth != null;` (no granular checks) | HIGH | FB-RULES-02 |
| `allow read: if true;` (open read) | HIGH | FB-RULES-01 |
| `allow write: if true;` (open write) | CRITICAL | FB-RULES-01 |
| No rules deployed at all | CRITICAL | FB-RULES-07 |
| Rules that do not validate data schemas | MEDIUM | FB-RULES-10 |

---

## Step 2 -- Realtime Database Security Rules

```bash
echo "=== Realtime Database Rules ==="

ACCESS_TOKEN=$(gcloud auth print-access-token)

# List RTDB instances
RTDB_INSTANCES=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://firebasedatabase.googleapis.com/v1beta/projects/$PROJECT_ID/locations/-/instances" 2>/dev/null)

echo "RTDB instances:"
echo "$RTDB_INSTANCES" | jq '.instances[]?.name' 2>/dev/null || echo "No RTDB instances found"

# Get RTDB rules for default instance
RTDB_RULES=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://$PROJECT_ID-default-rtdb.firebaseio.com/.settings/rules.json" 2>/dev/null)
echo "--- Default RTDB Rules ---"
echo "$RTDB_RULES" | jq . 2>/dev/null || echo "Could not fetch RTDB rules"

# If there are additional RTDB instances, fetch their rules too
echo "$RTDB_INSTANCES" | jq -r '.instances[]?.databaseUrl' 2>/dev/null | \
while IFS= read -r DB_URL; do
  if [ -n "$DB_URL" ]; then
    echo "--- Rules for $DB_URL ---"
    curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
      "$DB_URL/.settings/rules.json" 2>/dev/null | jq . || echo "Could not fetch rules"
  fi
done
```

**Evaluate RTDB rules for:**

| Pattern | Severity | Internal ID |
|---------|----------|-------------|
| `".read": true, ".write": true` | CRITICAL | FB-RULES-03 |
| `".read": "auth != null", ".write": "auth != null"` | HIGH | FB-RULES-04 |
| No rules deployed / default open rules | CRITICAL | FB-RULES-08 |
| No `.validate` rules | MEDIUM | FB-RULES-10 |

---

## Step 3 -- Firebase Storage Security Rules

```bash
echo "=== Firebase Storage Rules ==="

ACCESS_TOKEN=$(gcloud auth print-access-token)

# Get Storage rules release
STORAGE_RELEASE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://firebaserules.googleapis.com/v1/projects/$PROJECT_ID/releases/firebase.storage/$PROJECT_ID.appspot.com" 2>/dev/null)

if echo "$STORAGE_RELEASE" | jq -e '.rulesetName' > /dev/null 2>/dev/null; then
  STORAGE_RULESET=$(echo "$STORAGE_RELEASE" | jq -r '.rulesetName')
  echo "Storage ruleset: $STORAGE_RULESET"

  # Fetch the actual rules source
  RULES_SOURCE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://firebaserules.googleapis.com/v1/$STORAGE_RULESET" | \
    jq -r '.source.files[].content')
  echo "--- Storage Rules Content ---"
  echo "$RULES_SOURCE"
else
  echo "No Storage rules deployed or API not enabled"
fi
```

**Evaluate Storage rules for:**

| Pattern | Severity | Internal ID |
|---------|----------|-------------|
| `allow read, write: if true;` | CRITICAL | FB-RULES-05 |
| `allow read, write: if request.auth != null;` | HIGH | FB-RULES-06 |
| No Storage rules deployed | CRITICAL | FB-RULES-09 |
| No file size limits | MEDIUM | FB-RULES-10 |
| No content type validation | MEDIUM | FB-RULES-10 |

---

## Evaluation Summary

| Finding | Severity | Internal ID |
|---------|----------|-------------|
| Firestore rules allow open read/write | CRITICAL | FB-RULES-01 |
| Firestore rules allow any authenticated user full access | HIGH | FB-RULES-02 |
| RTDB rules allow open read/write | CRITICAL | FB-RULES-03 |
| RTDB rules allow any authenticated user full access | HIGH | FB-RULES-04 |
| Storage rules allow open read/write | CRITICAL | FB-RULES-05 |
| Storage rules allow any authenticated user full access | HIGH | FB-RULES-06 |
| No Firestore rules deployed | CRITICAL | FB-RULES-07 |
| No RTDB rules deployed or default rules active | CRITICAL | FB-RULES-08 |
| No Storage rules deployed | CRITICAL | FB-RULES-09 |
| Security rules lack data validation | MEDIUM | FB-RULES-10 |

---

## Output

- `scan-output/phases/phase-3-human.md` -- security rules analysis report
- `scan-output/phases/phase-3-state.json` -- structured findings
- `scan-output/docs/02-security-rules.md` -- full rules analysis document

Include the raw rules content in the human-readable report for reviewer reference.
