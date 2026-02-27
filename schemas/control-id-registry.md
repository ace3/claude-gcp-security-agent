# Firebase Security Control ID Registry

All findings use stable Internal IDs in format: FB-[CATEGORY]-[NUMBER]
This enables tracking findings across scan runs and mapping to NIST CSF 2.0.

---

## FB-IAM -- Identity & Legacy Roles

| ID | Title | NIST | Severity |
|----|-------|------|----------|
| FB-IAM-01 | Firebase Admin SDK SA has roles/editor | PR.AC-1 | CRITICAL |
| FB-IAM-02 | App Engine default SA has roles/editor | PR.AC-1 | CRITICAL |
| FB-IAM-03 | Cloud Build default SA has roles/editor | PR.AC-1 | CRITICAL |
| FB-IAM-04 | Human user has roles/editor at project level | PR.AC-1 | CRITICAL |
| FB-IAM-05 | Human user has roles/owner at project level | PR.AC-1 | CRITICAL |
| FB-IAM-06 | Group has roles/editor or roles/owner | PR.AC-1 | CRITICAL |
| FB-IAM-07 | SA has user-managed keys | PR.AC-1 | HIGH |
| FB-IAM-08 | SA user-managed key age > 90 days | PR.AC-1 | HIGH |
| FB-IAM-09 | SA user-managed key age > 365 days | PR.AC-1 | CRITICAL |
| FB-IAM-10 | Cross-project SA with editor/owner | PR.AC-1 | HIGH |
| FB-IAM-11 | External user (gmail etc) with any role | PR.AC-1 | HIGH |
| FB-IAM-12 | Cloud Functions SA has roles/editor | PR.AC-1 | CRITICAL |
| FB-IAM-13 | Google APIs SA has roles/editor (expected but document) | ID.AM | LOW |

---

## FB-RULES -- Firebase Security Rules

| ID | Title | NIST | Severity |
|----|-------|------|----------|
| FB-RULES-01 | Firestore rules allow open read/write | PR.AC-3 | CRITICAL |
| FB-RULES-02 | Firestore rules allow any authenticated user full access | PR.AC-3 | HIGH |
| FB-RULES-03 | RTDB rules allow open read/write | PR.AC-3 | CRITICAL |
| FB-RULES-04 | RTDB rules allow any authenticated user full access | PR.AC-3 | HIGH |
| FB-RULES-05 | Storage rules allow open read/write | PR.AC-3 | CRITICAL |
| FB-RULES-06 | Storage rules allow any authenticated user full access | PR.AC-3 | HIGH |
| FB-RULES-07 | No Firestore rules deployed | PR.AC-3 | CRITICAL |
| FB-RULES-08 | No RTDB rules deployed or default rules active | PR.AC-3 | CRITICAL |
| FB-RULES-09 | No Storage rules deployed | PR.AC-3 | CRITICAL |
| FB-RULES-10 | Security rules lack data validation | PR.DS-1 | MEDIUM |

---

## FB-PUB -- Public Exposure

| ID | Title | NIST | Severity |
|----|-------|------|----------|
| FB-PUB-01 | allUsers/allAuthenticatedUsers in project IAM | PR.AC-3 | CRITICAL |
| FB-PUB-02 | Firebase Storage bucket publicly accessible | PR.AC-3 | CRITICAL |
| FB-PUB-03 | Firebase Storage bucket uses legacy ACLs (not uniform) | PR.AC-1 | HIGH |
| FB-PUB-04 | Firebase Storage bucket public access prevention not enforced | PR.AC-3 | HIGH |
| FB-PUB-05 | Cloud Function has allUsers invoker | PR.AC-3 | HIGH |

---

## FB-AUTH -- Firebase Authentication

| ID | Title | NIST | Severity |
|----|-------|------|----------|
| FB-AUTH-01 | Firebase Auth email enumeration not protected | PR.AC-1 | MEDIUM |
| FB-AUTH-02 | Firebase Auth no MFA configured | PR.AC-1 | MEDIUM |
| FB-AUTH-03 | Firebase App Check not configured | PR.AC-7 | MEDIUM |
| FB-AUTH-04 | No authorized domain restrictions in Firebase Auth | PR.AC-3 | HIGH |

---

## FB-LOG -- Logging & Audit Trail

| ID | Title | NIST | Severity |
|----|-------|------|----------|
| FB-LOG-01 | Recent IAM policy change granting legacy roles | DE.CM-3 | HIGH |
| FB-LOG-02 | Recent SA key creation event | DE.CM-3 | HIGH |
