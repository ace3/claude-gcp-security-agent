# Internal Control ID Registry

All findings use stable Internal IDs in format: GCP-[CATEGORY]-[NUMBER]
This enables tracking findings across scan runs and mapping to compliance frameworks.

---

## GCP-IAM — Identity & Access Management

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-IAM-01 | SA has roles/editor or roles/owner | 1.5 | PR.AC-1 | CRITICAL |
| GCP-IAM-02 | SA has user-managed key age > 365 days | 1.4 | PR.AC-1 | CRITICAL |
| GCP-IAM-03 | SA has user-managed key age > 90 days | 1.4 | PR.AC-1 | HIGH |
| GCP-IAM-04 | SA unused 90+ days with active keys | 1.4 | ID.AM | HIGH |
| GCP-IAM-05 | Cloud Build default SA has roles/editor | 1.5 | PR.AC-1 | CRITICAL |
| GCP-IAM-06 | allUsers / allAuthenticatedUsers in project IAM | N/A | PR.AC-3 | CRITICAL |
| GCP-IAM-07 | External user (gmail.com etc) with project access | 1.1 | PR.AC-1 | HIGH |
| GCP-IAM-08 | SA impersonation chain (actAs / TokenCreator) | N/A | PR.AC-1 | HIGH |
| GCP-IAM-09 | Cross-project SA access undocumented | N/A | ID.AM | MEDIUM |
| GCP-IAM-10 | IAM Recommender flags unused permissions | N/A | PR.AC-1 | MEDIUM |
| GCP-IAM-11 | No Workload Identity Federation (WIF) for external CI | N/A | PR.AC-1 | HIGH |
| GCP-IAM-12 | SA key type USER_MANAGED when SYSTEM_MANAGED possible | 1.4 | PR.AC-1 | MEDIUM |
| GCP-IAM-13 | roles/owner at organization level (non-break-glass) | N/A | PR.AC-1 | CRITICAL |
| GCP-IAM-14 | No MFA enforcement for human users | 1.2 | PR.AC-1 | HIGH |
| GCP-IAM-15 | Default service account in use (not custom SA) | 1.1 | PR.AC-1 | HIGH |
| GCP-IAM-16 | KMS Admin and CryptoKey User on same principal (SoD) | N/A | PR.AC-4 | HIGH |
| GCP-IAM-17 | No org Essential Contacts configured | N/A | GV | HIGH |

---

## GCP-NET — Networking & Firewall

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-NET-01 | Firewall allows SSH (22) from 0.0.0.0/0 | 3.6 | PR.AC-3 | CRITICAL |
| GCP-NET-02 | Firewall allows RDP (3389) from 0.0.0.0/0 | 3.7 | PR.AC-3 | CRITICAL |
| GCP-NET-03 | Firewall allows all ports from 0.0.0.0/0 | 3.5 | PR.AC-3 | CRITICAL |
| GCP-NET-04 | Default VPC network still exists | 3.1 | PR.AC-5 | MEDIUM |
| GCP-NET-05 | Subnet with no VPC Flow Logs in prod | 3.8 | DE.CM-1 | HIGH |
| GCP-NET-06 | Firewall rule with 0 hits in 90 days | N/A | ID.AM | MEDIUM |
| GCP-NET-07 | Firewall Insights flags rule as overly permissive | N/A | PR.AC-3 | HIGH |
| GCP-NET-08 | No Cloud Armor on internet-facing load balancer | N/A | PR.PT-4 | HIGH |
| GCP-NET-09 | Instance has external IP (prefer Cloud NAT) | N/A | PR.AC-3 | MEDIUM |
| GCP-NET-10 | No IAP on admin/control-plane surfaces | N/A | PR.AC-3 | HIGH |
| GCP-NET-11 | VPC Service Controls not configured | N/A | PR.PT-4 | MEDIUM |
| GCP-NET-12 | Private Google Access disabled on subnet | N/A | PR.AC-3 | LOW |

---

## GCP-COMPUTE — Compute Engine

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-COMPUTE-01 | Shielded VM not enabled on instance | 4.8 | PR.PT-1 | HIGH |
| GCP-COMPUTE-02 | OS Login not enforced at project level | 4.4 | PR.AC-1 | HIGH |
| GCP-COMPUTE-03 | Project-wide SSH keys not blocked on instance | 4.3 | PR.AC-1 | HIGH |
| GCP-COMPUTE-04 | VM with external IP + open firewall | N/A | PR.AC-3 | CRITICAL |
| GCP-COMPUTE-05 | VM Manager / OS patching not enabled | N/A | PR.IP-12 | MEDIUM |
| GCP-COMPUTE-06 | Disk not encrypted with CMEK (sensitive workload) | 4.7 | PR.DS-1 | MEDIUM |

---

## GCP-STOR — Cloud Storage

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-STOR-01 | Bucket has allUsers or allAuthenticatedUsers binding | 5.1 | PR.AC-3 | CRITICAL |
| GCP-STOR-02 | Bucket public access prevention not enforced | 5.2 | PR.AC-3 | HIGH |
| GCP-STOR-03 | Bucket uses ACL mode not uniform bucket-level access | 5.3 | PR.AC-1 | HIGH |
| GCP-STOR-04 | Bucket versioning not enabled | 5.4 | PR.DS-3 | MEDIUM |
| GCP-STOR-05 | Bucket has no CMEK (sensitive data bucket) | N/A | PR.DS-1 | MEDIUM |
| GCP-STOR-06 | No lifecycle rules configured | N/A | PR.DS-3 | LOW |
| GCP-STOR-07 | No retention policy on compliance bucket | N/A | PR.DS-3 | HIGH |

---

## GCP-RUN — Cloud Run

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-RUN-01 | Cloud Run service allows unauthenticated invocations | N/A | PR.AC-3 | HIGH |
| GCP-RUN-02 | Cloud Run service uses default compute SA | N/A | PR.AC-1 | HIGH |
| GCP-RUN-03 | Cloud Run service not connected to VPC via connector | N/A | PR.AC-5 | MEDIUM |
| GCP-RUN-04 | Cloud Run ingress set to "all" (not internal) | N/A | PR.AC-3 | HIGH |
| GCP-RUN-05 | Cloud Run image from public registry (not internal AR) | N/A | PR.DS-6 | MEDIUM |

---

## GCP-BUILD — Cloud Build & CI/CD

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-BUILD-01 | Cloud Build default SA has roles/editor | N/A | PR.AC-1 | CRITICAL |
| GCP-BUILD-02 | No approval gate on production deployment trigger | N/A | PR.IP-1 | HIGH |
| GCP-BUILD-03 | Build uses public base image without pinned digest | N/A | PR.DS-6 | MEDIUM |
| GCP-BUILD-04 | Binary Authorization not enforced for Cloud Run | N/A | PR.DS-6 | HIGH |
| GCP-BUILD-05 | No build provenance / attestation configured | N/A | ID.SC | HIGH |
| GCP-BUILD-06 | No SBOM generated for built images | N/A | ID.SC | MEDIUM |

---

## GCP-AR — Artifact Registry

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-AR-01 | Deployed image has CRITICAL CVEs | N/A | PR.IP-12 | CRITICAL |
| GCP-AR-02 | Deployed image has HIGH CVEs | N/A | PR.IP-12 | HIGH |
| GCP-AR-03 | Vulnerability scanning not enabled | N/A | DE.CM-8 | HIGH |
| GCP-AR-04 | Image using EOL/unmaintained base OS | N/A | PR.IP-12 | HIGH |
| GCP-AR-05 | Image age > 90 days (not rebuilt/patched) | N/A | PR.IP-12 | MEDIUM |

---

## GCP-DATA — Data & Secrets

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-DATA-01 | Cloud SQL instance has public IP | 6.2 | PR.AC-3 | HIGH |
| GCP-DATA-02 | Cloud SQL authorized network is 0.0.0.0/0 | 6.5 | PR.AC-3 | CRITICAL |
| GCP-DATA-03 | Cloud SQL SSL not required | 6.1 | PR.DS-2 | HIGH |
| GCP-DATA-04 | Cloud SQL automated backups not enabled | 6.7 | RC.RP-1 | HIGH |
| GCP-DATA-05 | Secret with no rotation policy | N/A | PR.AC-1 | MEDIUM |
| GCP-DATA-06 | Secret accessed by multiple SAs | N/A | PR.AC-4 | MEDIUM |
| GCP-DATA-07 | KMS key rotation period > 365 days | 1.10 | PR.DS-1 | HIGH |
| GCP-DATA-08 | KMS Admin and Encrypter/Decrypter on same principal | N/A | PR.AC-4 | HIGH |
| GCP-DATA-09 | DLP findings in unexpected storage locations | N/A | ID.AM | HIGH |

---

## GCP-LOG — Logging & Detection

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-LOG-01 | No log sinks configured (logs not exported) | 2.2 | DE.CM-1 | HIGH |
| GCP-LOG-02 | Log sink disabled | 2.2 | DE.CM-1 | HIGH |
| GCP-LOG-03 | Data Access audit logs not enabled | 2.1 | DE.CM-7 | MEDIUM |
| GCP-LOG-04 | No alerting on IAM policy changes | 2.4 | DE.CM-3 | HIGH |
| GCP-LOG-05 | No alerting on SA key creation events | 2.4 | DE.CM-3 | HIGH |
| GCP-LOG-06 | No alerting on firewall rule changes | 2.7 | DE.CM-3 | HIGH |
| GCP-LOG-07 | No budget alerts configured | N/A | DE.CM-1 | MEDIUM |
| GCP-LOG-08 | SCC not enabled | N/A | DE.CM-7 | HIGH |
| GCP-LOG-09 | SCC finding muted without justification | N/A | DE.CM-7 | HIGH |
| GCP-LOG-10 | SCC active THREAT-category finding | N/A | DE.AE-2 | CRITICAL |

---

## GCP-ORG — Org Policy & Governance

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-ORG-01 | iam.disableServiceAccountKeyCreation not enforced | 1.4 | GV | HIGH |
| GCP-ORG-02 | iam.allowedPolicyMemberDomains not set | 1.8 | GV | HIGH |
| GCP-ORG-03 | storage.publicAccessPrevention not enforced | 5.2 | GV | HIGH |
| GCP-ORG-04 | compute.requireOsLogin not enforced | 4.4 | GV | HIGH |
| GCP-ORG-05 | compute.skipDefaultNetworkCreation not enforced | 3.1 | GV | MEDIUM |
| GCP-ORG-06 | No Organization node (orphan project) | N/A | GV | HIGH |
| GCP-ORG-07 | No folder structure (flat project hierarchy) | N/A | GV | MEDIUM |
| GCP-ORG-08 | No environment / owner labels on project | N/A | ID.AM | LOW |

---

## GCP-DR — Backup & Disaster Recovery

| ID | Title | CIS | NIST | Severity |
|----|-------|-----|------|----------|
| GCP-DR-01 | Cloud SQL no automated backup | 6.7 | RC.RP-1 | HIGH |
| GCP-DR-02 | Cloud SQL no HA / read replica | N/A | RC.RP-1 | MEDIUM |
| GCP-DR-03 | GCS critical bucket no versioning | 5.4 | RC.RP-1 | MEDIUM |
| GCP-DR-04 | No RPO/RTO documented for critical services | N/A | RC | MEDIUM |
