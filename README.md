# Firebase Security Audit Agent

## Claude Code Agent for Firebase Legacy Role Auditing

---

## What This Is

A self-contained Claude Code agent that audits a Firebase/GCP project for security
issues, with a focus on **legacy role (Editor/Owner) misuse** -- the most common and
dangerous security anti-pattern in Firebase projects.

Framework alignment:
- **NIST CSF 2.0** (Govern, Identify, Protect, Detect, Respond, Recover)
- **Firebase Security Best Practices**
- **Google Cloud IAM Best Practices**

---

## Why Legacy Roles Matter in Firebase

Firebase automatically grants `roles/editor` to service accounts it creates (e.g., the
Admin SDK SA). This is a security risk because:

- **`roles/editor` bypasses all Firebase Security Rules** -- even well-crafted Firestore,
  RTDB, and Storage rules are ineffective against principals with Editor
- **Full project read/write** -- a compromised SA with Editor can access every resource
- **Common accumulation** -- Firebase projects often have multiple SAs with Editor
  (Admin SDK, App Engine default, Cloud Build, Cloud Functions)

This agent systematically finds and documents all legacy role bindings with exact
remediation commands to replace them with least-privilege alternatives.

---

## Package Contents

```
gcp-security-agent/
|
+-- CLAUDE.md                      <- START HERE -- master orchestrator
|
+-- phases/
|   +-- PHASE-1.md                 <- Firebase discovery
|   +-- PHASE-2.md                 <- IAM & legacy role audit (core)
|   +-- PHASE-3.md                 <- Firebase security rules audit
|   +-- PHASE-4.md                 <- Public exposure & resource audit
|   +-- PHASE-5.md                 <- Risk synthesis & remediation (+ REVIEW GATE)
|
+-- schemas/
    +-- finding.schema.json        <- JSON schema for findings
    +-- phase-state.schema.json    <- JSON schema for phase handoff state
    +-- control-id-registry.md     <- Stable FB-XXX-NN IDs for all controls
```

---

## Quick Start

### Step 1 -- Configure

```bash
cp config.example.env config.local.env
# Edit config.local.env with your project ID
```

### Step 2 -- Authenticate

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

This agent runs as your current gcloud user. No scanner service account is needed.

### Step 3 -- Start Claude Code

```bash
claude
```

### Step 4 -- Run the audit

```
You: Run phase 1
```

Or to run everything:
```
You: Run all
```

---

## Phase Flow

```
Phase 1    Firebase discovery (services, apps, SAs, data stores)
    |
Phase 2    IAM & legacy role audit (Editor/Owner detection)
    |
Phase 3    Firebase security rules (Firestore, RTDB, Storage)
    |
Phase 4    Public exposure (allUsers, Functions, Hosting, Auth, App Check)
    |
Phase 5    Risk synthesis & remediation plan
    |
    [REVIEW GATE] -- human reviews findings before final docs
    |
    Final docs (overview, remediation plan, quick wins)
```

---

## Output Structure

```
scan-output/
+-- phases/                        <- Raw phase outputs (human + JSON)
+-- docs/
|   +-- 00-overview.md             <- Executive summary + score
|   +-- 01-iam-legacy-roles.md     <- Legacy role findings
|   +-- 02-security-rules.md       <- Rules audit
|   +-- 03-public-exposure.md      <- Public access findings
|   +-- remediation-plan.md        <- Prioritized with fix commands
|   +-- quick-wins.md              <- HIGH+ fixes in < 5 min
+-- diagrams/
|   +-- sa-role-map.md             <- SA-to-role Mermaid diagram
|   +-- legacy-role-blast-radius.md
+-- errors/
|   +-- permission-errors.log
+-- SCAN-INTEGRITY.md
```

---

## Control ID Registry

All findings use stable IDs in format `FB-[CATEGORY]-[NUMBER]`:

| Category | Controls | Focus |
|----------|----------|-------|
| FB-IAM | 13 controls | Legacy roles, SA keys, external access |
| FB-RULES | 10 controls | Firestore, RTDB, Storage security rules |
| FB-PUB | 5 controls | Public exposure |
| FB-AUTH | 4 controls | Firebase Auth configuration |
| FB-LOG | 2 controls | Audit trail |

Full registry: `schemas/control-id-registry.md`

---

## Requirements

- `gcloud` CLI installed and authenticated
- Claude Code installed: `npm install -g @anthropic-ai/claude-code`
- Current gcloud user needs sufficient permissions to read IAM policies and Firebase config
  (typically `roles/viewer` + `roles/iam.securityReviewer` on the project)

---

## Security Notes

- This agent is **read-only** -- it does not modify any resources or IAM policies
- Scan output may contain sensitive resource names and config details -- treat as confidential
- The REVIEW GATE ensures a human reviews all findings before remediation docs are finalized
- Remediation commands in the output are provided for reference -- run them manually after review

---

## Customization

### Skip a phase
Tell Claude: `"Skip phase 3 and continue"`

### Add a custom check
Add a new section to the relevant PHASE-N.md following the same pattern:
- Shell commands
- Evaluation criteria with severity
- Internal ID from the registry (or add a new entry to `schemas/control-id-registry.md`)

---

## Recommended Scan Cadence

| Scan Type | Phases | Frequency |
|-----------|--------|-----------|
| IAM pulse | 2 | Weekly |
| Full posture | All | Monthly |
| Post-change | Relevant phase | After IAM or rules changes |
| Pre-audit | All | Before compliance reviews |
