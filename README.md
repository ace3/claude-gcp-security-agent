# GCP Security Excellence Agent
## Claude Code Agent Documentation Package

---

## What This Is

A complete, self-contained agent documentation package that Claude Code can run
autonomously to audit a GCP project and produce security documentation aligned with:

- **NIST CSF 2.0** (Govern, Identify, Protect, Detect, Respond, Recover)
- **CIS GCP Benchmark v2.x** (L1 and L2 controls)
- **Google Security Foundations Blueprint**

---

## Package Contents

```
gcp-security-agent/
│
├── CLAUDE.md                      ← START HERE — master orchestrator
│
├── phases/
│   ├── PHASE-0.md                 ← Governance & landing zone
│   ├── PHASE-0.5.md               ← Threat model generation
│   ├── PHASE-1.md                 ← Service discovery
│   ├── PHASE-2.md                 ← Permission request generation (+ HUMAN GATE)
│   ├── PHASE-3.md                 ← Permission verification
│   ├── PHASE-4.md                 ← All technical scans (4a through 4f)
│   ├── PHASE-5.md                 ← Risk synthesis & scoring (+ HUMAN GATE)
│   └── PHASE-6-7.md               ← Output generation & scan integrity
│
└── schemas/
    ├── finding.schema.json         ← JSON schema for individual findings
    ├── phase-state.schema.json     ← JSON schema for phase handoff state
    └── control-id-registry.md     ← Stable GCP-XXX-NN IDs for all controls
```

---

## Quick Start

### Step 1 — Copy this package to your working directory

```bash
cp -r gcp-security-agent/ ~/my-gcp-audit/
cd ~/my-gcp-audit/
```

### Step 2 — Edit CLAUDE.md with your project details

```bash
# Edit the Project Configuration block at the top of CLAUDE.md
nano CLAUDE.md

# Set:
# PROJECT_ID="your-actual-project-id"
# ORG_ID="your-org-id"           (or leave blank)
# BILLING_ACCOUNT_ID="..."       (or leave blank)
# REVIEWER_NAME="Your Name"
```

### Step 3 — Start Claude Code

```bash
claude
```

### Step 4 — Run the audit

```
You: Run phase 1
```

Or to run everything with gates:
```
You: Run all
```

---

## Phase Flow Summary

```
Phase 0    Governance check (org, folders, org policies)
    ↓
Phase 0.5  Threat model (attack paths, crown jewels, blast radius)
    ↓
Phase 1    Service discovery (what's enabled in the project)
    ↓
Phase 2    Permission request generation
    ↓
    ⛔ HUMAN GATE: review roles, run grant script, confirm
    ↓
Phase 3    Permission verification (test every role before scanning)
    ↓
Phase 4a   Infrastructure (VMs, disks, VPC, firewall)
Phase 4b   Identity & access (SAs, users, keys, cross-project)
Phase 4c   Data & secrets (GCS, KMS, SQL, Secret Manager)
Phase 4d   Containers & supply chain (Cloud Run, AR, Cloud Build, BinAuthz)
Phase 4e   Runtime signals (SCC threats, audit log anomalies, cost signals)
Phase 4f   Detection & response readiness (sinks, alerting, runbook gaps)
    ↓
Phase 5    Risk synthesis (scored findings, project score, KPIs, top 10)
    ↓
    ⛔ HUMAN GATE: review findings, confirm before remediation docs published
    ↓
Phase 6    Full output generation (all docs, diagrams, IR playbooks)
    ↓
Phase 7    Scan integrity record (hashes, manifest, reviewer sign-off)
```

---

## Output Structure

```
scan-output/
├── docs/
│   ├── 00-overview.md             ← Executive summary + score
│   ├── 01-compute-network.md
│   ├── 02-storage.md
│   ├── 03-cloud-run.md
│   ├── 04-artifact-registry.md
│   ├── 05-cloud-build.md
│   ├── 06-service-accounts.md
│   ├── 07-threat-model.md
│   ├── remediation-plan.md        ← Top 10 with exact fix commands
│   └── quick-wins.md              ← HIGH+ findings fixable in < 5 min
├── audit/
│   ├── compliance-mapping.md      ← NIST + CIS control coverage
│   ├── sa-last-used-report.md
│   ├── sa-key-age-report.md
│   ├── orphaned-sa-report.md
│   ├── org-policy-gaps.md
│   ├── data-classification.md
│   ├── data-exposure-findings.md
│   ├── backup-dr-readiness.md
│   ├── cost-anomaly-signals.md
│   ├── sa-key-elimination-roadmap.md
│   └── security-kpis.md
├── diagrams/                      ← All Mermaid diagrams
│   ├── network-topology.md
│   ├── cicd-pipeline.md
│   ├── connectivity-map.md
│   ├── public-access-map.md
│   ├── service-account-map.md
│   ├── cross-project-trust-map.md
│   ├── blast-radius-map.md
│   ├── attack-paths.md
│   └── sa-risk-matrix.md
├── ir/
│   ├── plan.md
│   └── playbooks/
│       ├── iam-escalation.md
│       ├── public-exposure.md
│       └── credential-compromise.md
├── phases/                        ← Raw phase outputs (human + JSON)
├── errors/
│   └── permission-errors.log
├── MANIFEST.sha256                ← Integrity hashes of all files
└── SCAN-INTEGRITY.md              ← Audit trail + reviewer sign-off
```

---

## Recommended Scan Cadence

| Scan Type | Phases | Frequency |
|-----------|--------|-----------|
| Identity pulse | 4b, 4e | Weekly |
| Full posture | All phases | Monthly |
| Post-change | Relevant phase only | After infra changes |
| Pre-audit | All phases | Before compliance reviews |

---

## Customization

### Skip a phase
Tell Claude: `"Skip phase 4e and continue"`

### Add a custom check
Add a new section to the relevant PHASE-N.md file following the same pattern:
- Shell commands
- Evaluation criteria with severity
- Internal ID from the registry (or add new entry to `schemas/control-id-registry.md`)

### Add a new service
1. Add service check to PHASE-1.md services list
2. Add service → role mapping to PHASE-2.md
3. Add scan commands to the appropriate PHASE-4x.md
4. Add control IDs to `schemas/control-id-registry.md`

---

## Requirements

- `gcloud` CLI installed and authenticated
- Claude Code installed: `npm install -g @anthropic-ai/claude-code`
- For org-level checks: your personal gcloud auth needs org viewer access
- For project checks: the scanner SA with granted roles (generated by Phase 2)

---

## Security Notes

- The scanner SA is **read-only** — it cannot modify any resources
- SA key file (`gcp-scanner-key.json`) should be in `.gitignore`
- Delete the SA and key after the scan is complete:
  ```bash
  gcloud iam service-accounts delete gcp-doc-scanner@PROJECT.iam.gserviceaccount.com
  rm ./gcp-scanner-key.json
  ```
- Scan output may contain sensitive resource names and config details — treat as confidential

---

## Framework Alignment Summary

| Control Area | NIST CSF 2.0 | CIS GCP v2.x Section |
|-------------|-------------|---------------------|
| IAM & Identity | PR.AC, GV | Section 1 |
| Logging & Monitoring | DE.CM | Section 2 |
| Networking | PR.AC, PR.PT | Section 3 |
| Compute | PR.PT, PR.IP | Section 4 |
| Storage | PR.DS | Section 5 |
| BigQuery / Databases | PR.DS | Section 6 |
| Container Registry | PR.DS, ID.SC | Section 7 |
| Supply Chain | ID.SC, PR.IP | N/A (Google blueprint) |
| Incident Response | RS, RC | N/A |
| Governance | GV | N/A |
