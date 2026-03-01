# Firewall Phase 4 -- Effective Firewall & Exposure Analysis

**NIST Function**: IDENTIFY (ID.RA -- Risk Assessment) + DETECT (DE.CM -- Continuous Monitoring)
**Depends on**: `scan-output-firewall/phases/phase-1-state.json`, `phase-2-state.json`, `phase-3-state.json`
**Permissions needed**: `compute.instances.getEffectiveFirewalls`, `compute.instances.list`

---

## Objective

Determine the actual exposure of each Compute Engine instance by examining effective
firewalls (the combined result of hierarchical policies, network policies, and VPC rules).
Identify internet-reachable instances, detect orphaned firewall tags, and generate
Mermaid diagrams for network topology, ingress blast radius, and rule evaluation chains.

**Why effective firewalls matter:**
- Individual VPC rules and policies don't tell the full story -- evaluation order matters
- An instance's actual exposure is the result of ALL applicable rules combined
- Instances with public IPs + permissive ingress rules are directly internet-reachable
- Mermaid diagrams provide visual blast-radius analysis for stakeholder communication

---

## Step 1 -- Effective Firewalls per Instance

For each instance with an external IP (from Phase 1 state), retrieve the combined
effective firewall rules.

```bash
echo "=== Effective Firewalls for Internet-Exposed Instances ==="

# Get instances with external IPs from phase-1 state
gcloud compute instances list --project=$PROJECT_ID --format=json | \
  jq -r '.[] | select(.networkInterfaces[]?.accessConfigs[]?.natIP != null) |
  "\(.name) \(.zone | split("/") | last)"' | \
while IFS=' ' read -r INSTANCE ZONE; do
  echo "=== Instance: $INSTANCE (zone: $ZONE) ==="

  # Get effective firewalls
  gcloud compute instances get-effective-firewalls "$INSTANCE" \
    --zone="$ZONE" \
    --project=$PROJECT_ID \
    --format=json 2>/dev/null | jq .

  echo ""
done
```

For each instance, analyze the effective firewall output:
- List all INGRESS ALLOW rules that apply
- Identify the most permissive rule (widest source range + most ports)
- Check if any DENY rules provide protection
- Determine which policy/VPC level each rule comes from

---

## Step 2 -- Internet-Reachable Instance Analysis

Cross-reference instances with external IPs against permissive ingress rules.

```bash
echo "=== Internet-Reachable Instance Summary ==="

gcloud compute instances list --project=$PROJECT_ID --format=json | \
  jq '[.[] | select(.networkInterfaces[]?.accessConfigs[]?.natIP != null) |
  {name: .name,
   zone: (.zone | split("/") | last),
   externalIP: [.networkInterfaces[].accessConfigs[]?.natIP] | first,
   internalIP: [.networkInterfaces[].networkIP] | first,
   network: [.networkInterfaces[] | .network | split("/") | last] | first,
   tags: (.tags.items // []),
   serviceAccounts: [.serviceAccounts[]?.email],
   status: .status}]'
```

For each instance with an external IP:
1. Check Phase 2 findings: does any FW-VPC-01/02/04/05/10 rule target this instance (via tags or lack of target)?
2. Map: `instance → applicable permissive rules → exposed ports`
3. Determine effective exposure: what ports/protocols can the internet reach?

### Findings

**FW-NET-01** (HIGH): Instance with public IP and permissive 0.0.0.0/0 ingress
- Why: This instance is directly reachable from the internet on one or more ports. Combined with any service vulnerability, this enables remote exploitation.
- Record for each: instance name, zone, external IP, exposed ports, applicable rule names

**FW-NET-02** (MEDIUM): Instance with public IP (informational)
- Why: Public IPs increase attack surface even with restrictive firewall rules. Prefer internal-only instances behind load balancers where possible.
- Not generated if FW-NET-01 already covers the instance.

---

## Step 3 -- Generate Mermaid Diagrams

### 3a -- Network Topology Diagram

Generate `scan-output-firewall/diagrams/network-topology.md`:

```markdown
# Network Topology

```mermaid
graph TB
  subgraph Project["PROJECT_ID"]

    subgraph VPC_default["VPC: default"]
      subgraph subnet_default_us["us-central1 (10.128.0.0/20)"]
        instance1["instance-1<br/>10.128.0.2<br/>tags: web-server"]
        instance2["instance-2<br/>10.128.0.3<br/>tags: app-server"]
      end
      subgraph subnet_default_eu["europe-west1 (10.132.0.0/20)"]
        instance3["instance-3<br/>10.132.0.2<br/>tags: db-server"]
      end
    end

    subgraph VPC_custom["VPC: custom-network"]
      subgraph subnet_custom["us-east1 (10.0.0.0/24)"]
        instance4["instance-4<br/>10.0.0.2"]
      end
    end

  end

  INTERNET((Internet))

  %% Instances with external IPs
  INTERNET -.->|"34.x.x.x"| instance1
  INTERNET -.->|"35.x.x.x"| instance4

  style instance1 fill:#ff6b6b,stroke:#c92a2a
  style instance4 fill:#ff6b6b,stroke:#c92a2a
  style instance3 fill:#51cf66,stroke:#2b8a3e
```
```

The agent should populate this template dynamically with:
- Actual VPC networks and subnets from Phase 1 state
- Actual instances grouped by subnet
- Instances with external IPs highlighted in red
- Internal-only instances in green

### 3b -- Ingress Exposure Map (Blast Radius)

Generate `scan-output-firewall/diagrams/ingress-exposure-map.md`:

```markdown
# Ingress Exposure Map

```mermaid
graph LR
  INTERNET((("Internet<br/>0.0.0.0/0")))

  subgraph Rules["Permissive Firewall Rules"]
    R1["default-allow-ssh<br/>tcp:22<br/>priority:65534"]
    R2["allow-http<br/>tcp:80,443<br/>priority:1000"]
    R3["allow-all-traffic<br/>all protocols<br/>priority:1000"]
  end

  subgraph Targets["Affected Instances"]
    I1["instance-1<br/>34.x.x.x<br/>tags: web-server"]
    I2["instance-2<br/>35.x.x.x<br/>no tags"]
    I3["instance-3<br/>36.x.x.x<br/>tags: web-server"]
  end

  INTERNET -->|"0.0.0.0/0"| R1
  INTERNET -->|"0.0.0.0/0"| R2
  INTERNET -->|"0.0.0.0/0"| R3

  R1 -->|"ALL instances<br/>(no target tags)"| I1
  R1 -->|"ALL instances"| I2
  R1 -->|"ALL instances"| I3

  R2 -->|"tag: web-server"| I1
  R2 -->|"tag: web-server"| I3

  R3 -->|"ALL instances"| I1
  R3 -->|"ALL instances"| I2
  R3 -->|"ALL instances"| I3

  style R1 fill:#ffa94d,stroke:#e8590c
  style R3 fill:#ff6b6b,stroke:#c92a2a
  style I2 fill:#ff6b6b,stroke:#c92a2a
```
```

The agent should populate this template dynamically with:
- All 0.0.0.0/0 ingress ALLOW rules from Phase 2
- Instances affected by each rule (matched by tags or all instances if no tags)
- Color-coded severity (red = CRITICAL, orange = HIGH)
- Show which instances are hit by multiple permissive rules

### 3c -- Rule Evaluation Chain

Generate `scan-output-firewall/diagrams/rule-evaluation-chain.md`:

```markdown
# Firewall Rule Evaluation Chain

```mermaid
graph TB
  PACKET["Incoming Packet"]

  subgraph L1["1. Hierarchical Firewall Policies"]
    direction TB
    HP_ORG["Org Policy"]
    HP_FOLDER["Folder Policy"]
    HP_ORG --> HP_FOLDER
  end

  subgraph L2["2. Network Firewall Policies"]
    NP["Network Policy Rules<br/>(sorted by priority)"]
  end

  subgraph L3["3. VPC Firewall Rules"]
    VPC["VPC Rules<br/>(sorted by priority)"]
  end

  IMPLIED["4. Implied Rules<br/>deny-all-ingress<br/>allow-all-egress"]

  PACKET --> L1

  HP_FOLDER -->|"allow"| ALLOW_GREEN["ALLOW ✓"]
  HP_FOLDER -->|"deny"| DENY_RED["DENY ✗"]
  HP_FOLDER -->|"goto_next"| L2

  NP -->|"allow"| ALLOW_GREEN2["ALLOW ✓"]
  NP -->|"deny"| DENY_RED2["DENY ✗"]
  NP -->|"goto_next"| L3

  VPC -->|"allow"| ALLOW_GREEN3["ALLOW ✓"]
  VPC -->|"deny"| DENY_RED3["DENY ✗"]
  VPC -->|"no match"| IMPLIED

  IMPLIED -->|"ingress"| DENY_RED4["DENY ✗"]
  IMPLIED -->|"egress"| ALLOW_GREEN4["ALLOW ✓"]

  style ALLOW_GREEN fill:#51cf66,stroke:#2b8a3e
  style ALLOW_GREEN2 fill:#51cf66,stroke:#2b8a3e
  style ALLOW_GREEN3 fill:#51cf66,stroke:#2b8a3e
  style ALLOW_GREEN4 fill:#51cf66,stroke:#2b8a3e

  style DENY_RED fill:#ff6b6b,stroke:#c92a2a
  style DENY_RED2 fill:#ff6b6b,stroke:#c92a2a
  style DENY_RED3 fill:#ff6b6b,stroke:#c92a2a
  style DENY_RED4 fill:#ff6b6b,stroke:#c92a2a
```
```

The agent should:
- Populate with actual policies/rules found in phases 1-3
- Show which rules matched and their actions
- Highlight where policy-level allows override VPC-level denies (if FW-POL-05 was found)

---

## Step 4 -- Orphaned Firewall Tag Detection

Identify network tags referenced in firewall rules but not present on any instance.

```bash
echo "=== Orphaned Firewall Tags ==="

# Tags in firewall rules (targetTags)
RULE_TAGS=$(gcloud compute firewall-rules list --project=$PROJECT_ID --format=json | \
  jq '[.[].targetTags // [] | .[]] | unique | sort')

# Tags on instances
INSTANCE_TAGS=$(gcloud compute instances list --project=$PROJECT_ID --format=json | \
  jq '[.[].tags.items // [] | .[]] | unique | sort')

echo "Tags in firewall rules: $RULE_TAGS"
echo "Tags on instances: $INSTANCE_TAGS"

# Find tags in rules but not on any instance
echo "--- Orphaned tags (in rules, not on instances) ---"
# The agent should compare these two arrays and report differences
```

### Finding: FW-NET-03

| Field | Value |
|-------|-------|
| Internal ID | FW-NET-03 |
| Title | Orphaned firewall rule tags |
| Severity | LOW |
| NIST | ID.AM |
| Why | Tags referenced in firewall rules but not on any instance indicate stale rules. These create confusion about the security posture and may indicate decommissioned resources whose rules were not cleaned up. |
| Remediation | Review orphaned tags. Delete firewall rules targeting tags that are no longer in use. |

---

## Evaluation Criteria

| Finding | Severity | Internal ID |
|---------|----------|-------------|
| Instance with public IP and permissive 0.0.0.0/0 ingress | HIGH | FW-NET-01 |
| Instance with public IP (informational) | MEDIUM | FW-NET-02 |
| Orphaned firewall rule tags | LOW | FW-NET-03 |

---

## Output

- `scan-output-firewall/phases/phase-4-human.md` -- readable exposure analysis report
- `scan-output-firewall/phases/phase-4-state.json` -- structured findings + diagram metadata
- `scan-output-firewall/docs/03-exposure-analysis.md` -- detailed exposure findings document
- `scan-output-firewall/diagrams/network-topology.md` -- VPC → subnets → instances Mermaid diagram
- `scan-output-firewall/diagrams/ingress-exposure-map.md` -- Internet → rules → instances blast radius
- `scan-output-firewall/diagrams/rule-evaluation-chain.md` -- Policy evaluation order diagram
