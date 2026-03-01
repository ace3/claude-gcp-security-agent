# Firewall Phase 2 -- VPC Firewall Rules Audit

**NIST Function**: PROTECT (PR.AC -- Access Control, PR.DS -- Data Security)
**Depends on**: `scan-output-firewall/phases/phase-1-state.json`
**Permissions needed**: `compute.firewalls.list`, `compute.firewalls.get`

---

## Objective

This is the core audit phase. Analyze all VPC firewall rules for security
misconfigurations: overly permissive source ranges (0.0.0.0/0), wide-open protocols,
exposed management ports (SSH/RDP), untargeted rules, and dangerous default rules.

**Why VPC firewall misconfigurations are dangerous:**
- `0.0.0.0/0` ingress rules expose resources to the entire internet
- Allow-all-traffic rules bypass any intent of network segmentation
- SSH (22) and RDP (3389) from anywhere give attackers direct login capability
- Rules without target tags apply to ALL instances in the network
- Default rules (`default-allow-ssh`, `default-allow-rdp`) are often left active and forgotten

---

## Step 1 -- Full Firewall Rule Extraction

```bash
echo "=== VPC Firewall Rules ==="
FIREWALL_RULES=$(gcloud compute firewall-rules list --project=$PROJECT_ID --format=json)
echo "$FIREWALL_RULES" | jq .
```

---

## Step 2 -- 0.0.0.0/0 Ingress Detection

Identify all INGRESS ALLOW rules with `0.0.0.0/0` or `::/0` in sourceRanges.

```bash
echo "=== 0.0.0.0/0 Ingress Rules ==="
echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.direction == "INGRESS" and .allowed != null and
  (.sourceRanges[]? == "0.0.0.0/0" or .sourceRanges[]? == "::/0"))]'
```

### Evaluation

For each matching rule:
- Generate finding **FW-VPC-01** (CRITICAL)
- Record: rule name, network, allowed protocols/ports, targetTags, priority, disabled status
- If the rule also allows all protocols (Step 3), it compounds with FW-VPC-02


### Finding: FW-VPC-01

| Field | Value |
|-------|-------|
| Internal ID | FW-VPC-01 |
| Title | VPC firewall rule allows ingress from 0.0.0.0/0 |
| Severity | CRITICAL |
| NIST | PR.AC-3 |
| Why | Any resource in the target scope is reachable from the entire internet. Attackers can directly probe, exploit, or brute-force exposed services. |
| Remediation | Restrict `sourceRanges` to specific trusted CIDRs (e.g., office IP, VPN range, load balancer health check ranges). |

---

## Step 3 -- Wide Open Ports / Allow-All Traffic

Identify rules that allow all protocols or have no port restriction.

```bash
echo "=== Allow-All Traffic Rules ==="

# Rules allowing all protocols
echo "--- Allow all protocols ---"
echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.direction == "INGRESS" and
  (.allowed[]?.IPProtocol == "all"))]'

# Rules with excessively broad port ranges (> 100 ports)
echo "--- Broad port range rules ---"
echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.direction == "INGRESS" and .allowed != null) |
  {name: .name, network: (.network | split("/") | last),
   allowed: .allowed, sourceRanges: .sourceRanges,
   targetTags: .targetTags, priority: .priority} |
  select(.allowed[]? | .ports[]? |
  if (. | test("-")) then
    (. | split("-") | (.[1] | tonumber) - (.[0] | tonumber)) > 100
  else false end)]'
```

### Findings

**FW-VPC-02** (CRITICAL): Rule allows all traffic (`IPProtocol: "all"`)
- Why: No network segmentation -- all protocols and ports are open. This is equivalent to having no firewall rule at all.
- Remediation: Replace with specific protocol/port allow rules for required services only.

**FW-VPC-03** (HIGH): Rule allows excessively broad port range (>100 ports)
- Why: Large port ranges increase attack surface significantly. Legitimate services use specific ports.
- Remediation: Narrow port range to only the specific ports required.

---

## Step 4 -- SSH/RDP from Anywhere

Specifically detect management protocol exposure from the internet.

```bash
echo "=== SSH from 0.0.0.0/0 ==="
echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.direction == "INGRESS" and
  (.sourceRanges[]? == "0.0.0.0/0" or .sourceRanges[]? == "::/0") and
  (.allowed[]? | .IPProtocol == "tcp" and (.ports[]? | test("^22$|^22-22$"))))]'

echo "=== RDP from 0.0.0.0/0 ==="
echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.direction == "INGRESS" and
  (.sourceRanges[]? == "0.0.0.0/0" or .sourceRanges[]? == "::/0") and
  (.allowed[]? | .IPProtocol == "tcp" and (.ports[]? | test("^3389$|^3389-3389$"))))]'
```

### Findings

**FW-VPC-04** (CRITICAL): SSH (port 22) exposed to 0.0.0.0/0
- Why: SSH access from the entire internet enables brute-force attacks and exploitation of SSH vulnerabilities. This is the #1 most common firewall misconfiguration in GCP.
- Remediation: Restrict to specific trusted CIDRs, or use IAP TCP forwarding (`gcloud compute ssh --tunnel-through-iap`).
- Remediation command:
```bash
# Option A: Restrict to specific CIDR
gcloud compute firewall-rules update RULE_NAME \
  --source-ranges="OFFICE_CIDR" \
  --project=$PROJECT_ID

# Option B: Delete and use IAP instead (recommended)
gcloud compute firewall-rules delete RULE_NAME --project=$PROJECT_ID

# Create IAP-based SSH rule:
gcloud compute firewall-rules create allow-ssh-iap \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges="35.235.240.0/20" \
  --target-tags=allow-ssh \
  --project=$PROJECT_ID
```

**FW-VPC-05** (CRITICAL): RDP (port 3389) exposed to 0.0.0.0/0
- Why: RDP from internet is a primary ransomware entry vector. RDP vulnerabilities (BlueKeep, etc.) are actively exploited.
- Remediation: Remove the rule. Use IAP TCP forwarding or a VPN for Windows remote access.
- Remediation command:
```bash
gcloud compute firewall-rules delete RULE_NAME --project=$PROJECT_ID

# Create IAP-based RDP rule:
gcloud compute firewall-rules create allow-rdp-iap \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:3389 \
  --source-ranges="35.235.240.0/20" \
  --target-tags=allow-rdp \
  --project=$PROJECT_ID
```

---

## Step 5 -- No-Target Rules (Applies to All Instances)

Identify permissive INGRESS ALLOW rules with no `targetTags` or `targetServiceAccounts`.
These apply to **every instance** in the specified network.

```bash
echo "=== Untargeted Permissive Rules ==="
echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.direction == "INGRESS" and .allowed != null and
  (.targetTags == null or .targetTags == []) and
  (.targetServiceAccounts == null or .targetServiceAccounts == []) and
  (.sourceRanges[]? == "0.0.0.0/0" or .sourceRanges[]? == "::/0"))]'
```

### Finding: FW-VPC-06

| Field | Value |
|-------|-------|
| Internal ID | FW-VPC-06 |
| Title | Permissive firewall rule has no target restriction |
| Severity | HIGH |
| NIST | PR.AC-3 |
| Why | Without target tags or service account filters, this rule applies to ALL instances in the VPC network -- including instances that should not be internet-exposed. |
| Remediation | Add `--target-tags=TAG` to scope the rule to specific instances. |

---

## Step 6 -- Default Rules Audit

Check whether the auto-created default firewall rules are still active.

```bash
echo "=== Default Firewall Rules ==="

DEFAULT_RULES=("default-allow-internal" "default-allow-ssh" "default-allow-rdp" "default-allow-icmp")

for RULE in "${DEFAULT_RULES[@]}"; do
  echo "--- $RULE ---"
  gcloud compute firewall-rules describe "$RULE" --project=$PROJECT_ID --format=json 2>/dev/null || echo "Rule $RULE not found (OK - may have been removed)"
done
```

### Finding: FW-VPC-07

| Field | Value |
|-------|-------|
| Internal ID | FW-VPC-07 |
| Title | Default SSH/RDP firewall rules are still active |
| Severity | MEDIUM |
| NIST | PR.AC-3 |
| Why | The `default-allow-ssh` and `default-allow-rdp` rules allow SSH/RDP from `0.0.0.0/0` to ALL instances in the default network. These are auto-created and often forgotten. |
| Remediation | Delete default rules and replace with scoped rules targeting specific tags. |
| Remediation command | `gcloud compute firewall-rules delete default-allow-ssh default-allow-rdp --project=$PROJECT_ID` |

**Note:** `default-allow-internal` (allowing internal network traffic) is generally acceptable.
`default-allow-icmp` is low risk but can be disabled if ICMP is not needed.

---

## Step 7 -- Disabled Rules

Identify rules that exist but are disabled. These are informational but indicate
firewall rule hygiene issues.

```bash
echo "=== Disabled Firewall Rules ==="
echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.disabled == true) |
  {name: .name, network: (.network | split("/") | last),
   direction: .direction, allowed: .allowed, denied: .denied,
   sourceRanges: .sourceRanges, targetTags: .targetTags}]'
```

### Finding: FW-VPC-08

| Field | Value |
|-------|-------|
| Internal ID | FW-VPC-08 |
| Title | Disabled firewall rules present |
| Severity | LOW |
| NIST | ID.AM |
| Why | Disabled rules add clutter and may be accidentally re-enabled. If a rule is no longer needed, delete it. |
| Remediation | Review and delete rules that are no longer needed. |

---

## Step 8 -- Priority Conflicts

Detect overlapping rules with conflicting actions (ALLOW vs DENY) at similar priorities.
In GCP, lower priority number = higher precedence.

```bash
echo "=== Firewall Rule Priority Analysis ==="
echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.direction == "INGRESS") |
  {name: .name, priority: .priority, action: (if .allowed then "ALLOW" else "DENY" end),
   network: (.network | split("/") | last),
   sourceRanges: .sourceRanges, targetTags: .targetTags,
   protocols: ((.allowed // .denied) | [.[] | .IPProtocol + ":" + ((.ports // ["all"]) | join(","))])}] |
  sort_by(.priority)'
```

Look for patterns where:
- A DENY rule exists at higher priority (lower number) but an ALLOW rule at a nearby priority covers the same traffic
- An ALLOW rule with broad sourceRanges has a higher priority than a DENY rule meant to block traffic

### Finding: FW-VPC-09

| Field | Value |
|-------|-------|
| Internal ID | FW-VPC-09 |
| Title | Conflicting firewall rule priorities detected |
| Severity | MEDIUM |
| NIST | PR.AC-3 |
| Why | Conflicting ALLOW/DENY rules at similar priorities can cause unexpected traffic to be permitted or blocked. This indicates unclear network security intent. |
| Remediation | Consolidate conflicting rules. Ensure DENY rules have higher precedence (lower priority number) than ALLOW rules for the same traffic. |

---

## Step 9 -- Database Ports from Internet

Detect firewall rules exposing common database ports to 0.0.0.0/0.

```bash
echo "=== Database Ports Exposed to Internet ==="

DATABASE_PORTS=("3306" "5432" "27017" "6379" "9042" "1433" "1521" "5984" "8529" "26257")
DATABASE_NAMES=("MySQL" "PostgreSQL" "MongoDB" "Redis" "Cassandra" "MSSQL" "Oracle" "CouchDB" "ArangoDB" "CockroachDB")

echo "$FIREWALL_RULES" | \
  jq '[.[] | select(.direction == "INGRESS" and
  (.sourceRanges[]? == "0.0.0.0/0" or .sourceRanges[]? == "::/0") and
  (.allowed[]? | .IPProtocol == "tcp" and
  (.ports[]? | test("^(3306|5432|27017|6379|9042|1433|1521|5984|8529|26257)$"))))] |
  if length > 0 then . else "No database ports exposed to internet" end'
```

### Finding: FW-VPC-10

| Field | Value |
|-------|-------|
| Internal ID | FW-VPC-10 |
| Title | Database ports exposed to internet |
| Severity | CRITICAL |
| NIST | PR.DS-1 |
| Why | Database ports (MySQL 3306, PostgreSQL 5432, MongoDB 27017, Redis 6379, etc.) should never be accessible from 0.0.0.0/0. Exposed databases are prime targets for data exfiltration, ransomware, and credential stuffing. |
| Remediation | Restrict source ranges to application server CIDRs only. Use Cloud SQL Auth Proxy or Private Service Connect for managed databases. |
| Remediation command | `gcloud compute firewall-rules update RULE_NAME --source-ranges="APP_SERVER_CIDR" --project=$PROJECT_ID` |

---

## Evaluation Criteria

| Finding | Severity | Internal ID |
|---------|----------|-------------|
| VPC rule allows ingress from 0.0.0.0/0 | CRITICAL | FW-VPC-01 |
| VPC rule allows all traffic (protocol: all) | CRITICAL | FW-VPC-02 |
| VPC rule has excessively broad port range (>100 ports) | HIGH | FW-VPC-03 |
| SSH (port 22) exposed to 0.0.0.0/0 | CRITICAL | FW-VPC-04 |
| RDP (port 3389) exposed to 0.0.0.0/0 | CRITICAL | FW-VPC-05 |
| Permissive rule with no target tags/SA restriction | HIGH | FW-VPC-06 |
| Default SSH/RDP firewall rules still active | MEDIUM | FW-VPC-07 |
| Disabled firewall rules present | LOW | FW-VPC-08 |
| Conflicting firewall rule priorities | MEDIUM | FW-VPC-09 |
| Database ports exposed to internet | CRITICAL | FW-VPC-10 |

---

## Output

- `scan-output-firewall/phases/phase-2-human.md` -- readable VPC firewall audit report
- `scan-output-firewall/phases/phase-2-state.json` -- structured findings
- `scan-output-firewall/docs/01-vpc-firewall-rules.md` -- detailed VPC firewall findings document
