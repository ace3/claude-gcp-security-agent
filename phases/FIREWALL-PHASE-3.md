# Firewall Phase 3 -- Firewall Policies Audit

**NIST Function**: PROTECT (PR.AC -- Access Control)
**Depends on**: `scan-output-firewall/phases/phase-1-state.json`
**Permissions needed**: `compute.firewallPolicies.list`, `compute.firewallPolicies.get`, `compute.networkFirewallPolicies.list`, `compute.networkFirewallPolicies.get`

---

## Objective

Audit firewall policies (both hierarchical and network-level) for the same security
misconfigurations checked in Phase 2. Firewall policies operate at a higher level than
VPC rules and can override or interact with them in complex ways.

**Why firewall policies matter:**
- **Hierarchical policies** (at org/folder level) are evaluated BEFORE VPC rules and can override them
- **Network policies** are evaluated AFTER hierarchical but BEFORE VPC rules
- A permissive policy rule can silently negate carefully crafted VPC deny rules
- Policy misconfigurations have broader blast radius (affect multiple projects or networks)

**GCP Firewall Evaluation Order:**
1. Hierarchical firewall policies (org → folder, top-down) — `goto_next` passes to step 2
2. Network firewall policies — `goto_next` passes to step 3
3. VPC firewall rules
4. Implied deny-all ingress / allow-all egress

---

## Step 1 -- Hierarchical Firewall Policies

Hierarchical policies are attached at the organization or folder level. They require
org-level permissions to read.

```bash
echo "=== Hierarchical Firewall Policies ==="

# Org-level policies
if [ -n "$ORG_ID" ]; then
  echo "--- Organization-level policies ---"
  ORG_POLICIES=$(gcloud compute firewall-policies list --organization=$ORG_ID --format=json 2>/dev/null)
  if [ $? -eq 0 ] && [ "$ORG_POLICIES" != "[]" ] && [ -n "$ORG_POLICIES" ]; then
    echo "$ORG_POLICIES" | jq .

    # List rules in each policy
    echo "$ORG_POLICIES" | jq -r '.[].name' | while IFS= read -r POLICY_NAME; do
      echo "--- Rules in policy: $POLICY_NAME ---"
      gcloud compute firewall-policies rules list "$POLICY_NAME" --organization=$ORG_ID --format=json 2>/dev/null | jq .
    done
  else
    echo "No organization-level firewall policies found"
  fi
else
  echo "ORG_ID not set -- skipping org-level policy check"
fi

# Folder-level policies
if [ -n "$FOLDER_ID" ]; then
  echo "--- Folder-level policies ---"
  FOLDER_POLICIES=$(gcloud compute firewall-policies list --folder=$FOLDER_ID --format=json 2>/dev/null)
  if [ $? -eq 0 ] && [ "$FOLDER_POLICIES" != "[]" ] && [ -n "$FOLDER_POLICIES" ]; then
    echo "$FOLDER_POLICIES" | jq .

    echo "$FOLDER_POLICIES" | jq -r '.[].name' | while IFS= read -r POLICY_NAME; do
      echo "--- Rules in policy: $POLICY_NAME ---"
      gcloud compute firewall-policies rules list "$POLICY_NAME" --folder=$FOLDER_ID --format=json 2>/dev/null | jq .
    done
  else
    echo "No folder-level firewall policies found"
  fi
else
  echo "FOLDER_ID not set -- skipping folder-level policy check"
fi
```

---

## Step 2 -- Network Firewall Policies

Network firewall policies are attached to specific VPC networks within the project.

```bash
echo "=== Network Firewall Policies ==="
NETWORK_POLICIES=$(gcloud compute network-firewall-policies list --project=$PROJECT_ID --format=json 2>/dev/null)

if [ "$NETWORK_POLICIES" != "[]" ] && [ -n "$NETWORK_POLICIES" ] && [ "$NETWORK_POLICIES" != "null" ]; then
  echo "$NETWORK_POLICIES" | jq .

  # List rules in each network policy
  echo "$NETWORK_POLICIES" | jq -r '.[].name' | while IFS= read -r POLICY_NAME; do
    echo "--- Rules in network policy: $POLICY_NAME ---"
    gcloud compute network-firewall-policies rules list "$POLICY_NAME" --project=$PROJECT_ID --format=json 2>/dev/null | jq .

    # Check associations
    echo "--- Associations for: $POLICY_NAME ---"
    gcloud compute network-firewall-policies associations list --firewall-policy="$POLICY_NAME" --project=$PROJECT_ID --format=json 2>/dev/null | jq .
  done
else
  echo "No network firewall policies found"
fi

# Also check for regional network firewall policies
echo "=== Regional Network Firewall Policies ==="
gcloud compute regions list --format="value(name)" --project=$PROJECT_ID | while IFS= read -r REGION; do
  REGIONAL=$(gcloud compute network-firewall-policies list --project=$PROJECT_ID --region="$REGION" --format=json 2>/dev/null)
  if [ "$REGIONAL" != "[]" ] && [ -n "$REGIONAL" ] && [ "$REGIONAL" != "null" ]; then
    echo "--- Region: $REGION ---"
    echo "$REGIONAL" | jq .
  fi
done
```

---

## Step 3 -- Security Analysis of Policy Rules

Apply the same detection logic from Phase 2 to each policy rule found.

For each policy rule, check:

### 3a -- 0.0.0.0/0 Ingress in Policy

```bash
echo "=== Policy Rules with 0.0.0.0/0 Ingress ==="
# For each policy captured above, filter rules:
# - direction: INGRESS
# - action: allow
# - srcIpRanges contains "0.0.0.0/0" or "::/0"
```

Evaluate each policy rule object for:
- `match.srcIpRanges` containing `"0.0.0.0/0"` or `"::/0"`
- `action` is `"allow"`
- `direction` is `"INGRESS"`

### 3b -- Allow-All in Policy

Check for policy rules where:
- `match.layer4Configs` contains `{ipProtocol: "all"}` (no port restriction)
- `action` is `"allow"`

### 3c -- SSH/RDP from Anywhere in Policy

Check for policy rules where:
- `match.srcIpRanges` contains `"0.0.0.0/0"`
- `match.layer4Configs` contains `{ipProtocol: "tcp", ports: ["22"]}` or `{ipProtocol: "tcp", ports: ["3389"]}`

### 3d -- Policy Rule with No Target

Check for policy rules where:
- `targetResources` is empty or null (applies to all instances in associated networks)
- `targetServiceAccounts` is empty or null
- The rule allows permissive ingress

---

## Step 4 -- Policy-vs-VPC Rule Interaction Analysis

Analyze how policy rules interact with VPC firewall rules from Phase 2.

```bash
echo "=== Policy vs VPC Rule Interaction ==="

# This is a logical analysis step. The agent should:
# 1. Read phase-2 findings (specifically FW-VPC deny rules)
# 2. Check if any hierarchical/network policy ALLOW rules would override VPC DENY rules
# 3. Check for "goto_next" actions in policies that delegate to VPC rules
# 4. Identify cases where a policy "allow" has higher precedence than a VPC "deny"
```

Key interaction patterns to detect:
- **Policy ALLOW overriding VPC DENY**: A hierarchical policy allows 0.0.0.0/0 on port 22,
  but a VPC deny rule tries to block it -- the policy wins.
- **goto_next delegation**: A policy rule with `action: goto_next` passes evaluation
  to the next level. This is expected behavior but should be documented.
- **Policy DENY protecting VPC gaps**: A hierarchical deny rule blocking 0.0.0.0/0
  effectively protects all projects under that org/folder, even if individual VPC
  rules are permissive.

---

## Evaluation Criteria

| Finding | Severity | Internal ID |
|---------|----------|-------------|
| 0.0.0.0/0 ingress ALLOW in firewall policy | CRITICAL | FW-POL-01 |
| Allow-all traffic in firewall policy | CRITICAL | FW-POL-02 |
| SSH/RDP from 0.0.0.0/0 in firewall policy | CRITICAL | FW-POL-03 |
| Policy rule with no target restriction | HIGH | FW-POL-04 |
| Policy overrides may mask VPC deny rules | MEDIUM | FW-POL-05 |

### Finding Details

**FW-POL-01** (CRITICAL): 0.0.0.0/0 ingress ALLOW in firewall policy
- Why: Policy rules have higher precedence than VPC rules. A permissive policy ALLOW cannot be overridden by VPC deny rules, making the blast radius much larger.
- Remediation: Remove or restrict the policy rule's source IP ranges.

**FW-POL-02** (CRITICAL): Allow-all traffic in firewall policy
- Why: A policy rule allowing all protocols and ports bypasses all network segmentation at the policy level. This affects all networks the policy is associated with.
- Remediation: Replace with specific protocol/port rules.

**FW-POL-03** (CRITICAL): SSH/RDP from 0.0.0.0/0 in firewall policy
- Why: Management port exposure at the policy level affects all associated networks and cannot be mitigated by VPC-level deny rules.
- Remediation: Restrict to IAP source range (35.235.240.0/20) or remove the rule.

**FW-POL-04** (HIGH): Policy rule with no target restriction
- Why: A policy rule without target resource or SA filters applies to all instances in all associated networks.
- Remediation: Add target resources or service account filters.

**FW-POL-05** (MEDIUM): Policy overrides may mask VPC deny rules
- Why: When a policy ALLOW rule matches the same traffic as a VPC DENY rule, the policy wins due to evaluation order. Administrators may believe VPC deny rules are protecting resources when they are not.
- Remediation: Review policy-VPC interaction. Move deny rules to the policy level for guaranteed enforcement.

---

## Output

- `scan-output-firewall/phases/phase-3-human.md` -- readable firewall policies audit report
- `scan-output-firewall/phases/phase-3-state.json` -- structured findings
- `scan-output-firewall/docs/02-firewall-policies.md` -- detailed firewall policy findings document
