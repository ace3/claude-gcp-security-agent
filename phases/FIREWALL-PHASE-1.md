# Firewall Phase 1 -- Network & Compute Discovery

**NIST Function**: IDENTIFY (ID.AM -- Asset Management)
**Depends on**: Current gcloud user authentication
**Permissions needed**: `compute.networks.list`, `compute.instances.list`, `compute.firewalls.list`

---

## Objective

Discover the project's network topology: VPC networks, subnets, Compute Engine instances
(with network tags, service accounts, and network interfaces), instance groups, and
available firewall policy types. This inventory drives all subsequent audit phases.

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

## Step 2 -- VPC Network Discovery

```bash
echo "=== VPC Networks ==="
gcloud compute networks list --project=$PROJECT_ID --format=json
```

For each network, note:
- Network name and mode (`auto` vs `custom`)
- Whether it is the `default` network (security concern if still present)
- Peering connections

```bash
echo "=== VPC Network Details ==="
gcloud compute networks list --project=$PROJECT_ID --format="value(name)" | \
while IFS= read -r NETWORK; do
  echo "--- Network: $NETWORK ---"
  gcloud compute networks describe "$NETWORK" --project=$PROJECT_ID --format=json
done
```

---

## Step 3 -- Subnet Discovery

```bash
echo "=== Subnets ==="
gcloud compute networks subnets list --project=$PROJECT_ID --format=json
```

For each subnet, capture:
- Subnet name, region, network, IP range
- Private Google Access status
- Flow logs enabled (informational for Phase 4)

```bash
echo "=== Subnet Details ==="
gcloud compute networks subnets list --project=$PROJECT_ID --format=json | \
  jq '[.[] | {name: .name, region: (.region | split("/") | last),
       network: (.network | split("/") | last), ipCidrRange: .ipCidrRange,
       privateIpGoogleAccess: .privateIpGoogleAccess,
       logConfig: .logConfig}]'
```

---

## Step 4 -- Compute Engine Instance Inventory

```bash
echo "=== Compute Engine Instances ==="
gcloud compute instances list --project=$PROJECT_ID --format=json
```

For each instance, capture:
- Instance name, zone, status
- **Network tags** (critical for firewall rule targeting)
- **Service account** attached
- **Network interfaces** with internal/external IPs
- Machine type

```bash
echo "=== Instance Details ==="
gcloud compute instances list --project=$PROJECT_ID --format=json | \
  jq '[.[] | {name: .name,
       zone: (.zone | split("/") | last),
       status: .status,
       tags: .tags.items,
       serviceAccounts: [.serviceAccounts[]?.email],
       networkInterfaces: [.networkInterfaces[] | {
         network: (.network | split("/") | last),
         subnetwork: (.subnetwork | split("/") | last),
         internalIP: .networkIP,
         externalIP: .accessConfigs[]?.natIP
       }],
       machineType: (.machineType | split("/") | last)}]'
```

---

## Step 5 -- Instance Group Inventory

```bash
echo "=== Instance Groups ==="

# Managed instance groups
gcloud compute instance-groups managed list --project=$PROJECT_ID --format=json 2>/dev/null || echo "No managed instance groups"

# Unmanaged instance groups
gcloud compute instance-groups unmanaged list --project=$PROJECT_ID --format=json 2>/dev/null || echo "No unmanaged instance groups"
```

---

## Step 6 -- Firewall Rule Overview

```bash
echo "=== Firewall Rules Overview ==="
gcloud compute firewall-rules list --project=$PROJECT_ID --format=json
```

Classify rules:
- **Default rules** (names starting with `default-`): `default-allow-internal`, `default-allow-ssh`, `default-allow-rdp`, `default-allow-icmp`
- **Custom rules**: all other rules
- **Direction**: INGRESS vs EGRESS
- **Action**: ALLOW vs DENY

```bash
echo "=== Firewall Rules Summary ==="
gcloud compute firewall-rules list --project=$PROJECT_ID --format=json | \
  jq '{total: length,
       ingress: [.[] | select(.direction == "INGRESS")] | length,
       egress: [.[] | select(.direction == "EGRESS")] | length,
       allow: [.[] | select(.allowed)] | length,
       deny: [.[] | select(.denied)] | length,
       default_rules: [.[] | select(.name | startswith("default-"))] | length,
       custom_rules: [.[] | select(.name | startswith("default-") | not)] | length,
       disabled: [.[] | select(.disabled == true)] | length}'
```

---

## Step 7 -- Firewall Policy Discovery

```bash
echo "=== Network Firewall Policies ==="
gcloud compute network-firewall-policies list --project=$PROJECT_ID --format=json 2>/dev/null || echo "No network firewall policies"

# Hierarchical policies (requires org/folder access)
if [ -n "$ORG_ID" ]; then
  echo "=== Organization Firewall Policies ==="
  gcloud compute firewall-policies list --organization=$ORG_ID --format=json 2>/dev/null || echo "No org-level firewall policies or insufficient permissions"
fi

if [ -n "$FOLDER_ID" ]; then
  echo "=== Folder Firewall Policies ==="
  gcloud compute firewall-policies list --folder=$FOLDER_ID --format=json 2>/dev/null || echo "No folder-level firewall policies or insufficient permissions"
fi
```

---

## Step 8 -- Network Tag Inventory

Compile a mapping of all network tags in use across instances and firewall rules.

```bash
echo "=== Network Tags In Use ==="

# Tags on instances
echo "--- Tags on instances ---"
gcloud compute instances list --project=$PROJECT_ID --format=json | \
  jq '[.[].tags.items // [] | .[]] | unique | sort'

# Tags referenced in firewall rules (targetTags)
echo "--- Tags in firewall rules ---"
gcloud compute firewall-rules list --project=$PROJECT_ID --format=json | \
  jq '[.[].targetTags // [] | .[]] | unique | sort'

# Tags referenced in firewall rules (sourceTags)
echo "--- Source tags in firewall rules ---"
gcloud compute firewall-rules list --project=$PROJECT_ID --format=json | \
  jq '[.[].sourceTags // [] | .[]] | unique | sort'
```

---

## Step 9 -- Write Phase State

After running discovery, write `scan-output-firewall/phases/phase-1-state.json`:

```json
{
  "phase": "1",
  "timestamp": "<ISO8601>",
  "project_id": "<PROJECT_ID>",
  "status": "COMPLETE",
  "networks": [
    {"name": "default", "mode": "auto", "is_default": true, "peerings": []}
  ],
  "subnets": [
    {"name": "...", "region": "...", "network": "...", "ip_range": "...",
     "private_google_access": true, "flow_logs": false}
  ],
  "instances": [
    {"name": "...", "zone": "...", "status": "RUNNING",
     "tags": ["web-server"], "service_accounts": ["..."],
     "network_interfaces": [
       {"network": "default", "subnet": "...", "internal_ip": "...", "external_ip": "..."}
     ]}
  ],
  "instance_groups": [],
  "firewall_summary": {
    "total_rules": 0,
    "ingress_rules": 0,
    "egress_rules": 0,
    "default_rules": 0,
    "custom_rules": 0,
    "disabled_rules": 0
  },
  "firewall_policies": {
    "network_policies": [],
    "hierarchical_policies": []
  },
  "network_tags": {
    "on_instances": [],
    "in_firewall_rules": [],
    "in_source_tags": []
  },
  "summary": {
    "network_count": 0,
    "subnet_count": 0,
    "instance_count": 0,
    "instances_with_external_ip": 0,
    "total_firewall_rules": 0,
    "total_network_tags": 0
  }
}
```

---

## Output

- `scan-output-firewall/phases/phase-1-human.md` -- readable network & compute inventory
- `scan-output-firewall/phases/phase-1-state.json` -- machine-readable for subsequent phases

**No findings generated in this phase. Output is purely informational.**
