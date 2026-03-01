# Firewall Security Control ID Registry

All findings use stable Internal IDs in format: FW-[CATEGORY]-[NUMBER]
This enables tracking findings across scan runs and mapping to NIST CSF 2.0.

---

## FW-VPC -- VPC Firewall Rules

| ID | Title | NIST | CIS Benchmark | Severity |
|----|-------|------|---------------|----------|
| FW-VPC-01 | VPC firewall rule allows ingress from 0.0.0.0/0 | PR.AC-3 | 3.6 | CRITICAL |
| FW-VPC-02 | VPC firewall rule allows all traffic (protocol: all) | PR.AC-3 | 3.6 | CRITICAL |
| FW-VPC-03 | VPC firewall rule has excessively broad port range (>100 ports) | PR.AC-3 | -- | HIGH |
| FW-VPC-04 | SSH (port 22) exposed to 0.0.0.0/0 | PR.AC-3 | 3.6 | CRITICAL |
| FW-VPC-05 | RDP (port 3389) exposed to 0.0.0.0/0 | PR.AC-3 | 3.7 | CRITICAL |
| FW-VPC-06 | Permissive firewall rule has no target tags/SA restriction | PR.AC-3 | -- | HIGH |
| FW-VPC-07 | Default SSH/RDP firewall rules still active | PR.AC-3 | 3.6, 3.7 | MEDIUM |
| FW-VPC-08 | Disabled firewall rules present | ID.AM | -- | LOW |
| FW-VPC-09 | Conflicting firewall rule priorities detected | PR.AC-3 | -- | MEDIUM |
| FW-VPC-10 | Database ports exposed to internet | PR.DS-1 | -- | CRITICAL |

---

## FW-POL -- Firewall Policies

| ID | Title | NIST | Severity |
|----|-------|------|----------|
| FW-POL-01 | 0.0.0.0/0 ingress ALLOW in firewall policy | PR.AC-3 | CRITICAL |
| FW-POL-02 | Allow-all traffic in firewall policy | PR.AC-3 | CRITICAL |
| FW-POL-03 | SSH/RDP from 0.0.0.0/0 in firewall policy | PR.AC-3 | CRITICAL |
| FW-POL-04 | Firewall policy rule with no target restriction | PR.AC-3 | HIGH |
| FW-POL-05 | Policy overrides may mask VPC deny rules | PR.AC-3 | MEDIUM |

---

## FW-NET -- Network Exposure

| ID | Title | NIST | Severity |
|----|-------|------|----------|
| FW-NET-01 | Instance with public IP and permissive 0.0.0.0/0 ingress | PR.AC-3 | HIGH |
| FW-NET-02 | Instance with public IP (informational) | ID.AM | MEDIUM |
| FW-NET-03 | Orphaned firewall rule tags | ID.AM | LOW |

---

## Summary

| Category | Controls | Focus |
|----------|----------|-------|
| FW-VPC | 10 | VPC firewall rule misconfigurations |
| FW-POL | 5 | Firewall policy misconfigurations |
| FW-NET | 3 | Network exposure & hygiene |
| **Total** | **18** | |
