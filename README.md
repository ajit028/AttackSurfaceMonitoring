# 🛡️ Autonomous Attack Surface Management (ASM) & Threat Reconnaissance Pipeline

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Reconnaissance-red?style=for-the-badge&logo=shield)](https://attack.mitre.org/tactics/TA0043/)
[![SIEM Ready](https://img.shields.io/badge/SIEM-Splunk%20%7C%20Sentinel%20%7C%20Elastic-orange?style=for-the-badge)](https://github.com/ajit028/AttackSurfaceMonitoring)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

> **Lead Architect & Detection Engineer:** [Ajit Nayak (ajit028)](https://github.com/ajit028)  
> **Target Role:** SOC Analyst (Tier 1/2) | Threat Detection & Incident Response | EASM Engineer  
> **Location:** Bangalore, India | **Availability:** Immediate (0-Day Notice)

---

## 📌 Executive Summary & Threat Context

In modern hybrid cloud environments, an organization's perimeter is constantly shifting. Shadow IT, forgotten staging environments, dangling DNS records, expired TLS certificates, and misconfigured cloud buckets expose critical attack vectors before internal security teams are even aware of them.

**AttackSurfaceMonitoring (ASM)** is an enterprise-grade, proactive external attack surface management and threat intelligence reconnaissance pipeline. Built natively in Python with zero mandatory external runtime dependencies, it continuously discovers, fingerprints, analyzes, and risk-scores an organization's public infrastructure from the perspective of an advanced persistent threat (APT).

### 🎯 Key Engineering Highlights
* **Zero-Credential Discovery Engine:** Combines Certificate Transparency (crt.sh) logs with active permutations for 100% passive-to-active discovery.
* **Full-Stack Asset Fingerprinting:** Correlates multi-threaded TCP port scanning, HTTP response headers, web technology stacks, and TLS certificate lifecycles.
* **Dangling DNS & Subdomain Takeover Auditor:** Evaluates CNAME chains against 15+ cloud provider orphan response signatures (AWS S3, Azure App Services, GitHub Pages, Heroku, Fastly).
* **Multi-Cloud Storage Exposure Discovery:** Enumerates AWS S3, Azure Blob, and GCP Cloud Storage buckets for unauthorized `Public Read` (ListBucket) access.
* **Quantitative Multi-Factor Risk Scoring:** Algorithmic 0–100 scoring based on exposure severity, CVSS-aligned weights, and compliance impact.
* **Automated SOC & SIEM Alert Dispatcher:** Real-time webhooks formatted with interactive cards and color-coded severity for **Slack, Discord, MS Teams, Splunk HEC, and Microsoft Sentinel**.

---

## 🏗️ Architecture & Telemetry Pipeline

```
                               ┌────────────────────────────────────────────────────────┐
                               │             TARGET SCOPE (Domains / IPs)               │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
                      ┌────────────────────────────────────┴───────────────────────────────────┐
                      ▼                                                                        ▼
   ┌─────────────────────────────────────┐                                  ┌─────────────────────────────────────┐
   │    Certificate Transparency Logs    │                                  │   Active Subdomain Permutations     │
   │            (crt.sh API)             │                                  │        (DNS Bruteforcing)           │
   └──────────────────┬──────────────────┘                                  └──────────────────┬──────────────────┘
                      │                                                                        │
                      └────────────────────────────────────┬───────────────────────────────────┘
                                                           │
                                                           ▼
                                         ┌───────────────────────────────────┐
                                         │ Multi-Threaded DNS Resolution     │
                                         │ (A, AAAA, CNAME Pointer Tracing)  │
                                         └─────────────────┬─────────────────┘
                                                           │
              ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
              ▼                                            ▼                                            ▼
┌───────────────────────────┐                ┌───────────────────────────┐                ┌───────────────────────────┐
│  TCP Port & Service Scan  │                │  HTTP / TLS Fingerprint   │                │   Cloud Storage Auditor   │
│  • 23 High-Risk Ports     │                │  • Server & Stack Headers │                │  • AWS S3 (ListBucket)    │
│  • DB & Admin Interfaces  │                │  • SSL Days-to-Expiry     │                │  • Azure Blob Containers  │
│  • Socket Connection Pool │                │  • Missing HSTS/CSP/XFO   │                │  • Dangling DNS CNAMEs    │
└─────────────┬─────────────┘                └─────────────┬─────────────┘                └─────────────┬─────────────┘
              │                                            │                                            │
              └────────────────────────────────────────────┼────────────────────────────────────────────┘
                                                           │
                                                           ▼
                                         ┌───────────────────────────────────┐
                                         │  Quantitative Risk Engine (0-100) │
                                         │  CRITICAL | HIGH | MEDIUM | LOW   │
                                         └─────────────────┬─────────────────┘
                                                           │
                      ┌────────────────────────────────────┴───────────────────────────────────┐
                      ▼                                                                        ▼
   ┌─────────────────────────────────────┐                                  ┌─────────────────────────────────────┐
   │   SOC Triage Reports (JSON / CSV)   │                                  │    Real-Time Webhook Alert Engine   │
   │   • sample_scan_report.json         │                                  │    • Slack / Discord / MS Teams     │
   │   • SIEM Event Ingestion Payloads   │                                  │    • Splunk HEC / Sentinel LogicApp │
   └─────────────────────────────────────┘                                  └─────────────────────────────────────┘
```

---

## 🗺️ MITRE ATT&CK Enterprise Mapping

| Technique ID | Technique Name | Sub-Technique / Activity | Detection / Monitoring Logic in ASM |
| :--- | :--- | :--- | :--- |
| **T1595** | Active Scanning | `T1595.001` - Port Scanning | Multi-threaded socket scans identifying exposed DB (3306, 5432, 6379, 27017) and remote admin ports (3389, 22, 5900). |
| **T1595** | Active Scanning | `T1595.002` - Vulnerability Scanning | Passive banner grabbing, web stack leakage, and missing security headers (HSTS, CSP, X-Frame-Options). |
| **T1596** | Search Open Technical Databases | `T1596.001` - DNS | CNAME resolution tracking and historical record correlation. |
| **T1596** | Search Open Technical Databases | `T1596.004` - Digital Certificates | Parsing Certificate Transparency (CT) logs to unearth unlinked subdomains and staging endpoints. |
| **T1584.004** | Compromise Infrastructure | DNS Server / Dangling DNS | Probing orphan CNAME pointers against known cloud service response signatures for subdomain takeover vulnerabilities. |
| **T1530** | Data from Cloud Storage | Cloud Bucket Enumeration | Verifying `ListBucketResult` and public object permissions on AWS S3, Azure Blob, and GCP storage. |

---

## ⚙️ Repository Structure

```
AttackSurfaceMonitoring/
├── scanner/
│   ├── asm_pipeline.py          # Primary Attack Surface Discovery & Risk Scoring Pipeline
│   └── cloud_asset_finder.py    # Multi-Cloud Bucket Exposure & Subdomain Takeover Auditor
├── alerts/
│   └── webhook_notifier.py      # SOC Alert Dispatcher (Slack, Discord, MS Teams, SIEM)
├── sample-data/
│   ├── sample_targets.txt       # Example multi-target scope file
│   └── sample_scan_report.json  # Comprehensive mock scan report with realistic SOC findings
├── reports/                     # Output directory for generated JSON/CSV reports (auto-created)
├── requirements.txt             # Optional enhancement packages
├── .gitignore                   # Safe Git configuration excluding reports and secrets
└── README.md                    # Elite technical documentation & case study
```

---

## 🚀 Quick Start & CLI Usage

### Prerequisites
* Python 3.10+ (Standard library provides full core functionality)
* Optional packages for accelerated DNS / HTTP can be installed via:
```bash
pip install -r requirements.txt
```

---

### 1. Run the Core ASM Pipeline

#### Single Target Domain Scan:
```bash
python scanner/asm_pipeline.py --target example.com -o reports/example_scan.json --output-csv reports/example_scan.csv
```

#### Bulk Enterprise Scope Scan with Custom Ports:
```bash
python scanner/asm_pipeline.py \
  --target-file sample-data/sample_targets.txt \
  --ports 80,443,8080,8443,22,3306,6379,9200,3389 \
  --threads 30 \
  --timeout 3.5 \
  -o reports/perimeter_audit.json \
  --output-csv reports/perimeter_audit.csv
```

#### Scan with Real-Time Webhook Alerting:
```bash
python scanner/asm_pipeline.py \
  --target-file sample-data/sample_targets.txt \
  --webhook https://hooks.slack.com/services/T000/B000/XXXXXX \
  -o reports/live_scan.json
```

---

### 2. Multi-Cloud Asset & Dangling DNS Takeover Audit

#### Scan Cloud Buckets & Check for Subdomain Takeovers:
```bash
python scanner/cloud_asset_finder.py \
  --org myenterprise \
  --domain myenterprise.com \
  --subdomains-file sample-data/sample_targets.txt \
  --threads 25 \
  -j reports/cloud_assets.json \
  --output-csv reports/cloud_assets.csv
```

---

### 3. Dispatch SOC Alerts from Existing Scan Reports

```bash
# Dry-run test (prints formatted payload to stdout)
python alerts/webhook_notifier.py \
  --report sample-data/sample_scan_report.json \
  --min-severity HIGH \
  --dry-run

# Live dispatch to Microsoft Teams / Discord / Slack
python alerts/webhook_notifier.py \
  --webhook https://discord.com/api/webhooks/XXXXXX \
  --report sample-data/sample_scan_report.json \
  --min-severity HIGH
```

---

## 📊 Sample Output & Telemetry

### Terminal Executive Summary HUD:
```text
╔══════════════════════════════════════════════════════════════════════════╗
║      ATTACK SURFACE MONITORING & THREAT RECONNAISSANCE PIPELINE         ║
║      Lead Engineer: Ajit Nayak | Autonomous ASM & Threat Intel Engine    ║
╚══════════════════════════════════════════════════════════════════════════╝

[INFO]     Compiled 18 candidate hostnames for corp-enterprise-demo.io
[INFO]     Beginning active DNS resolution across 18 host targets...
[SUCCESS]  Discovered 4 active, resolvable assets on external perimeter
[INFO]     [1/4] Auditing Asset: api.corp-enterprise-demo.io (198.51.100.42)
[INFO]     [2/4] Auditing Asset: dev-cache.internal-staging.io (203.0.113.88)
[INFO]     [3/4] Auditing Asset: legacy-blog.corp-enterprise-demo.io (192.0.2.115)
[INFO]     [4/4] Auditing Asset: database-edge.api-gateway-mesh.net (198.51.100.201)

================================================================================
EXECUTIVE ATTACK SURFACE RECONNAISSANCE REPORT
================================================================================
  • Execution Duration:    14.82 seconds
  • Candidate Targets:     18
  • Active Live Hosts:     4
  • Open Perimeter Ports:  9
  • Security Vulnerabilities:
      - CRITICAL: 2
      - HIGH:     2
      - MEDIUM:   3
      - LOW:      4
  • Organization Risk Score: 78.5/100 (CRITICAL)
================================================================================

TOP PRIORITY SECURITY FINDINGS:
  1. [CRITICAL] database-edge.api-gateway-mesh.net -> MySQL Database Exposed (MITRE T1595.001)
  2. [CRITICAL] database-edge.api-gateway-mesh.net -> MongoDB Database Exposed (MITRE T1595.001)
  3. [CRITICAL] dev-cache.internal-staging.io -> Redis In-Memory Database Exposed (MITRE T1595.001)
  4. [CRITICAL] database-edge.api-gateway-mesh.net -> SSL/TLS Certificate is Expired (MITRE T1596.004)
  5. [HIGH] database-edge.api-gateway-mesh.net -> RDP (Remote Desktop) Exposed to Public Internet (MITRE T1595.001)
  6. [HIGH] api.corp-enterprise-demo.io -> SSL/TLS Certificate Expiring in 4 Days (MITRE T1596.004)
  7. [HIGH] legacy-blog.corp-enterprise-demo.io -> Dangling CNAME Record Pointing to Ghost Blog (MITRE T1584.004)
================================================================================
```

---

## 🔒 Quantitative Risk Scoring Methodology

The pipeline utilizes an algorithmic risk model designed to eliminate alert fatigue while elevating actionable perimeter exposures:

$$\text{Asset Risk Score} = \min\left(100.0, \sum \text{Finding Weights}\right)$$

| Finding Category | Example Vector | Weight | Severity Rating |
| :--- | :--- | :---: | :---: |
| **Exposed Database Ports** | Redis (`6379`), MongoDB (`27017`), MySQL (`3306`), Postgres (`5432`) | `+35 to +40` | **CRITICAL** |
| **Remote Access Interfaces** | RDP (`3389`), SMB (`445`), VNC (`5900`), Telnet (`23`) | `+30 to +40` | **CRITICAL / HIGH** |
| **Expired SSL/TLS Certificate** | `notAfter` < current UTC timestamp | `+35` | **CRITICAL** |
| **Imminent SSL Expiry** | Remaining validity $\le 7$ days | `+20` | **HIGH** |
| **Dangling DNS / Subdomain Takeover** | Orphaned CNAME targeting unclaimed cloud service | `+30` | **HIGH** |
| **Missing HSTS Security Header** | Missing `Strict-Transport-Security` on port 443 | `+10` | **MEDIUM** |
| **Missing Content-Security-Policy** | Missing `Content-Security-Policy` header | `+10` | **LOW** |
| **Information Disclosure** | Verbose `Server` / `X-Powered-By` banner leakage | `+5` | **INFO** |

---

## 🛡️ Incident Response & Remediation Playbooks

### 1. Remediation Playbook: Exposed Database Ports (Redis / MySQL / MongoDB)
1. **Immediate Containment:** Update Cloud Security Groups / Network ACLs to revoke ingress rule `0.0.0.0/0` on ports 3306, 6379, 27017, and 5432.
2. **Access Redirection:** Route administrative database traffic exclusively through an internal VPN with Multi-Factor Authentication (MFA) or an authorized Bastion host.
3. **Configuration Hardening:** Enforce binding to `127.0.0.1` in `/etc/redis/redis.conf` and enable `requirepass` with cryptographically strong secrets.

### 2. Remediation Playbook: Dangling DNS Subdomain Takeovers
1. **DNS Triage:** Query authoritative nameservers (`dig CNAME <subdomain>`) to identify the orphan target resource.
2. **Immediate Remediation:** Remove the dangling `CNAME` pointer from the authoritative DNS zone file, or re-claim the service namespace within AWS/Azure/Heroku.
3. **Process Improvement:** Institute DNS de-provisioning checks as mandatory gates in Infrastructure-as-Code (Terraform / CloudFormation) teardown pipelines.

---

## 👨💻 Candidate Profile & Contact

**Ajit Nayak**  
*Cybersecurity Specialist | SOC Analyst Candidate | Bangalore, India*  
* **GitHub:** [@ajit028](https://github.com/ajit028)  
* **Notice Period:** 0 Days (Immediate Joiner)  
* **Core Competencies:** External Attack Surface Management, SIEM Engineering (Splunk, Microsoft Sentinel), Threat Intelligence, KQL/Sigma Detection Engineering, Network Traffic Forensics (Wireshark/Zeek).
