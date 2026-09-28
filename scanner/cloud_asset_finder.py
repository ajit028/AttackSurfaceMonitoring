#!/usr/bin/env python3
"""
Cloud Asset Discovery & Subdomain Takeover Auditor
Author: Ajit Nayak (ajit028)
Role Target: Security Operations Center (SOC) / Threat Reconnaissance & Cloud Security

Features:
- Multi-Cloud Public Storage Enumeration:
  * AWS S3 Buckets (Public Read ListObjects, Exists/Private, Non-Existent)
  * Azure Blob Storage Accounts & Containers
  * Google Cloud Storage (GCS) Buckets
- Subdomain Takeover & Dangling DNS Verification:
  * Signature-based verification against 15+ cloud provider orphan response signatures
  * High-confidence CNAME and DNS resolution analysis
- Threat Intelligence & Risk Rating Output
- JSON, CSV, and Webhook alerting integration

MITRE ATT&CK Mapping:
- T1596: Search Open Technical Databases (T1596.001 - DNS)
- T1584.004: Compromise Infrastructure - DNS Server (Dangling DNS Takeover)
- T1530: Data from Cloud Storage (Unsecured Cloud Storage Discovery)
"""

import argparse
import concurrent.futures
import csv
import datetime
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

# ANSI Colors
class Colors:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

# Permutations for Cloud Storage Scanning
CLOUD_PERMUTATIONS = [
    "", "-backup", "-backups", "-data", "-dev", "-development", "-staging",
    "-stage", "-prod", "-production", "-assets", "-public", "-private",
    "-internal", "-logs", "-media", "-static", "-files", "-temp", "-corp",
    "-finance", "-hr", "-security", "-compliance", "-docs", "-exports",
    "-database", "-db", "-archive", "-storage", "-web", "-app", "-api"
]

# Signatures for Dangling DNS Subdomain Takeover Detection
TAKEOVER_SIGNATURES = [
    {
        "provider": "AWS S3 Bucket",
        "cname_pattern": r"s3[.-][a-z0-9-]+\.amazonaws\.com|s3\.amazonaws\.com",
        "response_signature": r"NoSuchBucket|The specified bucket does not exist",
        "severity": "CRITICAL"
    },
    {
        "provider": "GitHub Pages",
        "cname_pattern": r"[a-z0-9-]+\.github\.io",
        "response_signature": r"There isn't a GitHub Pages site here|404 File not found",
        "severity": "HIGH"
    },
    {
        "provider": "Heroku App",
        "cname_pattern": r"[a-z0-9-]+\.herokuapp\.com|[a-z0-9-]+\.herokussl\.com",
        "response_signature": r"No such app|herokucdn\.com/error-pages/no-such-app\.html",
        "severity": "HIGH"
    },
    {
        "provider": "Azure App Service",
        "cname_pattern": r"[a-z0-9-]+\.azurewebsites\.net|[a-z0-9-]+\.cloudapp\.net",
        "response_signature": r"404 Web Site not found|Error 404 - Web app not found",
        "severity": "CRITICAL"
    },
    {
        "provider": "Azure Traffic Manager",
        "cname_pattern": r"[a-z0-9-]+\.trafficmanager\.net",
        "response_signature": r"404 Not Found",
        "severity": "HIGH"
    },
    {
        "provider": "Fastly CDN",
        "cname_pattern": r"[a-z0-9-]+\.fastly\.net",
        "response_signature": r"Fastly error: unknown domain",
        "severity": "HIGH"
    },
    {
        "provider": "Shopify Store",
        "cname_pattern": r"[a-z0-9-]+\.myshopify\.com",
        "response_signature": r"Sorry, this shop is currently unavailable\.|Whatever you are looking for doesn't exist",
        "severity": "HIGH"
    },
    {
        "provider": "Zendesk Support",
        "cname_pattern": r"[a-z0-9-]+\.zendesk\.com",
        "response_signature": r"Help Center Closed",
        "severity": "MEDIUM"
    },
    {
        "provider": "Surge.sh",
        "cname_pattern": r"[a-z0-9-]+\.surge\.sh",
        "response_signature": r"project not found",
        "severity": "HIGH"
    },
    {
        "provider": "Pantheon",
        "cname_pattern": r"[a-z0-9-]+\.pantheonsite\.io",
        "response_signature": r"404 error unknown site!|The gods are wise, but do not know of the site",
        "severity": "HIGH"
    },
    {
        "provider": "Ghost Blog",
        "cname_pattern": r"[a-z0-9-]+\.ghost\.io",
        "response_signature": r"The thing you were looking for is no longer here",
        "severity": "MEDIUM"
    },
    {
        "provider": "Bitbucket",
        "cname_pattern": r"[a-z0-9-]+\.bitbucket\.io",
        "response_signature": r"Repository not found",
        "severity": "HIGH"
    }
]


class CloudAssetFinder:
    """
    Scans for exposed Multi-Cloud Storage and Dangling DNS Takeovers
    """
    def __init__(
        self,
        org_name: str,
        domain: Optional[str] = None,
        subdomains: Optional[List[str]] = None,
        threads: int = 20,
        timeout: float = 4.0,
        verbose: bool = False
    ):
        self.org_name = org_name.strip().lower()
        self.domain = domain.strip().lower() if domain else f"{self.org_name}.com"
        self.subdomains = subdomains or []
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose

        self.results: Dict[str, Any] = {
            "metadata": {
                "tool": "CloudAssetFinder",
                "author": "Ajit Nayak (SOC / Threat Recon)",
                "organization": self.org_name,
                "target_domain": self.domain,
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            },
            "summary": {
                "cloud_storage_tested": 0,
                "public_buckets_exposed": 0,
                "private_buckets_detected": 0,
                "subdomains_audited": 0,
                "dangling_dns_vulnerabilities": 0,
                "risk_rating": "INFO"
            },
            "cloud_storage_findings": [],
            "takeover_findings": []
        }

    def log(self, message: str, level: str = "INFO"):
        prefix = f"[{level}]"
        if level == "INFO":
            col = Colors.BLUE
        elif level == "SUCCESS":
            col = Colors.GREEN
        elif level == "WARN":
            col = Colors.YELLOW
        elif level in ["CRITICAL", "ALERT"]:
            col = Colors.RED
        else:
            col = Colors.CYAN
        if self.verbose or level in ["INFO", "SUCCESS", "WARN", "CRITICAL", "ALERT"]:
            print(f"{col}{prefix:<10}{Colors.RESET} {message}")

    # -------------------------------------------------------------
    # AWS S3 BUCKET CHECKER
    # -------------------------------------------------------------
    def check_s3_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Audits AWS S3 bucket accessibility."""
        url = f"https://{bucket_name}.s3.amazonaws.com"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatRecon-CloudFinder/2.0"}
        req = urllib.request.Request(url, headers=headers)
        
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read(4096).decode("utf-8", errors="ignore")
                if "<ListBucketResult" in body or "<Contents>" in body:
                    return {
                        "provider": "AWS S3",
                        "resource_name": bucket_name,
                        "url": url,
                        "status": "PUBLIC_READ_EXPOSED",
                        "severity": "CRITICAL",
                        "mitre_technique": "T1530",
                        "description": f"AWS S3 Bucket '{bucket_name}' has public read permissions enabled (ListBucketResult accessible).",
                        "remediation": "Apply AWS S3 'Block Public Access' (BPA) at the bucket and account level immediately."
                    }
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # Bucket exists but access denied (Private)
                return {
                    "provider": "AWS S3",
                    "resource_name": bucket_name,
                    "url": url,
                    "status": "EXISTING_PRIVATE",
                    "severity": "INFO",
                    "mitre_technique": "T1596",
                    "description": f"AWS S3 Bucket '{bucket_name}' exists but denies anonymous reads (Access Denied).",
                    "remediation": "Audit IAM access policies to maintain least-privilege access."
                }
            elif e.code == 404:
                # Bucket does not exist
                return None
        except Exception:
            return None
        return None

    # -------------------------------------------------------------
    # AZURE BLOB STORAGE CHECKER
    # -------------------------------------------------------------
    def check_azure_storage(self, account_name: str) -> Optional[Dict[str, Any]]:
        """Audits Azure Storage Account & Blob Service accessibility."""
        clean_name = re.sub(r"[^a-z0-9]", "", account_name)[:24]
        url = f"https://{clean_name}.blob.core.windows.net/?comp=list"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatRecon-CloudFinder/2.0"}
        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read(4096).decode("utf-8", errors="ignore")
                if "<EnumerationResults" in body or "<Containers>" in body:
                    return {
                        "provider": "Azure Blob Storage",
                        "resource_name": clean_name,
                        "url": url,
                        "status": "PUBLIC_READ_EXPOSED",
                        "severity": "CRITICAL",
                        "mitre_technique": "T1530",
                        "description": f"Azure Storage Account '{clean_name}' has public container listing enabled.",
                        "remediation": "Disable anonymous public read access in Azure Storage Account configuration."
                    }
        except urllib.error.HTTPError as e:
            if e.code in [400, 403]:
                return {
                    "provider": "Azure Blob Storage",
                    "resource_name": clean_name,
                    "url": f"https://{clean_name}.blob.core.windows.net",
                    "status": "EXISTING_PRIVATE",
                    "severity": "INFO",
                    "mitre_technique": "T1596",
                    "description": f"Azure Storage Account '{clean_name}' is registered and active.",
                    "remediation": "Verify network ACLs and Shared Access Signature (SAS) tokens."
                }
            elif e.code == 404:
                return None
        except Exception:
            return None
        return None

    # -------------------------------------------------------------
    # GCP STORAGE BUCKET CHECKER
    # -------------------------------------------------------------
    def check_gcp_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Audits Google Cloud Storage (GCS) accessibility."""
        url = f"https://storage.googleapis.com/{bucket_name}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatRecon-CloudFinder/2.0"}
        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read(4096).decode("utf-8", errors="ignore")
                if "<ListBucketResult" in body:
                    return {
                        "provider": "Google Cloud Storage",
                        "resource_name": bucket_name,
                        "url": url,
                        "status": "PUBLIC_READ_EXPOSED",
                        "severity": "CRITICAL",
                        "mitre_technique": "T1530",
                        "description": f"GCP Storage Bucket '{bucket_name}' allows public object enumeration.",
                        "remediation": "Enable GCP Uniform Bucket-Level Access and revoke 'allUsers' / 'allAuthenticatedUsers' roles."
                    }
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return {
                    "provider": "Google Cloud Storage",
                    "resource_name": bucket_name,
                    "url": url,
                    "status": "EXISTING_PRIVATE",
                    "severity": "INFO",
                    "mitre_technique": "T1596",
                    "description": f"GCP Storage Bucket '{bucket_name}' exists and is private.",
                    "remediation": "Enforce IAM least privilege and audit bucket ACLs."
                }
            elif e.code == 404:
                return None
        except Exception:
            return None
        return None

    # -------------------------------------------------------------
    # DANGLING DNS & SUBDOMAIN TAKEOVER CHECKER
    # -------------------------------------------------------------
    def audit_subdomain_takeover(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Audits CNAME records and response body for dangling DNS takeover signatures."""
        try:
            cnames = []
            try:
                host_info = socket.gethostbyname_ex(hostname)
                if host_info[0] != hostname:
                    cnames.append(host_info[0])
                for alias in host_info[1]:
                    if alias != hostname and alias not in cnames:
                        cnames.append(alias)
            except socket.gaierror:
                pass

            if not cnames:
                return None

            for cname in cnames:
                for sig in TAKEOVER_SIGNATURES:
                    if re.search(sig["cname_pattern"], cname, re.IGNORECASE):
                        # CNAME matches a takeover-vulnerable service; probe HTTP response
                        url = f"http://{hostname}"
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SubdomainTakeoverAuditor/2.0"})
                        
                        try:
                            with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
                                body = resp.read(8192).decode("utf-8", errors="ignore")
                                if re.search(sig["response_signature"], body, re.IGNORECASE):
                                    return {
                                        "hostname": hostname,
                                        "cname": cname,
                                        "provider": sig["provider"],
                                        "severity": sig["severity"],
                                        "mitre_technique": "T1584.004",
                                        "title": f"Vulnerable to Subdomain Takeover ({sig['provider']})",
                                        "description": f"Subdomain {hostname} points to {cname}, which returned the signature: '{sig['response_signature']}'. An attacker can register this resource to hijack the domain.",
                                        "remediation": f"Remove the dangling CNAME DNS record for {hostname} or claim the {sig['provider']} resource."
                                    }
                        except urllib.error.HTTPError as e:
                            body = e.read(8192).decode("utf-8", errors="ignore")
                            if re.search(sig["response_signature"], body, re.IGNORECASE):
                                return {
                                    "hostname": hostname,
                                    "cname": cname,
                                    "provider": sig["provider"],
                                    "severity": sig["severity"],
                                    "mitre_technique": "T1584.004",
                                    "title": f"Vulnerable to Subdomain Takeover ({sig['provider']})",
                                    "description": f"Subdomain {hostname} points to {cname} (HTTP {e.code}), matching signature: '{sig['response_signature']}'.",
                                    "remediation": f"Remove the dangling CNAME DNS record for {hostname} or claim the {sig['provider']} resource."
                                }
                        except Exception:
                            pass
        except Exception:
            pass
        return None

    # -------------------------------------------------------------
    # RUN PIPELINE
    # -------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        print(f"{Colors.BOLD}{Colors.CYAN}")
        print("╔══════════════════════════════════════════════════════════════════════════╗")
        print("║      CLOUD ASSET ENUMERATION & DANGLING DNS TAKEOVER AUDITOR             ║")
        print("║      Lead Engineer: Ajit Nayak | Multi-Cloud & Storage Security Engine   ║")
        print("╚══════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")

        # 1. Cloud Storage Checks
        target_names = [f"{self.org_name}{p}" for p in CLOUD_PERMUTATIONS]
        # Also include dot permutations if domain is provided
        base_domain_name = self.domain.split(".")[0]
        if base_domain_name != self.org_name:
            target_names.extend([f"{base_domain_name}{p}" for p in CLOUD_PERMUTATIONS])

        target_names = list(set(target_names))
        self.results["summary"]["cloud_storage_tested"] = len(target_names) * 3
        self.log(f"Initiating multi-cloud storage enumeration across {len(target_names)} naming permutations...", "INFO")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # S3
            s3_futures = {executor.submit(self.check_s3_bucket, name): name for name in target_names}
            # Azure
            azure_futures = {executor.submit(self.check_azure_storage, name): name for name in target_names}
            # GCP
            gcp_futures = {executor.submit(self.check_gcp_bucket, name): name for name in target_names}

            for future in concurrent.futures.as_completed(s3_futures):
                res = future.result()
                if res:
                    self.results["cloud_storage_findings"].append(res)
                    if res["status"] == "PUBLIC_READ_EXPOSED":
                        self.results["summary"]["public_buckets_exposed"] += 1
                        self.log(f"CRITICAL: Exposed AWS S3 Bucket found -> {res['url']}", "CRITICAL")
                    else:
                        self.results["summary"]["private_buckets_detected"] += 1

            for future in concurrent.futures.as_completed(azure_futures):
                res = future.result()
                if res:
                    self.results["cloud_storage_findings"].append(res)
                    if res["status"] == "PUBLIC_READ_EXPOSED":
                        self.results["summary"]["public_buckets_exposed"] += 1
                        self.log(f"CRITICAL: Exposed Azure Blob Container found -> {res['url']}", "CRITICAL")
                    else:
                        self.results["summary"]["private_buckets_detected"] += 1

            for future in concurrent.futures.as_completed(gcp_futures):
                res = future.result()
                if res:
                    self.results["cloud_storage_findings"].append(res)
                    if res["status"] == "PUBLIC_READ_EXPOSED":
                        self.results["summary"]["public_buckets_exposed"] += 1
                        self.log(f"CRITICAL: Exposed GCP Storage Bucket found -> {res['url']}", "CRITICAL")
                    else:
                        self.results["summary"]["private_buckets_detected"] += 1

        # 2. Subdomain Takeover Checks
        if self.subdomains:
            self.log(f"Auditing {len(self.subdomains)} subdomains for dangling DNS / Subdomain Takeover...", "INFO")
            self.results["summary"]["subdomains_audited"] = len(self.subdomains)
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                takeover_futures = {executor.submit(self.audit_subdomain_takeover, sub): sub for sub in self.subdomains}
                for future in concurrent.futures.as_completed(takeover_futures):
                    res = future.result()
                    if res:
                        self.results["takeover_findings"].append(res)
                        self.results["summary"]["dangling_dns_vulnerabilities"] += 1
                        self.log(f"ALERT: Subdomain Takeover Detected -> {res['hostname']} ({res['provider']})", "ALERT")

        # Summary Risk Calculation
        if self.results["summary"]["public_buckets_exposed"] > 0 or self.results["summary"]["dangling_dns_vulnerabilities"] > 0:
            self.results["summary"]["risk_rating"] = "CRITICAL"
        elif self.results["summary"]["private_buckets_detected"] > 0:
            self.results["summary"]["risk_rating"] = "MEDIUM"
        else:
            self.results["summary"]["risk_rating"] = "LOW"

        self.print_summary()
        return self.results

    def print_summary(self):
        s = self.results["summary"]
        rating = s["risk_rating"]
        col = Colors.RED if rating == "CRITICAL" else (Colors.YELLOW if rating == "MEDIUM" else Colors.GREEN)

        print("\n" + "="*80)
        print(f"{Colors.BOLD}CLOUD ASSET & DANGLING DNS AUDIT REPORT{Colors.RESET}")
        print("="*80)
        print(f"  • Target Organization:         {self.org_name}")
        print(f"  • Cloud Endpoints Scanned:     {s['cloud_storage_tested']}")
        print(f"  • {Colors.RED}Exposed Public Buckets:        {s['public_buckets_exposed']}{Colors.RESET}")
        print(f"  • Private Cloud Buckets:       {s['private_buckets_detected']}")
        print(f"  • Subdomains Audited:          {s['subdomains_audited']}")
        print(f"  • {Colors.RED}Dangling DNS Takeovers:        {s['dangling_dns_vulnerabilities']}{Colors.RESET}")
        print(f"  • Overall Cloud Risk Rating:   {col}{rating}{Colors.RESET}")
        print("="*80 + "\n")


def export_json(report: Dict[str, Any], filepath: str):
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"{Colors.GREEN}[+] JSON report saved to: {filepath}{Colors.RESET}")


def export_csv(report: Dict[str, Any], filepath: str):
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Resource / Hostname", "Provider", "Status / Severity", "MITRE ID", "Description", "Remediation"])
        for c in report.get("cloud_storage_findings", []):
            writer.writerow(["Cloud Storage", c.get("resource_name"), c.get("provider"), c.get("status"), c.get("mitre_technique"), c.get("description"), c.get("remediation")])
        for t in report.get("takeover_findings", []):
            writer.writerow(["Subdomain Takeover", t.get("hostname"), t.get("provider"), t.get("severity"), t.get("mitre_technique"), t.get("description"), t.get("remediation")])
    print(f"{Colors.GREEN}[+] CSV report saved to: {filepath}{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(description="Cloud Asset & Subdomain Takeover Auditor")
    parser.add_argument("-o", "--org", type=str, required=True, help="Target Organization name (e.g. acme, testcorp)")
    parser.add_argument("-d", "--domain", type=str, help="Target root domain (e.g. acme.com)")
    parser.add_argument("-s", "--subdomains-file", type=str, help="File containing list of subdomains to audit for takeover")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Concurrency worker threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=4.0, help="HTTP/DNS timeout in seconds (default: 4.0)")
    parser.add_argument("-j", "--output-json", type=str, default="reports/cloud_asset_report.json", help="JSON output file")
    parser.add_argument("--output-csv", type=str, help="CSV output file")
    parser.add_argument("--webhook", type=str, help="Webhook URL for alert notifications")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    subs = []
    if args.subdomains_file and os.path.exists(args.subdomains_file):
        with open(args.subdomains_file, "r", encoding="utf-8") as f:
            subs = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    finder = CloudAssetFinder(
        org_name=args.org,
        domain=args.domain,
        subdomains=subs,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )

    results = finder.run()

    if args.output_json:
        export_json(results, args.output_json)
    if args.output_csv:
        export_csv(results, args.output_csv)

    if args.webhook:
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from alerts.webhook_notifier import AlertNotifier
            notifier = AlertNotifier(args.webhook)
            notifier.dispatch_cloud_report(results)
        except Exception as e:
            print(f"{Colors.RED}[!] Webhook dispatch failed: {e}{Colors.RESET}")


if __name__ == "__main__":
    main()
