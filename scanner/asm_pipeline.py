#!/usr/bin/env python3
"""
Attack Surface Monitoring (ASM) & Threat Reconnaissance Pipeline
Author: Ajit Nayak (ajit028)
Role Target: Security Operations Center (SOC) / Threat Detection & EASM

Features:
- Passive Subdomain Enumeration (Certificate Transparency Logs / crt.sh)
- Active Subdomain Permutation & DNS Resolution
- CNAME Pointer & Dangling DNS Chain Tracking
- Multi-threaded TCP Port Scanning & Service Identification
- HTTP/HTTPS Banner Grabbing, Technology Fingerprinting & Security Header Auditing
- SSL/TLS Certificate Health & Expiration Auditing
- Quantitative Risk Scoring Engine (0-100 / Critical, High, Medium, Low, Info)
- SIEM / Webhook Alert Dispatching (Slack, Discord, MS Teams, Generic Webhook)
- Structured JSON & CSV Export for SOC Ingestion

MITRE ATT&CK Mapping:
- T1595: Active Scanning (T1595.001 - Port Scanning, T1595.002 - Vulnerability Scanning)
- T1596: Search Open Technical Databases (T1596.001 - DNS, T1596.004 - Digital Certificates)
- T1584.004: Compromise Infrastructure - DNS Server (Dangling DNS / Subdomain Takeover)
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

# ANSI Colors for Terminal Output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

# Default high-risk / exposed service ports
DEFAULT_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    1433,  # MS-SQL
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # HTTP Alt
    8080,  # HTTP Proxy/Web
    8443,  # HTTPS Alt
    8888,  # HTTP Alt / Jupyter
    9200,  # Elasticsearch
    27017  # MongoDB
]

DEFAULT_SUBDOMAINS = [
    "www", "api", "dev", "staging", "test", "stage", "prod", "auth",
    "login", "mail", "email", "vpn", "gateway", "portal", "admin",
    "dashboard", "jira", "git", "gitlab", "jenkins", "corp", "internal",
    "secure", "payment", "payments", "checkout", "app", "mobile",
    "status", "docs", "monitor", "grafana", "kibana", "s3", "assets",
    "cdn", "static", "media", "shop", "store", "db", "redis", "elastic",
    "cloud", "azure", "aws", "gcp", "bastion", "remote", "support"
]

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MS-SQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Dev",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9200: "Elasticsearch", 27017: "MongoDB"
}

DANGLING_DNS_SIGNATURES = {
    "s3.amazonaws.com": "AWS S3 Bucket",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku App",
    "azurewebsites.net": "Azure App Service",
    "trafficmanager.net": "Azure Traffic Manager",
    "cloudfront.net": "AWS CloudFront",
    "fastly.net": "Fastly CDN",
    "myshopify.com": "Shopify Store",
    "zendesk.com": "Zendesk Support",
    "wpengine.com": "WP Engine",
    "surge.sh": "Surge.sh Hosting",
    "pantheonsite.io": "Pantheon Hosting",
    "ghost.io": "Ghost Blog"
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


class ASMPipeline:
    """
    Main Attack Surface Management Engine
    """
    def __init__(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        threads: int = 25,
        timeout: float = 3.0,
        enable_crtsh: bool = True,
        enable_bruteforce: bool = True,
        custom_subdomains: Optional[List[str]] = None,
        verbose: bool = False
    ):
        self.targets = [t.strip().lower() for t in targets if t.strip()]
        self.ports = ports if ports is not None else DEFAULT_PORTS
        self.threads = threads
        self.timeout = timeout
        self.enable_crtsh = enable_crtsh
        self.enable_bruteforce = enable_bruteforce
        self.subdomain_wordlist = custom_subdomains if custom_subdomains else DEFAULT_SUBDOMAINS
        self.verbose = verbose
        self.scan_results: Dict[str, Any] = {
            "metadata": {
                "engine": "AttackSurfaceMonitoring (ASM) Suite",
                "author": "Ajit Nayak (SOC / Threat Recon)",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "targets": self.targets,
                "scanned_ports": self.ports,
                "threads": self.threads
            },
            "summary": {
                "total_targets": len(self.targets),
                "discovered_subdomains": 0,
                "live_hosts": 0,
                "total_open_ports": 0,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0,
                "overall_risk_score": 0.0,
                "risk_rating": "INFO"
            },
            "assets": [],
            "findings": []
        }

    def log(self, message: str, level: str = "INFO"):
        prefix = f"[{level}]"
        if level == "INFO":
            col = Colors.BLUE
        elif level == "SUCCESS":
            col = Colors.GREEN
        elif level == "WARN":
            col = Colors.YELLOW
        elif level == "CRITICAL" or level == "ALERT":
            col = Colors.RED
        else:
            col = Colors.CYAN
        if self.verbose or level in ["INFO", "SUCCESS", "WARN", "CRITICAL", "ALERT"]:
            print(f"{col}{prefix:<10}{Colors.RESET} {message}")

    # -------------------------------------------------------------
    # PHASE 1: SUBDOMAIN ENUMERATION & CERTIFICATE TRANSPARENCY
    # -------------------------------------------------------------
    def enumerate_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency logs for historical and active subdomains."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatRecon-ASM/2.0"
        }
        req = urllib.request.Request(url, headers=headers)
        try:
            self.log(f"Querying Certificate Transparency logs for {domain}...", "INFO")
            with urllib.request.urlopen(req, timeout=10.0) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8", errors="ignore"))
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub.endswith(domain) and sub != domain:
                                subdomains.add(sub)
        except Exception as e:
            self.log(f"crt.sh lookup note ({domain}): {e} (Continuing with active enum)", "WARN")
        return subdomains

    def discover_subdomains(self, domain: str) -> Set[str]:
        """Perform combined CT log enumeration and active DNS permutation."""
        discovered = {domain}

        # 1. Passive CT Search
        if self.enable_crtsh:
            ct_subs = self.enumerate_crtsh(domain)
            discovered.update(ct_subs)

        # 2. Active Permutations
        if self.enable_bruteforce:
            for word in self.subdomain_wordlist:
                candidate = f"{word}.{domain}"
                discovered.add(candidate)

        self.log(f"Compiled {len(discovered)} candidate hostnames for {domain}", "INFO")
        return discovered

    # -------------------------------------------------------------
    # PHASE 2: DNS RESOLUTION & DANGLING DNS DETECTION
    # -------------------------------------------------------------
    def resolve_host(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Resolve IP addresses, reverse PTR, and detect potential dangling CNAME pointers."""
        try:
            # Resolve IPv4
            ip_addresses = []
            cnames = []
            try:
                host_info = socket.gethostbyname_ex(hostname)
                primary_name = host_info[0]
                alias_list = host_info[1]
                ip_addresses = host_info[2]
                if primary_name != hostname:
                    cnames.append(primary_name)
                for alias in alias_list:
                    if alias != hostname and alias not in cnames:
                        cnames.append(alias)
            except socket.gaierror:
                return None

            if not ip_addresses:
                return None

            # Reverse DNS lookup
            reverse_ptr = None
            try:
                reverse_ptr = socket.gethostbyaddr(ip_addresses[0])[0]
            except Exception:
                pass

            # Dangling DNS check
            dangling_service = None
            for cname in cnames:
                for sig, svc_name in DANGLING_DNS_SIGNATURES.items():
                    if sig in cname.lower():
                        dangling_service = {
                            "service": svc_name,
                            "cname_target": cname,
                            "signature": sig
                        }
                        break

            return {
                "hostname": hostname,
                "ip_addresses": ip_addresses,
                "primary_ip": ip_addresses[0],
                "cnames": cnames,
                "reverse_ptr": reverse_ptr,
                "dangling_dns": dangling_service
            }
        except Exception:
            return None

    # -------------------------------------------------------------
    # PHASE 3: MULTI-THREADED PORT SCANNING
    # -------------------------------------------------------------
    def scan_single_port(self, ip: str, port: int) -> Optional[int]:
        """Perform socket TCP connection scan on a target IP and port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
        return None

    def scan_ports(self, ip: str) -> List[Dict[str, Any]]:
        """Concurrent port scanner over candidate ports."""
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, len(self.ports))) as executor:
            future_to_port = {executor.submit(self.scan_single_port, ip, port): port for port in self.ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    res = future.result()
                    if res is not None:
                        open_ports.append({
                            "port": port,
                            "service": PORT_SERVICE_MAP.get(port, "Unknown"),
                            "state": "OPEN"
                        })
                except Exception:
                    pass
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    # -------------------------------------------------------------
    # PHASE 4: HTTP / HTTPS BANNER & SECURITY HEADER AUDITING
    # -------------------------------------------------------------
    def audit_http_service(self, hostname: str, port: int) -> Dict[str, Any]:
        """Perform HTTP/HTTPS banner grabbing, title extraction, and security header checks."""
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{hostname}:{port}" if port not in [80, 443] else f"{protocol}://{hostname}"
        
        banner_info = {
            "url": url,
            "protocol": protocol,
            "status_code": None,
            "server": None,
            "x_powered_by": None,
            "title": None,
            "security_headers": {},
            "missing_security_headers": [],
            "technology_fingerprints": []
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackSurfaceScanner/2.0 (SOC Defense Recon)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
                banner_info["status_code"] = resp.status
                resp_headers = dict(resp.headers)
                
                # Banner info
                banner_info["server"] = resp_headers.get("Server") or resp_headers.get("server")
                banner_info["x_powered_by"] = resp_headers.get("X-Powered-By") or resp_headers.get("x-powered-by")
                
                # Check security headers
                for sec_header in SECURITY_HEADERS:
                    header_val = None
                    for k, v in resp_headers.items():
                        if k.lower() == sec_header.lower():
                            header_val = v
                            break
                    if header_val:
                        banner_info["security_headers"][sec_header] = header_val
                    else:
                        banner_info["missing_security_headers"].append(sec_header)

                # HTML Title extraction
                body = resp.read(8192).decode("utf-8", errors="ignore")
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    banner_info["title"] = title_match.group(1).strip()[:100]

                # Technology fingerprints
                if banner_info["server"]:
                    banner_info["technology_fingerprints"].append(f"Server: {banner_info['server']}")
                if banner_info["x_powered_by"]:
                    banner_info["technology_fingerprints"].append(f"Tech: {banner_info['x_powered_by']}")
                if "wp-content" in body:
                    banner_info["technology_fingerprints"].append("WordPress")
                if "swagger" in body.lower() or "openapi" in body.lower():
                    banner_info["technology_fingerprints"].append("Swagger/OpenAPI Docs")

        except urllib.error.HTTPError as e:
            banner_info["status_code"] = e.code
        except Exception:
            pass

        return banner_info

    # -------------------------------------------------------------
    # PHASE 5: SSL / TLS CERTIFICATE AUDITING
    # -------------------------------------------------------------
    def audit_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Inspect SSL/TLS certificate validity, expiry, SANs, and issuer."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    if not cert:
                        # Fallback for cert extraction in CERT_NONE mode
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            # Basic parse
                            return {
                                "tls_version": tls_version,
                                "cipher": cipher[0] if cipher else None,
                                "status": "CERT_OBTAINED_UNVALIDATED"
                            }
                        return None

                    # Extract Subject
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))

                    # Dates
                    not_after_str = cert.get("notAfter")
                    not_before_str = cert.get("notBefore")
                    days_remaining = None
                    is_expired = False

                    if not_after_str:
                        # e.g., 'May 24 12:00:00 2025 GMT'
                        expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        now = datetime.datetime.utcnow()
                        days_remaining = (expiry_date - now).days
                        is_expired = days_remaining < 0

                    # SANs
                    sans = []
                    for item in cert.get("subjectAltName", []):
                        if item[0] == "DNS":
                            sans.append(item[1])

                    return {
                        "subject_cn": subject.get("commonName"),
                        "issuer_cn": issuer.get("commonName") or issuer.get("organizationName"),
                        "not_before": not_before_str,
                        "not_after": not_after_str,
                        "days_remaining": days_remaining,
                        "is_expired": is_expired,
                        "sans": sans,
                        "tls_version": tls_version,
                        "cipher_suite": cipher[0] if cipher else None
                    }
        except Exception:
            return None

    # -------------------------------------------------------------
    # PHASE 6: QUANTITATIVE RISK SCORING & FINDING GENERATION
    # -------------------------------------------------------------
    def calculate_asset_risk(self, asset: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculates a quantitative risk score (0-100) and returns detailed vulnerability findings.
        """
        score = 0.0
        findings = []
        hostname = asset["hostname"]

        # 1. Database and Remote Management Ports exposed
        critical_ports = {
            3306: ("MySQL Database Exposed", 35.0, "CRITICAL", "T1595.001"),
            5432: ("PostgreSQL Database Exposed", 35.0, "CRITICAL", "T1595.001"),
            6379: ("Redis In-Memory Database Exposed", 40.0, "CRITICAL", "T1595.001"),
            27017: ("MongoDB Database Exposed", 40.0, "CRITICAL", "T1595.001"),
            9200: ("Elasticsearch Node Exposed", 35.0, "CRITICAL", "T1595.001"),
            3389: ("RDP (Remote Desktop) Exposed to Public Internet", 30.0, "HIGH", "T1595.001"),
            22: ("SSH Management Port Exposed", 10.0, "LOW", "T1595.001"),
            21: ("Cleartext FTP Service Exposed", 25.0, "MEDIUM", "T1595.001"),
            23: ("Insecure Telnet Service Exposed", 35.0, "CRITICAL", "T1595.001"),
            445: ("SMB Port Exposed to Internet", 40.0, "CRITICAL", "T1595.001")
        }

        open_port_nums = [p["port"] for p in asset.get("open_ports", [])]
        for p_num, (vuln_title, vuln_weight, severity, mitre_id) in critical_ports.items():
            if p_num in open_port_nums:
                score += vuln_weight
                findings.append({
                    "id": f"ASM-{hostname}-PORT-{p_num}",
                    "asset": hostname,
                    "type": "Exposed Service",
                    "title": vuln_title,
                    "severity": severity,
                    "mitre_technique": mitre_id,
                    "description": f"Port {p_num} is publicly accessible from the perimeter, violating network segregation.",
                    "remediation": f"Restrict port {p_num} behind an internal VPN, bastion host, or security group whitelist."
                })

        # 2. SSL/TLS Expiration & Certificate Weaknesses
        ssl_info = asset.get("ssl_certificate")
        if ssl_info:
            days = ssl_info.get("days_remaining")
            if ssl_info.get("is_expired") or (days is not None and days < 0):
                score += 35.0
                findings.append({
                    "id": f"ASM-{hostname}-SSL-EXPIRED",
                    "asset": hostname,
                    "type": "Certificate Expiration",
                    "title": "SSL/TLS Certificate is Expired",
                    "severity": "CRITICAL",
                    "mitre_technique": "T1596.004",
                    "description": f"The SSL certificate expired {abs(days) if days else 0} days ago. Visitors encounter security warning barriers.",
                    "remediation": "Renew and bind a valid TLS certificate from an authorized CA immediately."
                })
            elif days is not None and days <= 7:
                score += 20.0
                findings.append({
                    "id": f"ASM-{hostname}-SSL-IMMINENT-EXPIRY",
                    "asset": hostname,
                    "type": "Certificate Expiration",
                    "title": f"SSL/TLS Certificate Expiring in {days} Days",
                    "severity": "HIGH",
                    "mitre_technique": "T1596.004",
                    "description": f"Certificate expires in {days} days. Outage risk is imminent without automated renewal.",
                    "remediation": "Trigger automated ACME / Let's Encrypt renewal or deploy updated enterprise certificate."
                })
            elif days is not None and days <= 30:
                score += 10.0
                findings.append({
                    "id": f"ASM-{hostname}-SSL-WARN-EXPIRY",
                    "asset": hostname,
                    "type": "Certificate Expiration",
                    "title": f"SSL/TLS Certificate Expiring within 30 Days ({days}d)",
                    "severity": "MEDIUM",
                    "mitre_technique": "T1596.004",
                    "description": f"Certificate valid for {days} more days. Schedule renewal.",
                    "remediation": "Verify that automated renewal pipelines are configured and operational."
                })

        # 3. HTTP Security Headers
        http_info = asset.get("http_banner")
        if http_info and http_info.get("status_code"):
            missing_hdrs = http_info.get("missing_security_headers", [])
            if "Strict-Transport-Security" in missing_hdrs and 443 in open_port_nums:
                score += 10.0
                findings.append({
                    "id": f"ASM-{hostname}-MISSING-HSTS",
                    "asset": hostname,
                    "type": "Security Header",
                    "title": "Missing HTTP Strict-Transport-Security (HSTS)",
                    "severity": "MEDIUM",
                    "mitre_technique": "T1595.002",
                    "description": "The web service does not enforce HSTS, leaving users susceptible to SSL-stripping and downgrade attacks.",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to response headers."
                })
            if "Content-Security-Policy" in missing_hdrs:
                score += 10.0
                findings.append({
                    "id": f"ASM-{hostname}-MISSING-CSP",
                    "asset": hostname,
                    "type": "Security Header",
                    "title": "Missing Content-Security-Policy (CSP)",
                    "severity": "LOW",
                    "mitre_technique": "T1595.002",
                    "description": "No CSP header detected, increasing vulnerability to Cross-Site Scripting (XSS) and data injection.",
                    "remediation": "Implement a restrictive Content-Security-Policy header defining trusted script/resource origins."
                })
            if "X-Frame-Options" in missing_hdrs:
                score += 5.0
                findings.append({
                    "id": f"ASM-{hostname}-MISSING-XFO",
                    "asset": hostname,
                    "type": "Security Header",
                    "title": "Missing X-Frame-Options Header",
                    "severity": "LOW",
                    "mitre_technique": "T1595.002",
                    "description": "Missing X-Frame-Options allows iframe embedding, creating clickjacking vectors.",
                    "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' in web server config."
                })
            if http_info.get("x_powered_by") or (http_info.get("server") and any(c.isdigit() for c in http_info.get("server"))):
                score += 5.0
                findings.append({
                    "id": f"ASM-{hostname}-INFO-DISCLOSURE",
                    "asset": hostname,
                    "type": "Information Disclosure",
                    "title": "Server Banner & Version Leaking",
                    "severity": "INFO",
                    "mitre_technique": "T1595.002",
                    "description": f"Server banner disclosed technical stack: {http_info.get('server') or http_info.get('x_powered_by')}.",
                    "remediation": "Disable 'ServerTokens Prod' or strip X-Powered-By / Server response headers in reverse proxy."
                })

        # 4. Dangling DNS / Subdomain Takeover
        if asset.get("dangling_dns"):
            dang = asset["dangling_dns"]
            score += 30.0
            findings.append({
                "id": f"ASM-{hostname}-DANGLING-DNS",
                "asset": hostname,
                "type": "Subdomain Takeover",
                "title": f"Dangling CNAME Record Pointing to {dang['service']}",
                "severity": "HIGH",
                "mitre_technique": "T1584.004",
                "description": f"CNAME pointer '{dang['cname_target']}' matches {dang['service']} fingerprint. If unclaimed, an adversary can register the resource and hijack the subdomain.",
                "remediation": f"Delete the dangling DNS CNAME record or claim the underlying {dang['service']} resource."
            })

        # Cap score at 100.0
        normalized_score = min(100.0, round(score, 1))
        return normalized_score, findings

    # -------------------------------------------------------------
    # MAIN WORKFLOW EXECUTION
    # -------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        """Execute the end-to-end Attack Surface Reconnaissance pipeline."""
        start_time = time.time()
        print(f"{Colors.BOLD}{Colors.CYAN}")
        print("╔══════════════════════════════════════════════════════════════════════════╗")
        print("║      ATTACK SURFACE MONITORING & THREAT RECONNAISSANCE PIPELINE         ║")
        print("║      Lead Engineer: Ajit Nayak | Autonomous ASM & Threat Intel Engine    ║")
        print("╚══════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")

        all_candidates: Set[str] = set()

        for target in self.targets:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                all_candidates.add(target)
            else:
                subs = self.discover_subdomains(target)
                all_candidates.update(subs)

        self.scan_results["summary"]["discovered_subdomains"] = len(all_candidates)
        self.log(f"Beginning active DNS resolution across {len(all_candidates)} host targets...", "INFO")

        # Resolve live hosts concurrently
        live_hosts: List[Dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_host = {executor.submit(self.resolve_host, host): host for host in all_candidates}
            for future in concurrent.futures.as_completed(future_to_host):
                res = future.result()
                if res:
                    live_hosts.append(res)

        self.scan_results["summary"]["live_hosts"] = len(live_hosts)
        self.log(f"Discovered {len(live_hosts)} active, resolvable assets on external perimeter", "SUCCESS")

        # Scan each live host
        for idx, host_data in enumerate(live_hosts, 1):
            hostname = host_data["hostname"]
            primary_ip = host_data["primary_ip"]
            self.log(f"[{idx}/{len(live_hosts)}] Auditing Asset: {hostname} ({primary_ip})", "INFO")

            # Port Scan
            open_ports = self.scan_ports(primary_ip)
            host_data["open_ports"] = open_ports
            self.scan_results["summary"]["total_open_ports"] += len(open_ports)

            # Banner Grab & Security Headers (check HTTP 80, 8080, 443, 8443)
            http_banner = None
            for p_dict in open_ports:
                p_num = p_dict["port"]
                if p_num in [80, 443, 8080, 8443, 8000, 8888]:
                    http_banner = self.audit_http_service(hostname, p_num)
                    if http_banner.get("status_code"):
                        break
            host_data["http_banner"] = http_banner

            # SSL/TLS Check (if 443 or 8443 open)
            ssl_cert = None
            if any(p["port"] in [443, 8443] for p in open_ports):
                ssl_cert = self.audit_ssl_certificate(hostname, 443)
            host_data["ssl_certificate"] = ssl_cert

            # Risk Scoring & Findings
            asset_score, asset_findings = self.calculate_asset_risk(host_data)
            host_data["risk_score"] = asset_score
            host_data["findings_count"] = len(asset_findings)
            self.scan_results["findings"].extend(asset_findings)

            # Asset Risk Rating
            if asset_score >= 70:
                host_data["risk_level"] = "CRITICAL"
            elif asset_score >= 45:
                host_data["risk_level"] = "HIGH"
            elif asset_score >= 20:
                host_data["risk_level"] = "MEDIUM"
            elif asset_score > 0:
                host_data["risk_level"] = "LOW"
            else:
                host_data["risk_level"] = "INFO"

            self.scan_results["assets"].append(host_data)

        # Aggregate Summary
        total_score = 0.0
        for f in self.scan_results["findings"]:
            sev = f["severity"]
            if sev == "CRITICAL":
                self.scan_results["summary"]["critical_vulnerabilities"] += 1
            elif sev == "HIGH":
                self.scan_results["summary"]["high_vulnerabilities"] += 1
            elif sev == "MEDIUM":
                self.scan_results["summary"]["medium_vulnerabilities"] += 1
            elif sev == "LOW":
                self.scan_results["summary"]["low_vulnerabilities"] += 1

        if self.scan_results["assets"]:
            total_score = sum(a["risk_score"] for a in self.scan_results["assets"]) / len(self.scan_results["assets"])
        
        self.scan_results["summary"]["overall_risk_score"] = round(total_score, 1)
        if total_score >= 70 or self.scan_results["summary"]["critical_vulnerabilities"] > 0:
            self.scan_results["summary"]["risk_rating"] = "CRITICAL"
        elif total_score >= 45 or self.scan_results["summary"]["high_vulnerabilities"] > 0:
            self.scan_results["summary"]["risk_rating"] = "HIGH"
        elif total_score >= 20 or self.scan_results["summary"]["medium_vulnerabilities"] > 0:
            self.scan_results["summary"]["risk_rating"] = "MEDIUM"
        else:
            self.scan_results["summary"]["risk_rating"] = "LOW"

        duration = round(time.time() - start_time, 2)
        self.scan_results["metadata"]["scan_duration_seconds"] = duration
        self.print_summary_table(duration)
        return self.scan_results

    def print_summary_table(self, duration: float):
        """Render rich ANSI terminal summary table."""
        summary = self.scan_results["summary"]
        rating = summary["risk_rating"]
        col = Colors.RED if rating in ["CRITICAL", "HIGH"] else (Colors.YELLOW if rating == "MEDIUM" else Colors.GREEN)

        print("\n" + "="*80)
        print(f"{Colors.BOLD}EXECUTIVE ATTACK SURFACE RECONNAISSANCE REPORT{Colors.RESET}")
        print("="*80)
        print(f"  • Execution Duration:    {duration} seconds")
        print(f"  • Candidate Targets:     {summary['discovered_subdomains']}")
        print(f"  • Active Live Hosts:     {summary['live_hosts']}")
        print(f"  • Open Perimeter Ports:  {summary['total_open_ports']}")
        print(f"  • Security Vulnerabilities:")
        print(f"      - {Colors.RED}CRITICAL: {summary['critical_vulnerabilities']}{Colors.RESET}")
        print(f"      - {Colors.YELLOW}HIGH:     {summary['high_vulnerabilities']}{Colors.RESET}")
        print(f"      - {Colors.CYAN}MEDIUM:   {summary['medium_vulnerabilities']}{Colors.RESET}")
        print(f"      - {Colors.BLUE}LOW:      {summary['low_vulnerabilities']}{Colors.RESET}")
        print(f"  • Organization Risk Score: {col}{summary['overall_risk_score']}/100 ({rating}){Colors.RESET}")
        print("="*80)

        if self.scan_results["findings"]:
            print(f"\n{Colors.BOLD}TOP PRIORITY SECURITY FINDINGS:{Colors.RESET}")
            for idx, f in enumerate(self.scan_results["findings"][:8], 1):
                f_col = Colors.RED if f['severity'] in ['CRITICAL', 'HIGH'] else Colors.YELLOW
                print(f"  {idx}. {f_col}[{f['severity']}]{Colors.RESET} {f['asset']} -> {f['title']} (MITRE {f['mitre_technique']})")
        print("="*80 + "\n")


def export_json(report: Dict[str, Any], filepath: str):
    """Save report to disk in JSON format."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"{Colors.GREEN}[+] JSON scan report exported to: {filepath}{Colors.RESET}")


def export_csv(report: Dict[str, Any], filepath: str):
    """Save findings to disk in CSV format for spreadsheet & SOC triage."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Finding ID", "Asset", "Severity", "Finding Type", "MITRE ATT&CK", "Title", "Description", "Remediation"])
        for f_item in report.get("findings", []):
            writer.writerow([
                f_item.get("id"),
                f_item.get("asset"),
                f_item.get("severity"),
                f_item.get("type"),
                f_item.get("mitre_technique"),
                f_item.get("title"),
                f_item.get("description"),
                f_item.get("remediation")
            ])
    print(f"{Colors.GREEN}[+] CSV findings exported to: {filepath}{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Production Attack Surface Management & Threat Reconnaissance Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--target", type=str, help="Single target domain or IP (e.g. example.com)")
    parser.add_argument("-f", "--target-file", type=str, help="Path to text file containing target domains/IPs")
    parser.add_argument("-p", "--ports", type=str, help="Comma-separated list of ports (e.g. 80,443,3306,6379,8080)")
    parser.add_argument("-c", "--threads", type=int, default=25, help="Thread concurrency limit (default: 25)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket and HTTP timeout in seconds (default: 3.0)")
    parser.add_argument("--no-crtsh", action="store_true", help="Disable Certificate Transparency querying")
    parser.add_argument("--no-bruteforce", action="store_true", help="Disable active subdomain bruteforce permutation")
    parser.add_argument("-o", "--output-json", type=str, default="reports/asm_scan_report.json", help="Output JSON path")
    parser.add_argument("--output-csv", type=str, help="Output CSV path")
    parser.add_argument("--webhook", type=str, help="Optional Slack/Discord/Teams/SIEM Webhook URL to dispatch alerts")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logs")

    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.target_file:
        if not os.path.exists(args.target_file):
            print(f"{Colors.RED}[!] Target file not found: {args.target_file}{Colors.RESET}")
            sys.exit(1)
        with open(args.target_file, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        # Default fallback demo target
        print(f"{Colors.YELLOW}[*] No target specified. Defaulting to 'scanme.nmap.org' demo target.{Colors.RESET}")
        targets = ["scanme.nmap.org"]

    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print(f"{Colors.RED}[!] Invalid ports specification. Use comma-separated integers.{Colors.RESET}")
            sys.exit(1)

    pipeline = ASMPipeline(
        targets=targets,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        enable_crtsh=not args.no_crtsh,
        enable_bruteforce=not args.no_bruteforce,
        verbose=args.verbose
    )

    results = pipeline.run()

    if args.output_json:
        export_json(results, args.output_json)
    if args.output_csv:
        export_csv(results, args.output_csv)

    if args.webhook:
        try:
            # Import webhook notifier module
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from alerts.webhook_notifier import AlertNotifier
            notifier = AlertNotifier(args.webhook)
            notifier.dispatch_asm_report(results)
        except Exception as e:
            print(f"{Colors.RED}[!] Webhook notification failed: {e}{Colors.RESET}")


if __name__ == "__main__":
    main()
