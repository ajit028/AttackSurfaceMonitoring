#!/usr/bin/env python3
"""
Attack Surface Management - Real-Time SOC Webhook Notifier
Author: Ajit Nayak (ajit028)
Role Target: Security Operations Center (SOC) / Threat Reconnaissance & Incident Response

Features:
- Multi-Platform Security Alert Dispatcher:
  * Slack Webhooks (Block Kit & Rich Attachments)
  * Discord Webhooks (Structured Embeds)
  * Microsoft Teams Webhooks (Connector Cards / Adaptive Cards)
  * Generic SIEM / SOAR HTTP Endpoints (Splunk HEC, Elastic, Sentinel Webhook)
- Severity-based color coding & triage routing
- Severity filtering (--min-severity: CRITICAL, HIGH, MEDIUM, LOW)
- Dry-run mode for CI/CD test validation
- Exponential backoff & retry mechanism
"""

import argparse
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

# Severity mapping and colors
SEVERITY_COLORS = {
    "CRITICAL": {"hex": "#E01E5A", "int": 0xE01E5A, "emoji": "🚨"},
    "HIGH": {"hex": "#FF8C00", "int": 0xFF8C00, "emoji": "⚠️"},
    "MEDIUM": {"hex": "#FFD700", "int": 0xFFD700, "emoji": "⚡"},
    "LOW": {"hex": "#2EB886", "int": 0x2EB886, "emoji": "ℹ️"},
    "INFO": {"hex": "#439FE0", "int": 0x439FE0, "emoji": "📋"}
}

SEVERITY_RANKS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


class AlertNotifier:
    """
    SOC Alert Dispatcher for Attack Surface Management findings
    """
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        min_severity: str = "MEDIUM",
        dry_run: bool = False,
        timeout: float = 5.0,
        max_retries: int = 3
    ):
        self.webhook_url = webhook_url or os.environ.get("ASM_ALERT_WEBHOOK", "")
        self.min_severity = min_severity.upper()
        self.dry_run = dry_run
        self.timeout = timeout
        self.max_retries = max_retries

    def _detect_platform(self, url: str) -> str:
        """Identify destination platform from webhook URL syntax."""
        url_lower = url.lower()
        if "hooks.slack.com" in url_lower:
            return "slack"
        elif "discord.com/api/webhooks" in url_lower:
            return "discord"
        elif "office.com/webhook" in url_lower or "webhook.office.com" in url_lower:
            return "msteams"
        else:
            return "generic"

    def _send_http_post(self, url: str, payload: Dict[str, Any]) -> bool:
        """Send HTTP POST request with retry logic."""
        if self.dry_run or not url:
            print("[DRY-RUN] Webhook payload simulated successfully:")
            print(json.dumps(payload, indent=2))
            return True

        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AttackSurfaceMonitoring-Notifier/2.0 (SOC Alerting Engine)"
        }
        req = urllib.request.Request(url, data=data, headers=headers)

        for attempt in range(1, self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if 200 <= response.status < 300:
                        return True
            except urllib.error.HTTPError as e:
                print(f"[!] Webhook delivery HTTP error (attempt {attempt}/{self.max_retries}): {e.code} - {e.reason}")
            except Exception as e:
                print(f"[!] Webhook delivery error (attempt {attempt}/{self.max_retries}): {e}")
            time.sleep(attempt * 1.5)

        return False

    # -------------------------------------------------------------
    # PAYLOAD BUILDERS
    # -------------------------------------------------------------
    def _build_slack_payload(self, title: str, summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Format Slack Block Kit alert."""
        rating = summary.get("risk_rating", "INFO")
        color = SEVERITY_COLORS.get(rating, SEVERITY_COLORS["INFO"])["hex"]
        emoji = SEVERITY_COLORS.get(rating, SEVERITY_COLORS["INFO"])["emoji"]

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Attack Surface Security Alert: {title}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Overall Risk:*\n`{rating}` ({summary.get('overall_risk_score', 0)}/100)"},
                    {"type": "mrkdwn", "text": f"*Live Perimeter Assets:*\n`{summary.get('live_hosts', 0)}`"},
                    {"type": "mrkdwn", "text": f"*Open Ports:*\n`{summary.get('total_open_ports', 0)}`"},
                    {"type": "mrkdwn", "text": f"*Critical/High Findings:*\n`{summary.get('critical_vulnerabilities', 0)} Critical | {summary.get('high_vulnerabilities', 0)} High`"}
                ]
            },
            {"type": "divider"}
        ]

        # Add top findings
        for f in findings[:5]:
            f_sev = f.get("severity", "INFO")
            f_emoji = SEVERITY_COLORS.get(f_sev, SEVERITY_COLORS["INFO"])["emoji"]
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{f_emoji} *[{f_sev}] {f.get('asset', 'Target')}*\n*Finding:* {f.get('title')}\n*MITRE:* `{f.get('mitre_technique', 'N/A')}`\n*Remediation:* {f.get('remediation')}"
                }
            })

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }

    def _build_discord_payload(self, title: str, summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Format Discord Embed alert."""
        rating = summary.get("risk_rating", "INFO")
        color_int = SEVERITY_COLORS.get(rating, SEVERITY_COLORS["INFO"])["int"]
        emoji = SEVERITY_COLORS.get(rating, SEVERITY_COLORS["INFO"])["emoji"]

        embed_fields = [
            {"name": "Overall Posture", "value": f"{rating} ({summary.get('overall_risk_score', 0)}/100)", "inline": True},
            {"name": "Live Assets", "value": str(summary.get("live_hosts", 0)), "inline": True},
            {"name": "Open Ports", "value": str(summary.get("total_open_ports", 0)), "inline": True},
            {"name": "Vulnerability Counts", "value": f"🚨 {summary.get('critical_vulnerabilities', 0)} Crit | ⚠️ {summary.get('high_vulnerabilities', 0)} High | ⚡ {summary.get('medium_vulnerabilities', 0)} Med", "inline": False}
        ]

        for f in findings[:4]:
            embed_fields.append({
                "name": f"[{f.get('severity')}] {f.get('asset')}",
                "value": f"**{f.get('title')}**\nMITRE: `{f.get('mitre_technique', 'N/A')}`\nFix: {f.get('remediation')}",
                "inline": False
            })

        return {
            "username": "AttackSurface-SOC-Bot",
            "embeds": [
                {
                    "title": f"{emoji} Security Alert: {title}",
                    "description": "Perimeter reconnaissance discovered actionable security exposures requiring SOC triage.",
                    "color": color_int,
                    "fields": embed_fields,
                    "footer": {"text": "AttackSurfaceMonitoring | Threat Recon Pipeline"},
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                }
            ]
        }

    def _build_teams_payload(self, title: str, summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Format MS Teams MessageCard."""
        rating = summary.get("risk_rating", "INFO")
        color_hex = SEVERITY_COLORS.get(rating, SEVERITY_COLORS["INFO"])["hex"].replace("#", "")

        facts = [
            {"name": "Risk Rating", "value": f"{rating} ({summary.get('overall_risk_score', 0)}/100)"},
            {"name": "Live Assets", "value": str(summary.get("live_hosts", 0))},
            {"name": "Critical / High Vulns", "value": f"{summary.get('critical_vulnerabilities', 0)} / {summary.get('high_vulnerabilities', 0)}"}
        ]

        sections = [
            {
                "activityTitle": f"Attack Surface Alert: {title}",
                "activitySubtitle": f"Timestamp: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "facts": facts,
                "markdown": True
            }
        ]

        for f in findings[:4]:
            sections.append({
                "title": f"[{f.get('severity')}] {f.get('asset')} - {f.get('title')}",
                "text": f"**MITRE ATT&CK:** {f.get('mitre_technique', 'N/A')}\n\n**Remediation:** {f.get('remediation')}",
                "markdown": True
            })

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_hex,
            "summary": f"Attack Surface Security Alert - {rating}",
            "sections": sections
        }

    def _build_generic_payload(self, title: str, summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Format Generic SIEM / JSON event."""
        return {
            "event_type": "ATTACK_SURFACE_MONITORING_ALERT",
            "alert_title": title,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "findings": findings
        }

    # -------------------------------------------------------------
    # DISPATCH METHODS
    # -------------------------------------------------------------
    def dispatch_asm_report(self, report_data: Dict[str, Any]) -> bool:
        """Filter and send alert for an ASM pipeline scan report."""
        summary = report_data.get("summary", {})
        findings = report_data.get("findings", [])
        
        # Filter findings by min_severity
        min_rank = SEVERITY_RANKS.get(self.min_severity, 2)
        filtered_findings = [f for f in findings if SEVERITY_RANKS.get(f.get("severity", "INFO"), 0) >= min_rank]

        if not filtered_findings and summary.get("overall_risk_score", 0) < 20:
            print(f"[*] No findings meeting severity threshold ({self.min_severity}). Alert dispatch suppressed.")
            return True

        title = f"Perimeter Scan ({summary.get('live_hosts', 0)} Live Hosts, {len(filtered_findings)} Actionable Findings)"
        platform = self._detect_platform(self.webhook_url)

        if platform == "slack":
            payload = self._build_slack_payload(title, summary, filtered_findings)
        elif platform == "discord":
            payload = self._build_discord_payload(title, summary, filtered_findings)
        elif platform == "msteams":
            payload = self._build_teams_payload(title, summary, filtered_findings)
        else:
            payload = self._build_generic_payload(title, summary, filtered_findings)

        print(f"[*] Dispatching security alert to {platform.upper()} webhook...")
        success = self._send_http_post(self.webhook_url, payload)
        if success:
            print("[+] Alert successfully delivered to SOC webhook channel.")
        else:
            print("[!] Alert delivery encountered an error.")
        return success

    def dispatch_cloud_report(self, cloud_data: Dict[str, Any]) -> bool:
        """Filter and send alert for Cloud Asset Finder discoveries."""
        summary = cloud_data.get("summary", {})
        c_findings = cloud_data.get("cloud_storage_findings", [])
        t_findings = cloud_data.get("takeover_findings", [])
        all_findings = []

        for c in c_findings:
            if c.get("status") == "PUBLIC_READ_EXPOSED":
                all_findings.append({
                    "asset": c.get("url"),
                    "severity": "CRITICAL",
                    "title": f"Exposed Cloud Storage ({c.get('provider')})",
                    "mitre_technique": c.get("mitre_technique", "T1530"),
                    "remediation": c.get("remediation")
                })

        for t in t_findings:
            all_findings.append({
                "asset": t.get("hostname"),
                "severity": t.get("severity", "HIGH"),
                "title": t.get("title"),
                "mitre_technique": t.get("mitre_technique", "T1584.004"),
                "remediation": t.get("remediation")
            })

        if not all_findings:
            print("[*] No high-risk cloud exposures found. Webhook dispatch suppressed.")
            return True

        meta = cloud_data.get("metadata", {})
        title = f"Cloud & Takeover Alert for '{meta.get('organization')}' ({len(all_findings)} Critical Findings)"
        platform = self._detect_platform(self.webhook_url)

        synth_summary = {
            "risk_rating": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in all_findings) else "HIGH",
            "overall_risk_score": 85.0 if any(f["severity"] == "CRITICAL" for f in all_findings) else 60.0,
            "live_hosts": summary.get("subdomains_audited", 0),
            "total_open_ports": 0,
            "critical_vulnerabilities": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
            "high_vulnerabilities": sum(1 for f in all_findings if f["severity"] == "HIGH")
        }

        if platform == "slack":
            payload = self._build_slack_payload(title, synth_summary, all_findings)
        elif platform == "discord":
            payload = self._build_discord_payload(title, synth_summary, all_findings)
        elif platform == "msteams":
            payload = self._build_teams_payload(title, synth_summary, all_findings)
        else:
            payload = self._build_generic_payload(title, synth_summary, all_findings)

        print(f"[*] Dispatching cloud security alert to {platform.upper()} webhook...")
        success = self._send_http_post(self.webhook_url, payload)
        if success:
            print("[+] Cloud security alert successfully delivered.")
        return success


def main():
    parser = argparse.ArgumentParser(description="ASM Real-Time Security Alert Notifier")
    parser.add_argument("-w", "--webhook", type=str, help="Webhook URL (Slack, Discord, MS Teams, Generic)")
    parser.add_argument("-r", "--report", type=str, required=True, help="Path to JSON scan report file")
    parser.add_argument("-m", "--min-severity", type=str, default="MEDIUM", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Minimum severity to alert on")
    parser.add_argument("--dry-run", action="store_true", help="Print payload without making outbound network calls")

    args = parser.parse_args()

    if not os.path.exists(args.report):
        print(f"[!] Report file not found: {args.report}")
        sys.exit(1)

    with open(args.report, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    notifier = AlertNotifier(
        webhook_url=args.webhook,
        min_severity=args.min_severity,
        dry_run=args.dry_run
    )

    if "cloud_storage_findings" in report_data or "takeover_findings" in report_data:
        notifier.dispatch_cloud_report(report_data)
    else:
        notifier.dispatch_asm_report(report_data)


if __name__ == "__main__":
    main()
