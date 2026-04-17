"""
test_parser.py
--------------
Run the PhishingParser against all sample emails and print detailed results.
This is your verification step before wiring up the UI.

Run with:  python test_parser.py
"""

from email_parser import PhishingParser
from sample_emails import ALL_SAMPLES


RISK_COLOURS = {
    "LOW":      "\033[92m",   # green
    "MEDIUM":   "\033[93m",   # yellow
    "HIGH":     "\033[91m",   # red
    "CRITICAL": "\033[95m",   # magenta
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def banner(text: str, char: str = "="):
    print(f"\n{BOLD}{char * 60}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{char * 60}{RESET}")


def section(title: str):
    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {'─' * 50}")


def run_sample(name: str, raw_email: str):
    banner(f"SAMPLE: {name.upper().replace('_', ' ')}")

    parser = PhishingParser(raw_email)
    report = parser.analyse()

    colour = RISK_COLOURS.get(report.risk_label, "")
    print(f"\n  Subject : {report.raw_subject}")
    print(f"  From    : {report.headers.sender_display_name} <{report.headers.sender_email}>")
    print(f"  Risk    : {colour}{BOLD}{report.risk_label} ({report.risk_score}/100){RESET}")

    # --- Header flags ---
    section("Header Anomalies")
    flags = {
        "Display name spoofing":  report.headers.display_name_spoofing,
        "Reply-To mismatch":      report.headers.reply_to_mismatch,
        "Return-Path mismatch":   report.headers.return_path_mismatch,
        "Free email sender":      report.headers.free_email_sender,
        "Suspicious Message-ID":  report.headers.suspicious_message_id,
    }
    for label, triggered in flags.items():
        icon = "✗" if triggered else "✓"
        colour_flag = "\033[91m" if triggered else "\033[92m"
        print(f"    {colour_flag}{icon}{RESET}  {label}")

    # --- URLs ---
    if report.urls:
        section(f"URLs Found ({len(report.urls)})")
        for u in report.urls:
            issues = []
            if u.ip_based:        issues.append("IP-based")
            if u.url_shortener:   issues.append("shortener")
            if u.homograph_risk:  issues.append("homograph")
            if u.typosquat_candidates: issues.append(f"typosquat:{','.join(u.typosquat_candidates)}")
            if u.suspicious_keywords:  issues.append(f"keywords:{','.join(u.suspicious_keywords[:2])}")
            tag = f"  \033[91m[{', '.join(issues)}]{RESET}" if issues else ""
            print(f"    • {u.domain}{tag}")
            print(f"      {u.raw_url[:90]}{'...' if len(u.raw_url) > 90 else ''}")

    # --- Content ---
    section("Content Analysis")
    c = report.content
    if c.urgency_phrases:
        print(f"    Urgency phrases  : {', '.join(set(c.urgency_phrases[:4]))}")
    if c.credential_lures:
        print(f"    Credential lures : {', '.join(set(c.credential_lures[:4]))}")
    if c.threat_phrases:
        print(f"    Threat language  : {', '.join(set(c.threat_phrases[:4]))}")
    if c.html_text_mismatch:
        print(f"    \033[91m! HTML href/text mismatch detected{RESET}")
    if c.form_actions:
        print(f"    \033[91m! Form actions: {', '.join(c.form_actions)}{RESET}")
    if c.sender_impersonation:
        print(f"    Brand refs       : {', '.join(set(c.sender_impersonation[:4]))}")

    # --- Attachments ---
    if report.attachments:
        section(f"Attachments ({len(report.attachments)})")
        for a in report.attachments:
            flag = "\033[91m[SUSPICIOUS] " + a.reason + RESET if a.suspicious else ""
            print(f"    • {a.filename} ({a.content_type}, {a.size_bytes} bytes) {flag}")

    # --- IOCs ---
    section("Extracted IOCs")
    iocs = report.iocs
    if iocs.urls:
        print(f"    URLs     ({len(iocs.urls)}) : {iocs.urls[0][:70]}{'...' if len(iocs.urls[0]) > 70 else ''}")
    if iocs.domains:
        print(f"    Domains  ({len(iocs.domains)}) : {', '.join(iocs.domains[:4])}")
    if iocs.ips:
        print(f"    IPs      ({len(iocs.ips)}) : {', '.join(iocs.ips)}")
    if iocs.email_addresses:
        print(f"    Emails   ({len(iocs.email_addresses)}) : {', '.join(iocs.email_addresses[:3])}")

    # --- Risk factors ---
    section("Risk Factors Triggered")
    for i, factor in enumerate(report.risk_factors, 1):
        print(f"    {i:2}. {factor}")

    # --- MITRE ---
    if report.mitre_techniques:
        section("MITRE ATT&CK Techniques")
        for t in report.mitre_techniques:
            print(f"    [{t['id']}] {t['name']}")


def main():
    banner("PHISHING EMAIL ANALYSER — Parser Test Run", "█")
    print(f"  Testing {len(ALL_SAMPLES)} sample emails...\n")

    for name, raw in ALL_SAMPLES.items():
        run_sample(name, raw)

    banner("TEST COMPLETE", "-")
    print("  All samples parsed. Review output above for any errors.\n")


if __name__ == "__main__":
    main()
