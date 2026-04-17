"""
test_enrichment.py
------------------
Full pipeline test: parse email -> extract IOCs -> enrich with threat intel APIs.

Run with:  python test_enrichment.py

If you haven't added API keys to config.py yet, the script still runs —
it just skips the live lookups and shows you what WOULD be sent to the APIs.
"""

from email_parser import PhishingParser
from threat_intel import ThreatIntel, EnrichedIOCs
from sample_emails import ALL_SAMPLES
import config

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"


VERDICT_COLOURS = {
    "MALICIOUS":  RED,
    "SUSPICIOUS": YELLOW,
    "CLEAN":      GREEN,
    "UNKNOWN":    CYAN,
    "ERROR":      "\033[90m",   # grey
}


def print_banner(text, char="="):
    print(f"\n{BOLD}{char*62}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{char*62}{RESET}")


def print_section(title):
    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {'─'*52}")


def verdict_tag(verdict: str) -> str:
    c = VERDICT_COLOURS.get(verdict, "")
    return f"{c}{BOLD}[{verdict}]{RESET}"


def print_vt_result(r):
    tag = verdict_tag(r.verdict)
    print(f"    {tag}  {r.indicator_type.upper()}: {r.indicator[:55]}")
    if r.error:
        print(f"           Error: {r.error}")
    else:
        print(f"           Detections : {r.detection_ratio} engines")
        if r.threat_names:
            print(f"           Threats    : {', '.join(r.threat_names[:3])}")
        if r.categories:
            print(f"           Categories : {', '.join(r.categories[:3])}")
        if r.last_analysis_date:
            print(f"           Last scan  : {r.last_analysis_date}")
        if r.vt_link:
            print(f"           VT link    : {r.vt_link}")


def print_abuse_result(r):
    tag = verdict_tag(r.verdict)
    print(f"    {tag}  IP: {r.ip}")
    if r.error:
        print(f"           Error: {r.error}")
    else:
        score_colour = RED if r.abuse_confidence_score >= 75 else (YELLOW if r.abuse_confidence_score >= 25 else GREEN)
        print(f"           Abuse score : {score_colour}{r.abuse_confidence_score}/100{RESET}  ({r.total_reports} reports)")
        if r.country_code:
            print(f"           Country     : {r.country_code}")
        if r.isp:
            print(f"           ISP         : {r.isp}")
        if r.usage_type:
            print(f"           Usage type  : {r.usage_type}")
        if r.is_tor:
            print(f"           {RED}! Known Tor exit node{RESET}")
        if r.last_reported:
            print(f"           Last report : {r.last_reported}")


def run_full_analysis(name: str, raw_email: str, ti: ThreatIntel):
    print_banner(f"SAMPLE: {name.upper().replace('_', ' ')}")

    # Step 1: Parse
    parser = PhishingParser(raw_email)
    report = parser.analyse()

    risk_colour = MAGENTA if report.risk_label == "CRITICAL" else (RED if report.risk_label == "HIGH" else YELLOW)
    print(f"\n  Subject  : {report.raw_subject}")
    print(f"  From     : {report.headers.sender_display_name} <{report.headers.sender_email}>")
    print(f"  Parser   : {risk_colour}{BOLD}{report.risk_label} ({report.risk_score}/100){RESET}")

    # Step 2: Show IOCs queued for enrichment
    print_section("IOCs Queued for Enrichment")
    if report.iocs.urls:
        print(f"    URLs    : {len(report.iocs.urls)}")
        for u in report.iocs.urls[:3]:
            print(f"              {u[:65]}")
    if report.iocs.domains:
        print(f"    Domains : {', '.join(report.iocs.domains[:5])}")
    if report.iocs.ips:
        print(f"    IPs     : {', '.join(report.iocs.ips[:5])}")

    # Step 3: Enrich
    if not ti.vt_key and not ti.abuse_key:
        print(f"\n  {YELLOW}No API keys configured — skipping live lookups.{RESET}")
        print(f"  Add your keys to config.py to enable threat intel enrichment.")
        return

    enriched = ti.enrich_iocs(report.iocs, max_urls=2, max_domains=2, max_ips=3)

    # Step 4: Print enrichment results
    if enriched.vt_urls or enriched.vt_domains or enriched.vt_ips:
        print_section("VirusTotal Results")
        for r in enriched.vt_urls:
            print_vt_result(r)
        for r in enriched.vt_domains:
            print_vt_result(r)
        for r in enriched.vt_ips:
            print_vt_result(r)

    if enriched.abuse_ips:
        print_section("AbuseIPDB Results")
        for r in enriched.abuse_ips:
            print_abuse_result(r)

    # Step 5: Combined score
    if enriched.enrichment_risk_factors:
        print_section("Enrichment Risk Factors")
        for i, f in enumerate(enriched.enrichment_risk_factors, 1):
            print(f"    {i:2}. {f}")

    combined_score = min(report.risk_score + enriched.enrichment_risk_score, 100)
    combined_label = _label(combined_score)
    combined_colour = MAGENTA if combined_label == "CRITICAL" else RED

    print_section("Combined Verdict")
    print(f"    Parser score     : {report.risk_score}/100  ({report.risk_label})")
    print(f"    Enrichment score : +{enriched.enrichment_risk_score}")
    print(f"    Combined         : {combined_colour}{BOLD}{combined_score}/100  {combined_label}{RESET}")
    print(f"    Malicious IOCs   : {enriched.total_malicious}")
    print(f"    Suspicious IOCs  : {enriched.total_suspicious}")


def _label(score: int) -> str:
    if score >= 70:   return "CRITICAL"
    if score >= 45:   return "HIGH"
    if score >= 20:   return "MEDIUM"
    return "LOW"


def main():
    print_banner("PHISHING ANALYSER — Full Pipeline Test", "█")

    # Check for API keys
    has_vt    = bool(config.VIRUSTOTAL_API_KEY.strip())
    has_abuse = bool(config.ABUSEIPDB_API_KEY.strip())

    print(f"\n  API Key Status:")
    print(f"    VirusTotal  : {GREEN+'✓ Configured'+RESET if has_vt  else YELLOW+'✗ Not set (add to config.py)'+RESET}")
    print(f"    AbuseIPDB   : {GREEN+'✓ Configured'+RESET if has_abuse else YELLOW+'✗ Not set (add to config.py)'+RESET}")

    ti = ThreatIntel(
        vt_api_key    = config.VIRUSTOTAL_API_KEY  or None,
        abuseipdb_key = config.ABUSEIPDB_API_KEY   or None,
        rate_limit    = 16.0,   # safe for free VT tier
    )

    # Only test 2 samples to conserve API quota
    SAMPLES_TO_TEST = ["hmrc_refund", "barclays_security"]

    for name in SAMPLES_TO_TEST:
        run_full_analysis(name, ALL_SAMPLES[name], ti)

    print_banner("DONE", "-")
    print("  Next step: python -m streamlit run app.py\n")


if __name__ == "__main__":
    main()
