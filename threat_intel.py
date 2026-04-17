"""
threat_intel.py
---------------
Live threat intelligence lookups using free public APIs.

APIs used:
  - VirusTotal  (URLs, domains, IPs)  — free tier: 4 requests/min, 500/day
  - AbuseIPDB   (IPs only)            — free tier: 1000 requests/day

How to get your free API keys:
  VirusTotal : https://www.virustotal.com/gui/join-us  (free account)
  AbuseIPDB  : https://www.abuseipdb.com/register      (free account)

Usage:
    from threat_intel import ThreatIntel
    ti = ThreatIntel(vt_api_key="YOUR_VT_KEY", abuseipdb_key="YOUR_ABUSE_KEY")
    result = ti.enrich_iocs(ioc_bundle)
"""

import time
import ipaddress
import hashlib
import base64
import requests
from dataclasses import dataclass, field
from typing import Optional
from email_parser import IOCBundle


# ---------------------------------------------------------------------------
# Result data structures
# ---------------------------------------------------------------------------

@dataclass
class VTResult:
    """VirusTotal result for a single indicator."""
    indicator: str
    indicator_type: str          # "url", "domain", "ip"
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    threat_names: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    last_analysis_date: Optional[str] = None
    vt_link: Optional[str] = None
    error: Optional[str] = None

    @property
    def verdict(self) -> str:
        if self.error:
            return "ERROR"
        if self.malicious_count >= 5:
            return "MALICIOUS"
        elif self.malicious_count >= 1 or self.suspicious_count >= 3:
            return "SUSPICIOUS"
        elif self.total_engines > 0:
            return "CLEAN"
        return "UNKNOWN"

    @property
    def detection_ratio(self) -> str:
        if self.total_engines == 0:
            return "N/A"
        return f"{self.malicious_count}/{self.total_engines}"


@dataclass
class AbuseIPDBResult:
    """AbuseIPDB result for a single IP address."""
    ip: str
    abuse_confidence_score: int = 0   # 0-100
    total_reports: int = 0
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    is_tor: bool = False
    is_whitelisted: bool = False
    usage_type: Optional[str] = None
    last_reported: Optional[str] = None
    error: Optional[str] = None

    @property
    def verdict(self) -> str:
        if self.error:
            return "ERROR"
        if self.abuse_confidence_score >= 75:
            return "MALICIOUS"
        elif self.abuse_confidence_score >= 25:
            return "SUSPICIOUS"
        elif self.is_tor:
            return "SUSPICIOUS"
        return "CLEAN"


@dataclass
class EnrichedIOCs:
    """Full enrichment results for all IOCs from an email."""
    vt_urls: list[VTResult] = field(default_factory=list)
    vt_domains: list[VTResult] = field(default_factory=list)
    vt_ips: list[VTResult] = field(default_factory=list)
    abuse_ips: list[AbuseIPDBResult] = field(default_factory=list)

    # Summary
    total_malicious: int = 0
    total_suspicious: int = 0
    enrichment_risk_score: int = 0
    enrichment_risk_factors: list[str] = field(default_factory=list)

    def summarise(self):
        """Calculate summary stats after all lookups are complete."""
        all_vt = self.vt_urls + self.vt_domains + self.vt_ips

        for r in all_vt:
            if r.verdict == "MALICIOUS":
                self.total_malicious += 1
                self.enrichment_risk_score += 35
                self.enrichment_risk_factors.append(
                    f"VirusTotal: {r.indicator} flagged MALICIOUS "
                    f"({r.detection_ratio} engines) — {', '.join(r.threat_names[:2])}"
                )
            elif r.verdict == "SUSPICIOUS":
                self.total_suspicious += 1
                self.enrichment_risk_score += 15
                self.enrichment_risk_factors.append(
                    f"VirusTotal: {r.indicator} flagged SUSPICIOUS "
                    f"({r.detection_ratio} engines)"
                )

        for r in self.abuse_ips:
            if r.verdict == "MALICIOUS":
                self.total_malicious += 1
                self.enrichment_risk_score += 30
                self.enrichment_risk_factors.append(
                    f"AbuseIPDB: {r.ip} abuse score {r.abuse_confidence_score}/100 "
                    f"({r.total_reports} reports) — {r.isp or 'unknown ISP'}"
                )
            elif r.verdict == "SUSPICIOUS":
                self.total_suspicious += 1
                self.enrichment_risk_score += 12
                self.enrichment_risk_factors.append(
                    f"AbuseIPDB: {r.ip} abuse score {r.abuse_confidence_score}/100"
                )
            if r.is_tor:
                self.enrichment_risk_score += 20
                self.enrichment_risk_factors.append(
                    f"AbuseIPDB: {r.ip} is a known Tor exit node"
                )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ThreatIntel:
    """
    Enriches extracted IOCs with live threat intelligence.

    Args:
        vt_api_key:    Your VirusTotal API key (free at virustotal.com)
        abuseipdb_key: Your AbuseIPDB API key  (free at abuseipdb.com)
        rate_limit:    Seconds to wait between VT requests (default 16s for free tier)
                       Free tier = 4 req/min, so 16s between calls is safe.
    """

    VT_BASE   = "https://www.virustotal.com/api/v3"
    ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        abuseipdb_key: Optional[str] = None,
        rate_limit: float = 16.0,
    ):
        self.vt_key    = vt_api_key
        self.abuse_key = abuseipdb_key
        self.rate_limit = rate_limit
        self._last_vt_call = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_iocs(self, iocs: IOCBundle, max_urls: int = 3, max_domains: int = 3, max_ips: int = 5) -> EnrichedIOCs:
        """
        Run all available API lookups for the given IOC bundle.

        Limits are applied to stay within free tier quotas.
        URLs and domains that are well-known safe (e.g. google.com) are skipped.

        Args:
            iocs:        IOCBundle from PhishingParser.analyse()
            max_urls:    Max number of URLs to submit to VT
            max_domains: Max number of domains to look up on VT
            max_ips:     Max number of IPs to look up

        Returns:
            EnrichedIOCs with all results populated.
        """
        result = EnrichedIOCs()

        if not self.vt_key and not self.abuse_key:
            return result  # No keys configured, return empty

        # Filter out known safe/irrelevant indicators
        urls_to_check    = self._filter_safe(iocs.urls, kind="url")[:max_urls]
        domains_to_check = self._filter_safe(iocs.domains, kind="domain")[:max_domains]
        ips_to_check     = self._deduplicate_ips(iocs.ips)[:max_ips]

        print(f"\n[ThreatIntel] Starting enrichment...")
        print(f"  URLs to check    : {len(urls_to_check)}")
        print(f"  Domains to check : {len(domains_to_check)}")
        print(f"  IPs to check     : {len(ips_to_check)}")

        # --- VirusTotal: URLs ---
        if self.vt_key:
            for url in urls_to_check:
                print(f"  [VT] Scanning URL: {url[:60]}...")
                vt_res = self._vt_url(url)
                result.vt_urls.append(vt_res)
                self._vt_sleep()

            # --- VirusTotal: Domains ---
            for domain in domains_to_check:
                print(f"  [VT] Looking up domain: {domain}")
                vt_res = self._vt_domain(domain)
                result.vt_domains.append(vt_res)
                self._vt_sleep()

            # --- VirusTotal: IPs ---
            for ip in ips_to_check:
                print(f"  [VT] Looking up IP: {ip}")
                vt_res = self._vt_ip(ip)
                result.vt_ips.append(vt_res)
                self._vt_sleep()

        # --- AbuseIPDB: IPs ---
        if self.abuse_key:
            for ip in ips_to_check:
                print(f"  [AbuseIPDB] Checking IP: {ip}")
                abuse_res = self._abuseipdb_ip(ip)
                result.abuse_ips.append(abuse_res)
                time.sleep(1)  # Be polite to the API

        result.summarise()
        print(f"\n[ThreatIntel] Enrichment complete.")
        print(f"  Malicious indicators : {result.total_malicious}")
        print(f"  Suspicious indicators: {result.total_suspicious}")

        return result

    # ------------------------------------------------------------------
    # VirusTotal methods
    # ------------------------------------------------------------------

    def _vt_url(self, url: str) -> VTResult:
        """Submit a URL to VirusTotal for analysis."""
        res = VTResult(indicator=url, indicator_type="url")
        try:
            # VT requires URLs to be base64url-encoded without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            endpoint = f"{self.VT_BASE}/urls/{url_id}"

            response = requests.get(
                endpoint,
                headers={"x-apikey": self.vt_key},
                timeout=15,
            )

            if response.status_code == 404:
                # Not in VT database yet — submit it
                submit = requests.post(
                    f"{self.VT_BASE}/urls",
                    headers={"x-apikey": self.vt_key},
                    data={"url": url},
                    timeout=15,
                )
                if submit.status_code == 200:
                    res.error = "Submitted for analysis (not yet in database)"
                else:
                    res.error = f"HTTP {submit.status_code}"
                return res

            if response.status_code != 200:
                res.error = f"HTTP {response.status_code}"
                return res

            data = response.json().get("data", {}).get("attributes", {})
            return self._parse_vt_stats(res, data, url)

        except requests.exceptions.Timeout:
            res.error = "Request timed out"
        except requests.exceptions.ConnectionError:
            res.error = "Connection error — check internet"
        except Exception as e:
            res.error = str(e)
        return res

    def _vt_domain(self, domain: str) -> VTResult:
        """Look up a domain on VirusTotal."""
        res = VTResult(indicator=domain, indicator_type="domain")
        try:
            response = requests.get(
                f"{self.VT_BASE}/domains/{domain}",
                headers={"x-apikey": self.vt_key},
                timeout=15,
            )
            if response.status_code == 404:
                res.error = "Not found in VirusTotal database"
                return res
            if response.status_code != 200:
                res.error = f"HTTP {response.status_code}"
                return res

            data = response.json().get("data", {}).get("attributes", {})
            res = self._parse_vt_stats(res, data, domain)
            res.vt_link = f"https://www.virustotal.com/gui/domain/{domain}"

            # Extra: grab categories assigned by VT partners
            cats = data.get("categories", {})
            res.categories = list(set(cats.values()))[:5]
            return res

        except Exception as e:
            res.error = str(e)
        return res

    def _vt_ip(self, ip: str) -> VTResult:
        """Look up an IP address on VirusTotal."""
        res = VTResult(indicator=ip, indicator_type="ip")
        try:
            response = requests.get(
                f"{self.VT_BASE}/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_key},
                timeout=15,
            )
            if response.status_code != 200:
                res.error = f"HTTP {response.status_code}"
                return res

            data = response.json().get("data", {}).get("attributes", {})
            res = self._parse_vt_stats(res, data, ip)
            res.vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
            return res

        except Exception as e:
            res.error = str(e)
        return res

    def _parse_vt_stats(self, res: VTResult, data: dict, indicator: str) -> VTResult:
        """Extract standard stats from a VT API attributes block."""
        stats = data.get("last_analysis_stats", {})
        results = data.get("last_analysis_results", {})

        res.malicious_count  = stats.get("malicious", 0)
        res.suspicious_count = stats.get("suspicious", 0)
        res.harmless_count   = stats.get("harmless", 0)
        res.undetected_count = stats.get("undetected", 0)
        res.total_engines    = sum(stats.values())

        # Collect threat names from engines that flagged it
        threat_names = set()
        for engine_data in results.values():
            if engine_data.get("category") in ("malicious", "suspicious"):
                name = engine_data.get("result")
                if name and name not in ("malicious", "suspicious", "phishing"):
                    threat_names.add(name)
        res.threat_names = list(threat_names)[:5]

        # Last analysis date
        ts = data.get("last_analysis_date")
        if ts:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            res.last_analysis_date = dt.strftime("%Y-%m-%d %H:%M UTC")

        return res

    # ------------------------------------------------------------------
    # AbuseIPDB methods
    # ------------------------------------------------------------------

    def _abuseipdb_ip(self, ip: str) -> AbuseIPDBResult:
        """Check an IP against AbuseIPDB."""
        res = AbuseIPDBResult(ip=ip)
        try:
            response = requests.get(
                f"{self.ABUSE_BASE}/check",
                headers={
                    "Key": self.abuse_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": True,
                },
                timeout=15,
            )
            if response.status_code != 200:
                res.error = f"HTTP {response.status_code}"
                return res

            data = response.json().get("data", {})
            res.abuse_confidence_score = data.get("abuseConfidenceScore", 0)
            res.total_reports          = data.get("totalReports", 0)
            res.country_code           = data.get("countryCode")
            res.isp                    = data.get("isp")
            res.domain                 = data.get("domain")
            res.is_tor                 = data.get("isTor", False)
            res.is_whitelisted         = data.get("isWhitelisted", False)
            res.usage_type             = data.get("usageType")
            res.last_reported          = data.get("lastReportedAt")
            return res

        except requests.exceptions.Timeout:
            res.error = "Request timed out"
        except Exception as e:
            res.error = str(e)
        return res

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _vt_sleep(self):
        """Enforce rate limit between VT API calls (free tier: 4/min)."""
        elapsed = time.time() - self._last_vt_call
        if elapsed < self.rate_limit:
            wait = self.rate_limit - elapsed
            print(f"  [VT] Rate limit — waiting {wait:.0f}s...")
            time.sleep(wait)
        self._last_vt_call = time.time()

    @staticmethod
    def _filter_safe(indicators: list[str], kind: str) -> list[str]:
        """Remove well-known safe indicators to avoid wasting API quota."""
        SAFE_DOMAINS = {
            "google.com", "microsoft.com", "apple.com", "amazon.com",
            "cloudflare.com", "gstatic.com", "googleapis.com",
            "w3.org", "schema.org", "example.com", "example.co.uk",
        }
        SAFE_URL_PREFIXES = (
            "https://www.google.", "https://www.microsoft.",
            "https://www.apple.", "https://schema.org",
        )

        filtered = []
        for ind in indicators:
            if kind == "domain" and ind.lower() in SAFE_DOMAINS:
                continue
            if kind == "url":
                if any(ind.startswith(p) for p in SAFE_URL_PREFIXES):
                    continue
            filtered.append(ind)
        return filtered

    @staticmethod
    def _deduplicate_ips(ips: list[str]) -> list[str]:
        """Deduplicate and validate IP addresses."""
        seen = set()
        valid = []
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            try:
                ipaddress.ip_address(ip)
                # Skip private/loopback ranges — not useful for threat intel
                addr = ipaddress.ip_address(ip)
                if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                    valid.append(ip)
            except ValueError:
                pass
        return valid
