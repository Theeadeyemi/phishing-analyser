"""
email_parser.py
---------------
Core IOC extraction engine for the Phishing Email Analyser.
Parses raw .eml content and extracts all indicators of compromise.

Usage:
    from email_parser import PhishingParser
    parser = PhishingParser(raw_eml_text)
    report = parser.analyse()
"""

import email
import re
import ipaddress
import urllib.parse
from email import policy
from email.parser import BytesParser, Parser
from dataclasses import dataclass, field
from typing import Optional
import tldextract


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HeaderAnalysis:
    sender_display_name: str
    sender_email: str
    reply_to: Optional[str]
    return_path: Optional[str]
    subject: str
    date: Optional[str]
    message_id: Optional[str]
    x_mailer: Optional[str]
    x_originating_ip: Optional[str]
    received_chain: list[str]

    # Anomaly flags
    display_name_spoofing: bool = False      # Display name impersonates a brand but email domain differs
    reply_to_mismatch: bool = False          # Reply-To domain differs from From domain
    return_path_mismatch: bool = False       # Return-Path domain differs from From domain
    free_email_sender: bool = False          # Sent from gmail/yahoo/hotmail etc
    suspicious_message_id: bool = False      # Message-ID domain doesn't match From domain
    received_chain_anomaly: bool = False     # Received hops inconsistent with claimed origin


@dataclass
class URLAnalysis:
    raw_url: str
    decoded_url: str
    domain: str
    subdomain: str
    tld: str
    ip_based: bool = False                   # URL uses raw IP instead of domain
    url_shortener: bool = False              # Known URL shortener service
    homograph_risk: bool = False             # Non-ASCII characters in domain (IDN homograph)
    typosquat_candidates: list[str] = field(default_factory=list)  # Potential brand impersonation
    suspicious_keywords: list[str] = field(default_factory=list)   # Keywords in URL path
    encoded_chars: bool = False              # %XX encoding in URL


@dataclass
class ContentAnalysis:
    plain_text: str
    html_body: str
    urgency_phrases: list[str] = field(default_factory=list)
    credential_lures: list[str] = field(default_factory=list)
    threat_phrases: list[str] = field(default_factory=list)
    sender_impersonation: list[str] = field(default_factory=list)
    html_text_mismatch: bool = False         # Link display text differs from actual href
    external_resource_domains: list[str] = field(default_factory=list)
    form_actions: list[str] = field(default_factory=list)


@dataclass
class AttachmentAnalysis:
    filename: str
    content_type: str
    size_bytes: int
    suspicious: bool = False
    reason: str = ""


@dataclass
class IOCBundle:
    """All extracted indicators of compromise in one place."""
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    file_hashes: list[str] = field(default_factory=list)   # If found in body (e.g. threat intel sharing)


@dataclass
class AnalysisReport:
    """Top-level report returned by PhishingParser.analyse()"""
    raw_subject: str
    headers: HeaderAnalysis
    urls: list[URLAnalysis]
    content: ContentAnalysis
    attachments: list[AttachmentAnalysis]
    iocs: IOCBundle
    risk_score: int           # 0–100
    risk_label: str           # LOW / MEDIUM / HIGH / CRITICAL
    risk_factors: list[str]   # Human-readable list of triggered rules
    mitre_techniques: list[dict]  # Mapped ATT&CK techniques


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "msn.com", "icloud.com", "me.com",
    "protonmail.com", "proton.me", "tutanota.com",
    "aol.com", "mail.com", "yandex.com", "gmx.com",
    "zoho.com", "fastmail.com", "hey.com"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "short.link", "is.gd", "buff.ly", "rebrand.ly", "tiny.cc",
    "cutt.ly", "shorturl.at", "snip.ly", "clck.ru"
}

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "barclays", "lloyds", "hsbc", "natwest", "halifax", "santander",
    "virgin", "bt", "sky", "hmrc", "dvla", "nhs", "gov", "royal-mail",
    "royalmail", "dhl", "fedex", "ups", "evri", "parcelforce",
    "ebay", "facebook", "instagram", "whatsapp", "tiktok",
    "dropbox", "docusign", "linkedin", "twitter", "spotify"
]

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\baction required\b",
    r"\baccount.{0,20}suspend", r"\bverify.{0,20}account",
    r"\bunusual.{0,20}activity\b", r"\bwithin\s+\d+\s+hour",
    r"\bwithin\s+\d+\s+day", r"\blast\s+chance\b",
    r"\bexpire[sd]?\b", r"\bdeactivat", r"\blimit(ed)?\s+time",
    r"\bact\s+now\b", r"\bfinal\s+notice\b", r"\bwarning\b",
]

CREDENTIAL_LURE_PATTERNS = [
    r"\bpassword\b", r"\bsign.?in\b", r"\blog.?in\b",
    r"\bverif(y|ication)\b", r"\bconfirm\b", r"\bcredentials?\b",
    r"\bsecurity.{0,20}code\b", r"\bone.time.{0,20}code\b",
    r"\bpayment\s+detail", r"\bcredit\s+card\b", r"\bbank\s+detail",
    r"\bsocial\s+security\b", r"\bnational\s+insurance\b",
    r"\bdate\s+of\s+birth\b", r"\bmother.s\s+maiden\b",
]

THREAT_PATTERNS = [
    r"\baccount.{0,30}terminat", r"\blegal\s+action\b",
    r"\blaw\s+enforcement\b", r"\bpolice\b", r"\bfraud\b",
    r"\bcriminal\b", r"\bproscut", r"\bdebt\s+collect",
    r"\bcollect(ion|or)\b", r"\bunpaid\b", r"\boverdue\b",
    r"\bblocked\b", r"\bfrozen\b", r"\bsuspended\b",
]

SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "verify", "confirm", "account", "secure",
    "update", "billing", "payment", "password", "credential",
    "webscr", "cmd=_login", "authtoken", "oauth", "reset",
]

SUSPICIOUS_ATTACHMENT_TYPES = {
    ".exe": "Executable file — high risk",
    ".bat": "Batch script — high risk",
    ".ps1": "PowerShell script — high risk",
    ".vbs": "VBScript — high risk",
    ".js":  "JavaScript file — high risk",
    ".jar": "Java archive — high risk",
    ".scr": "Screen saver / executable — high risk",
    ".iso": "Disk image — often used to bypass AV",
    ".img": "Disk image — often used to bypass AV",
    ".htm": "HTML file — could be credential harvest page",
    ".html":"HTML file — could be credential harvest page",
    ".doc": "Legacy Word doc — may contain macros",
    ".xls": "Legacy Excel file — may contain macros",
    ".xlsm":"Excel macro-enabled workbook — high risk",
    ".docm":"Word macro-enabled document — high risk",
    ".zip": "Archive — may conceal malicious payload",
    ".rar": "Archive — may conceal malicious payload",
    ".7z":  "Archive — may conceal malicious payload",
    ".lnk": "Windows shortcut — often used in spear phishing",
    ".pdf": "PDF — can contain malicious JavaScript or links",
}

MITRE_MAPPING = {
    "url_shortener":           {"id": "T1027.006", "name": "HTML Smuggling / Obfuscated Files"},
    "credential_lure":         {"id": "T1598.003", "name": "Phishing for Information: Spearphishing via Service"},
    "display_name_spoofing":   {"id": "T1036.005", "name": "Masquerading: Match Legitimate Name or Location"},
    "reply_to_mismatch":       {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
    "urgency":                 {"id": "T1566.002", "name": "Phishing: Spearphishing Link"},
    "suspicious_attachment":   {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
    "html_text_mismatch":      {"id": "T1036",     "name": "Masquerading"},
    "homograph":               {"id": "T1036.007", "name": "Masquerading: Double File Extension / IDN Homograph"},
    "brand_impersonation":     {"id": "T1656",     "name": "Impersonation"},
}


# ---------------------------------------------------------------------------
# Main parser class
# ---------------------------------------------------------------------------

class PhishingParser:
    """
    Parses a raw email (string or bytes) and extracts all phishing IOCs.

    Args:
        raw_email: Raw email content as string or bytes.
                   Can be a full .eml file or pasted email headers + body.
    """

    def __init__(self, raw_email: str | bytes):
        if isinstance(raw_email, bytes):
            self.msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        else:
            self.msg = Parser(policy=policy.default).parsestr(raw_email)

        self._plain_text = ""
        self._html_body = ""
        self._risk_score = 0
        self._risk_factors: list[str] = []
        self._triggered_mitre: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(self) -> AnalysisReport:
        """Run full analysis and return a structured report."""
        headers = self._parse_headers()
        self._extract_body_parts()
        urls = self._parse_urls()
        content = self._analyse_content(urls)
        attachments = self._parse_attachments()
        iocs = self._bundle_iocs(urls, headers)

        self._score_headers(headers)
        self._score_urls(urls)
        self._score_content(content)
        self._score_attachments(attachments)

        risk_label = self._label(self._risk_score)
        mitre = [MITRE_MAPPING[k] for k in self._triggered_mitre if k in MITRE_MAPPING]
        # Deduplicate MITRE entries
        seen_ids = set()
        unique_mitre = []
        for t in mitre:
            if t["id"] not in seen_ids:
                seen_ids.add(t["id"])
                unique_mitre.append(t)

        return AnalysisReport(
            raw_subject=headers.subject,
            headers=headers,
            urls=urls,
            content=content,
            attachments=attachments,
            iocs=iocs,
            risk_score=min(self._risk_score, 100),
            risk_label=risk_label,
            risk_factors=self._risk_factors,
            mitre_techniques=unique_mitre,
        )

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------

    def _parse_headers(self) -> HeaderAnalysis:
        msg = self.msg

        from_header = str(msg.get("From", ""))
        sender_display_name, sender_email = self._parse_address(from_header)

        reply_to_raw = str(msg.get("Reply-To", ""))
        _, reply_to = self._parse_address(reply_to_raw) if reply_to_raw else (None, None)

        return_path_raw = str(msg.get("Return-Path", ""))
        _, return_path = self._parse_address(return_path_raw) if return_path_raw else (None, None)

        received = [str(h) for h in msg.get_all("Received", [])]
        x_orig_ip = str(msg.get("X-Originating-IP", msg.get("X-Sender-IP", "")))

        ha = HeaderAnalysis(
            sender_display_name=sender_display_name,
            sender_email=sender_email,
            reply_to=reply_to,
            return_path=return_path,
            subject=str(msg.get("Subject", "(no subject)")),
            date=str(msg.get("Date", "")),
            message_id=str(msg.get("Message-ID", "")),
            x_mailer=str(msg.get("X-Mailer", msg.get("X-MimeOLE", ""))),
            x_originating_ip=x_orig_ip if x_orig_ip else None,
            received_chain=received,
        )

        sender_domain = self._domain_from_email(sender_email)

        # --- Display name spoofing ---
        # Extract the registered domain root (e.g. "barclays" from "barclays-secure-verify.com")
        # so that typosquat domains like barclays-secure-verify.com don't pass as legitimate
        import tldextract as _tld
        _ext = _tld.extract(sender_email)
        sender_domain_root = _ext.domain.lower() if _ext.domain else ""
        name_lower = sender_display_name.lower()
        for brand in BRAND_KEYWORDS:
            if brand in name_lower:
                # Only skip the flag if the sender domain ROOT exactly matches the brand
                # e.g. brand="barclays", root="barclays" → legitimate
                # e.g. brand="barclays", root="barclays-secure-verify" → spoof
                if sender_domain_root != brand:
                    ha.display_name_spoofing = True
                    break

        # --- Reply-To mismatch ---
        if reply_to:
            rt_domain = self._domain_from_email(reply_to)
            if rt_domain and sender_domain and rt_domain != sender_domain:
                ha.reply_to_mismatch = True

        # --- Return-Path mismatch ---
        if return_path:
            rp_domain = self._domain_from_email(return_path)
            if rp_domain and sender_domain and rp_domain != sender_domain:
                ha.return_path_mismatch = True

        # --- Free email provider ---
        if sender_domain and sender_domain.lower() in FREE_EMAIL_PROVIDERS:
            ha.free_email_sender = True

        # --- Suspicious Message-ID ---
        mid = ha.message_id or ""
        if "@" in mid:
            mid_domain = mid.split("@")[-1].rstrip(">").strip()
            if mid_domain and sender_domain and mid_domain != sender_domain:
                ha.suspicious_message_id = True

        return ha

    # ------------------------------------------------------------------
    # Body extraction
    # ------------------------------------------------------------------

    def _extract_body_parts(self):
        for part in self.msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                continue
            try:
                payload = part.get_content()
            except Exception:
                payload = ""
            if ct == "text/plain" and not self._plain_text:
                self._plain_text = str(payload)
            elif ct == "text/html" and not self._html_body:
                self._html_body = str(payload)

        if not self._plain_text and not self._html_body:
            # Fallback for simple single-part emails
            try:
                self._plain_text = str(self.msg.get_body(preferencelist=("plain",)).get_content())
            except Exception:
                self._plain_text = str(self.msg.get_payload(decode=True) or b"")

    # ------------------------------------------------------------------
    # URL parsing
    # ------------------------------------------------------------------

    def _parse_urls(self) -> list[URLAnalysis]:
        combined = self._plain_text + " " + self._html_body

        url_pattern = re.compile(
            r'https?://[^\s<>"\')\]]+',
            re.IGNORECASE
        )
        raw_urls = list(set(url_pattern.findall(combined)))

        results = []
        for raw in raw_urls:
            raw = raw.rstrip(".,;)")
            decoded = urllib.parse.unquote(raw)
            ext = tldextract.extract(raw)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            subdomain = ext.subdomain

            ua = URLAnalysis(
                raw_url=raw,
                decoded_url=decoded,
                domain=domain,
                subdomain=subdomain,
                tld=ext.suffix,
            )

            # IP-based URL
            try:
                host = urllib.parse.urlparse(raw).hostname or ""
                ipaddress.ip_address(host)
                ua.ip_based = True
            except ValueError:
                pass

            # URL shortener
            if domain.lower() in URL_SHORTENERS:
                ua.url_shortener = True

            # Homograph / IDN
            try:
                raw.encode("ascii")
            except UnicodeEncodeError:
                ua.homograph_risk = True
            if "xn--" in raw.lower():
                ua.homograph_risk = True

            # Suspicious keywords in path
            path = urllib.parse.urlparse(raw).path.lower()
            params = urllib.parse.urlparse(raw).query.lower()
            full_path = path + params
            ua.suspicious_keywords = [k for k in SUSPICIOUS_URL_KEYWORDS if k in full_path]

            # Percent encoding
            if re.search(r"%[0-9A-Fa-f]{2}", raw):
                ua.encoded_chars = True

            # Typosquat / brand impersonation
            domain_lower = domain.lower()
            for brand in BRAND_KEYWORDS:
                if brand in domain_lower and not domain_lower.startswith(brand + "."):
                    ua.typosquat_candidates.append(brand)

            results.append(ua)

        return results

    # ------------------------------------------------------------------
    # Content analysis
    # ------------------------------------------------------------------

    def _analyse_content(self, urls: list[URLAnalysis]) -> ContentAnalysis:
        body = (self._plain_text + " " + self._html_body).lower()

        ca = ContentAnalysis(
            plain_text=self._plain_text,
            html_body=self._html_body,
        )

        # Urgency phrases
        for pat in URGENCY_PATTERNS:
            matches = re.findall(pat, body, re.IGNORECASE)
            if matches:
                ca.urgency_phrases.extend(matches)

        # Credential lures
        for pat in CREDENTIAL_LURE_PATTERNS:
            matches = re.findall(pat, body, re.IGNORECASE)
            if matches:
                ca.credential_lures.extend(matches)

        # Threat phrases
        for pat in THREAT_PATTERNS:
            matches = re.findall(pat, body, re.IGNORECASE)
            if matches:
                ca.threat_phrases.extend(matches)

        # Brand impersonation in body
        for brand in BRAND_KEYWORDS:
            if brand in body:
                ca.sender_impersonation.append(brand)

        # HTML href vs display text mismatch
        href_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
        for href_match in href_pattern.finditer(self._html_body):
            href_url = href_match.group(1)
            display = re.sub(r"<[^>]+>", "", href_match.group(2)).strip()
            if display.startswith("http") and display != href_url:
                ca.html_text_mismatch = True
            elif any(brand in display.lower() for brand in BRAND_KEYWORDS):
                display_domain = tldextract.extract(display).domain if display.startswith("http") else ""
                href_domain = tldextract.extract(href_url).domain
                if display_domain and display_domain != href_domain:
                    ca.html_text_mismatch = True

        # External resources (img src, script src, etc.)
        resource_pattern = re.compile(r'(?:src|href)=["\']https?://([^/"\']+)', re.IGNORECASE)
        ca.external_resource_domains = list(set(resource_pattern.findall(self._html_body)))

        # Form actions
        form_pattern = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)
        ca.form_actions = form_pattern.findall(self._html_body)

        return ca

    # ------------------------------------------------------------------
    # Attachment parsing
    # ------------------------------------------------------------------

    def _parse_attachments(self) -> list[AttachmentAnalysis]:
        attachments = []
        for part in self.msg.walk():
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" not in cd:
                continue
            filename = part.get_filename() or "unnamed"
            ct = part.get_content_type()
            try:
                payload = part.get_payload(decode=True) or b""
                size = len(payload)
            except Exception:
                size = 0

            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            suspicious = ext in SUSPICIOUS_ATTACHMENT_TYPES
            reason = SUSPICIOUS_ATTACHMENT_TYPES.get(ext, "")

            # Double extension check
            if filename.count(".") > 1:
                parts = filename.split(".")
                if len(parts) >= 3:
                    suspicious = True
                    reason = f"Double extension detected: .{parts[-2]}.{parts[-1]}"

            attachments.append(AttachmentAnalysis(
                filename=filename,
                content_type=ct,
                size_bytes=size,
                suspicious=suspicious,
                reason=reason,
            ))
        return attachments

    # ------------------------------------------------------------------
    # IOC bundling
    # ------------------------------------------------------------------

    def _bundle_iocs(self, urls: list[URLAnalysis], headers: HeaderAnalysis) -> IOCBundle:
        iocs = IOCBundle()

        iocs.urls = list({u.raw_url for u in urls})
        iocs.domains = list({u.domain for u in urls if u.domain})

        # IPs from URL list
        iocs.ips = list({u.domain for u in urls if u.ip_based})

        # Originating IP from headers
        if headers.x_originating_ip:
            ip_clean = re.sub(r"[^0-9a-fA-F:.]", "", headers.x_originating_ip)
            if ip_clean:
                iocs.ips.append(ip_clean)

        # Email addresses from body
        body = self._plain_text + self._html_body
        email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
        iocs.email_addresses = list(set(email_pattern.findall(body)))

        # Hash patterns (MD5/SHA1/SHA256 in body — useful for threat intel emails)
        hash_pattern = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
        iocs.file_hashes = list(set(hash_pattern.findall(body)))

        return iocs

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_headers(self, h: HeaderAnalysis):
        if h.display_name_spoofing:
            self._add(20, "Display name impersonates a known brand", "display_name_spoofing")
        if h.reply_to_mismatch:
            self._add(15, "Reply-To domain differs from sender domain", "reply_to_mismatch")
        if h.return_path_mismatch:
            self._add(10, "Return-Path domain differs from sender domain")
        if h.free_email_sender:
            self._add(10, f"Email sent from free provider ({h.sender_email})")
        if h.suspicious_message_id:
            self._add(8, "Message-ID domain does not match sender domain")

    def _score_urls(self, urls: list[URLAnalysis]):
        for u in urls:
            if u.ip_based:
                self._add(20, f"URL uses raw IP address: {u.raw_url}")
            if u.url_shortener:
                self._add(15, f"URL shortener detected: {u.domain}", "url_shortener")
            if u.homograph_risk:
                self._add(20, f"Homograph / IDN spoofing in domain: {u.domain}", "homograph")
            if u.typosquat_candidates:
                brands = ", ".join(u.typosquat_candidates)
                self._add(15, f"Domain may be typosquatting: {u.domain} (targets: {brands})", "brand_impersonation")
            if u.suspicious_keywords:
                self._add(10, f"Suspicious keywords in URL path: {', '.join(u.suspicious_keywords)}")
            if u.encoded_chars:
                self._add(5, f"Percent-encoded characters in URL: {u.raw_url}")

    def _score_content(self, c: ContentAnalysis):
        if c.urgency_phrases:
            unique = list(set(c.urgency_phrases))[:3]
            self._add(12, f"Urgency/pressure language detected: {', '.join(unique)}", "urgency")
        if c.credential_lures:
            unique = list(set(c.credential_lures))[:3]
            self._add(15, f"Credential harvesting language: {', '.join(unique)}", "credential_lure")
        if c.threat_phrases:
            unique = list(set(c.threat_phrases))[:3]
            self._add(10, f"Threat/intimidation language: {', '.join(unique)}")
        if c.html_text_mismatch:
            self._add(18, "Hyperlink display text differs from actual destination", "html_text_mismatch")
        if c.form_actions:
            self._add(15, f"HTML form with action URL detected ({len(c.form_actions)} form(s))")
        if c.sender_impersonation:
            brands = list(set(c.sender_impersonation))[:3]
            self._add(8, f"Email body references known brands: {', '.join(brands)}", "brand_impersonation")

    def _score_attachments(self, attachments: list[AttachmentAnalysis]):
        for a in attachments:
            if a.suspicious:
                self._add(25, f"Suspicious attachment: {a.filename} — {a.reason}", "suspicious_attachment")

    def _add(self, points: int, reason: str, mitre_key: str = None):
        self._risk_score += points
        self._risk_factors.append(reason)
        if mitre_key:
            self._triggered_mitre.add(mitre_key)

    @staticmethod
    def _label(score: int) -> str:
        if score >= 70:
            return "CRITICAL"
        elif score >= 45:
            return "HIGH"
        elif score >= 20:
            return "MEDIUM"
        else:
            return "LOW"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_address(header_val: str) -> tuple[str, str]:
        """
        Extract (display_name, email) from a From/Reply-To header value.
        Handles: Name <addr>,  "Name" <addr>,  plain@addr.com,  <addr>
        """
        header_val = header_val.strip()
        if not header_val:
            return "", ""
        # Format with angle brackets: optional name then <email>
        bracket = re.match(r'(.*?)<([^>]+)>', header_val)
        if bracket:
            name = bracket.group(1).strip().strip('"').strip("'").strip()
            addr = bracket.group(2).strip()
            return name, addr
        # Plain email address with no brackets
        if "@" in header_val:
            return "", header_val.strip()
        # Just a name, no address found
        return header_val, ""

    @staticmethod
    def _domain_from_email(email_addr: str) -> Optional[str]:
        if email_addr and "@" in email_addr:
            return email_addr.split("@")[-1].strip().lower()
        return None
