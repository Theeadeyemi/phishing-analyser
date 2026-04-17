"""
app.py
------
Phishing Email Analyser — Streamlit Dashboard
Run with:  streamlit run app.py
"""

import streamlit as st
from email_parser import PhishingParser
from threat_intel import ThreatIntel
from sample_emails import ALL_SAMPLES
import config

# ─── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing Analyser",
    page_icon="🎣",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap');

html, body, [class*="css"] { font-family: 'Syne', sans-serif; }
.stApp { background-color: #0a0e17; color: #c8d0e0; }

/* Hide Streamlit chrome AND sidebar toggle completely */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="collapsedControl"] { display: none !important; }
[data-testid="stSidebar"] { display: none !important; }

.block-container { padding: 2rem 2.5rem 3rem; max-width: 1200px; }

/* Text area */
.stTextArea textarea {
    background: #0d1220 !important;
    border: 1px solid #1e2740 !important;
    border-radius: 8px !important;
    color: #c8d0e0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
}
.stTextArea textarea:focus {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 0 1px #3b82f6 !important;
}
.stTextArea label { color: #5a6a8a !important; font-size: 13px !important; }

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #1d4ed8, #1e40af);
    color: #fff;
    border: none;
    border-radius: 8px;
    font-family: 'Syne', sans-serif;
    font-weight: 700;
    font-size: 14px;
    padding: 0.6rem 2rem;
    transition: all 0.2s;
    letter-spacing: 0.03em;
    width: 100%;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    transform: translateY(-1px);
    box-shadow: 0 4px 20px rgba(59,130,246,0.3);
}

/* Selectbox */
.stSelectbox > div > div {
    background: #0d1220 !important;
    border: 1px solid #1e2740 !important;
    color: #c8d0e0 !important;
    border-radius: 8px !important;
}
.stSelectbox label { color: #5a6a8a !important; font-size: 12px !important; }

/* Checkbox */
.stCheckbox label { color: #8899bb !important; font-size: 13px !important; }

/* Metric cards */
[data-testid="stMetric"] {
    background: #0d1220;
    border: 1px solid #1e2740;
    border-radius: 12px;
    padding: 1rem 1.2rem;
}
[data-testid="stMetricLabel"] { color: #5a6a8a !important; font-size: 12px !important; }
[data-testid="stMetricValue"] { color: #c8d0e0 !important; font-size: 26px !important; font-weight: 700 !important; }

/* Expander */
details > summary {
    background: #0d1220 !important;
    border: 1px solid #1e2740 !important;
    border-radius: 8px !important;
    color: #8899bb !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
    padding: 10px 14px !important;
    cursor: pointer;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: transparent;
    gap: 4px;
    border-bottom: 1px solid #1e2740;
}
.stTabs [data-baseweb="tab"] {
    background: transparent;
    border-radius: 8px 8px 0 0;
    color: #5a6a8a;
    font-family: 'Syne', sans-serif;
    font-weight: 600;
    font-size: 13px;
    padding: 8px 18px;
    border: none;
}
.stTabs [aria-selected="true"] {
    background: #0d1220 !important;
    color: #3b82f6 !important;
    border-top: 2px solid #3b82f6 !important;
}

/* Divider */
hr { border-color: #1e2740 !important; margin: 1.5rem 0 !important; }

/* Code */
.stCode pre, [data-testid="stCode"] pre {
    background: #0d1220 !important;
    border: 1px solid #1e2740 !important;
    border-radius: 6px !important;
}
code {
    background: #0d1220 !important;
    color: #7dd3fc !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
    padding: 2px 6px !important;
    border-radius: 4px !important;
}

/* Download button — distinct from Analyse */
[data-testid="stDownloadButton"] > button {
    background: #0d1220 !important;
    color: #3b82f6 !important;
    border: 1px solid #1e2740 !important;
    border-radius: 8px;
    font-family: 'Syne', sans-serif;
    font-weight: 600;
    font-size: 13px;
    padding: 0.5rem 1.2rem;
    transition: all 0.2s;
    width: 100%;
}
[data-testid="stDownloadButton"] > button:hover {
    background: #1e2740 !important;
    border-color: #3b82f6 !important;
    transform: translateY(-1px);
}

/* Alert */
[data-testid="stAlert"] {
    background: #0d1220 !important;
    border: 1px solid #1e2740 !important;
    border-radius: 8px !important;
    color: #8899bb !important;
}
</style>
""", unsafe_allow_html=True)


# ─── Helpers ───────────────────────────────────────────────────────────────────
RISK_COLOURS = {
    "CRITICAL": ("#ff3b5c", "#2a0a10"),
    "HIGH":     ("#f97316", "#1f1007"),
    "MEDIUM":   ("#eab308", "#1c1700"),
    "LOW":      ("#22c55e", "#051f0a"),
}

def verdict_badge(verdict):
    cols = {
        "MALICIOUS":  ("#ff3b5c", "#2a0a10"),
        "SUSPICIOUS": ("#eab308", "#1c1700"),
        "CLEAN":      ("#22c55e", "#051f0a"),
        "UNKNOWN":    ("#8899bb", "#111827"),
        "ERROR":      ("#5a6a8a", "#111827"),
    }
    fg, bg = cols.get(verdict, ("#8899bb", "#111827"))
    return (f'<span style="background:{bg};color:{fg};border:1px solid {fg}44;'
            f'border-radius:4px;padding:2px 10px;font-family:JetBrains Mono,monospace;'
            f'font-size:11px;font-weight:700;white-space:nowrap;">{verdict}</span>')

def flag_row(label, triggered):
    icon   = "✗" if triggered else "✓"
    color  = "#ff3b5c" if triggered else "#22c55e"
    weight = "700" if triggered else "400"
    tc     = "#c8d0e0" if triggered else "#5a6a8a"
    return (f'<div style="display:flex;align-items:center;gap:10px;padding:7px 0;'
            f'border-bottom:1px solid #131a2a;">'
            f'<span style="color:{color};font-family:JetBrains Mono,monospace;'
            f'font-size:13px;font-weight:{weight};min-width:16px;">{icon}</span>'
            f'<span style="color:{tc};font-size:13px;font-weight:{weight};">{label}</span></div>')

def ioc_pill(text, bg="#1e2740"):
    safe = str(text).replace("<","&lt;").replace(">","&gt;")
    return (f'<span style="background:{bg};color:#c8d0e0;border-radius:4px;'
            f'padding:3px 9px;font-family:JetBrains Mono,monospace;font-size:11px;'
            f'margin:2px 2px 2px 0;display:inline-block;">{safe}</span>')

def section_header(title, icon=""):
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:10px;margin:1.5rem 0 0.8rem;'
        f'border-left:3px solid #3b82f6;padding-left:12px;">'
        f'<span style="font-family:Syne,sans-serif;font-size:15px;font-weight:700;'
        f'color:#c8d0e0;letter-spacing:0.04em;">{icon} {title}</span></div>',
        unsafe_allow_html=True,
    )

def card(inner_html, border="#1e2740"):
    st.markdown(
        f'<div style="background:#0d1220;border:1px solid {border};'
        f'border-radius:8px;padding:6px 14px;">{inner_html}</div>',
        unsafe_allow_html=True,
    )

def safe(v):
    return str(v or "").replace("<","&lt;").replace(">","&gt;")


# ─── API key status ─────────────────────────────────────────────────────────────
has_vt    = bool(config.VIRUSTOTAL_API_KEY.strip())
has_abuse = bool(config.ABUSEIPDB_API_KEY.strip())


# ─── Header bar ─────────────────────────────────────────────────────────────────
h_left, h_right = st.columns([3, 2])
with h_left:
    st.markdown("""
    <div style="padding:0.4rem 0 1rem;">
        <div style="font-family:Syne,sans-serif;font-size:28px;font-weight:800;
                    color:#ffffff;letter-spacing:-0.03em;line-height:1.1;">
            🎣 Phishing Email Analyser
        </div>
        <div style="font-family:JetBrains Mono,monospace;font-size:12px;color:#5a6a8a;margin-top:6px;">
            IOC extraction · VirusTotal · AbuseIPDB · MITRE ATT&CK
        </div>
    </div>
    """, unsafe_allow_html=True)

with h_right:
    vt_dot    = "🟢" if has_vt    else "🔴"
    abuse_dot = "🟢" if has_abuse else "🔴"
    st.markdown(f"""
    <div style="display:flex;justify-content:flex-end;align-items:center;
                gap:20px;padding:1rem 0;flex-wrap:wrap;">
        <span style="font-family:JetBrains Mono,monospace;font-size:12px;color:#5a6a8a;">
            {vt_dot} VirusTotal
        </span>
        <span style="font-family:JetBrains Mono,monospace;font-size:12px;color:#5a6a8a;">
            {abuse_dot} AbuseIPDB
        </span>
        <span style="font-family:JetBrains Mono,monospace;font-size:11px;color:#2a3a5a;">
            by Theeadeyemi
        </span>
    </div>
    """, unsafe_allow_html=True)

st.markdown('<hr style="border-color:#1e2740;margin:0 0 1.5rem;">', unsafe_allow_html=True)


# ─── Input panel ────────────────────────────────────────────────────────────────
inp_col, opt_col = st.columns([3, 1])

with opt_col:
    st.markdown('<div style="height:2px;"></div>', unsafe_allow_html=True)
    sample_map = {
        "— load a sample —": None,
        "HMRC Tax Refund":    "hmrc_refund",
        "Royal Mail Parcel":  "parcel_delivery",
        "Barclays Security":  "barclays_security",
        "Microsoft 365":      "microsoft_365",
    }
    selected_label  = st.selectbox("Sample phishing emails", list(sample_map.keys()))
    selected_sample = sample_map[selected_label]

    st.markdown('<div style="height:6px;"></div>', unsafe_allow_html=True)
    run_enrichment = st.checkbox(
        "Live threat intel",
        value=has_vt or has_abuse,
        disabled=not (has_vt or has_abuse),
        help="Runs VirusTotal + AbuseIPDB lookups. Uses free API quota (~16s per IOC).",
    )
    if not (has_vt or has_abuse):
        st.markdown(
            '<div style="font-family:JetBrains Mono,monospace;font-size:10px;'
            'color:#5a6a8a;margin-top:2px;">Add keys to config.py</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)
    analyse_btn = st.button("⚡  Analyse Email")

with inp_col:
    default_text = ALL_SAMPLES.get(selected_sample, "") if selected_sample else ""
    email_input  = st.text_area(
        "Paste raw email (.eml headers + body)",
        value=default_text,
        height=230,
        placeholder="Paste the full email here — including From, To, Subject, Received headers and body...",
    )


# ─── Empty state ────────────────────────────────────────────────────────────────
if not analyse_btn:
    st.markdown("""
    <div style="background:#0d1220;border:1px solid #1e2740;border-radius:16px;
                padding:3rem;text-align:center;margin-top:1.5rem;">
        <div style="font-size:44px;margin-bottom:14px;">🎣</div>
        <div style="font-family:Syne,sans-serif;font-size:18px;font-weight:700;
                    color:#c8d0e0;margin-bottom:8px;">Ready to analyse</div>
        <div style="color:#5a6a8a;font-size:13px;font-family:JetBrains Mono,monospace;line-height:2;">
            Load a sample from the dropdown · or paste a raw email · then click Analyse Email<br>
            Parser → IOC extraction → VirusTotal → AbuseIPDB → MITRE ATT&amp;CK mapping
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

if not email_input.strip():
    st.warning("Paste an email or load a sample first.")
    st.stop()


# ─── Parse ──────────────────────────────────────────────────────────────────────
with st.spinner("Parsing email headers and body..."):
    parser = PhishingParser(email_input)
    report = parser.analyse()

# ─── Enrich ─────────────────────────────────────────────────────────────────────
enriched = None
if run_enrichment and (has_vt or has_abuse):
    n = len(report.iocs.urls) + len(report.iocs.domains) + len(report.iocs.ips)
    with st.spinner(f"Threat intel lookups on {n} IOCs — please wait (VT free tier: ~16s per call)..."):
        ti = ThreatIntel(
            vt_api_key    = config.VIRUSTOTAL_API_KEY or None,
            abuseipdb_key = config.ABUSEIPDB_API_KEY  or None,
            rate_limit    = 16.0,
        )
        enriched = ti.enrich_iocs(report.iocs, max_urls=3, max_domains=3, max_ips=5)

# ─── Final score ─────────────────────────────────────────────────────────────────
def score_label(s):
    if s >= 70: return "CRITICAL"
    if s >= 45: return "HIGH"
    if s >= 20: return "MEDIUM"
    return "LOW"

parser_score     = report.risk_score
raw_enrichment   = enriched.enrichment_risk_score if enriched else 0
combined_score   = min(parser_score + raw_enrichment, 100)
# enrichment_added = what actually got added after the 100 cap
enrichment_score = combined_score - min(parser_score, 100)
final_label      = score_label(combined_score)
fg, bg           = RISK_COLOURS.get(final_label, ("#8899bb", "#111827"))
all_factors      = report.risk_factors + (enriched.enrichment_risk_factors if enriched else [])

st.markdown('<hr style="border-color:#1e2740;margin:1.5rem 0;">', unsafe_allow_html=True)

# ─── Computed values ─────────────────────────────────────────────────────────────
subj             = safe(report.raw_subject)[:65] + ("..." if len(report.raw_subject) > 65 else "")
s_name           = safe(report.headers.sender_display_name)
s_addr           = safe(report.headers.sender_email)
bar_p            = min(parser_score, 100)
bar_e            = min(enrichment_score, 100 - bar_p)

# ─── Verdict banner ──────────────────────────────────────────────────────────────
import streamlit.components.v1 as _components

_components.html(
    "<style>@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@800&display=swap');</style>"
    + "<div style='background:" + bg + ";border:1px solid " + fg + "33;border-radius:12px;"
    + "padding:1.4rem 2rem;margin-bottom:0;display:flex;align-items:center;"
    + "justify-content:space-between;flex-wrap:wrap;gap:1rem;'>"
    + "<div>"
    + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:" + fg + "99;"
    + "letter-spacing:0.12em;margin-bottom:4px;'>VERDICT</div>"
    + "<div style='font-family:Syne,sans-serif;font-size:40px;font-weight:800;"
    + "color:" + fg + ";letter-spacing:-0.02em;line-height:1;'>" + final_label + "</div>"
    + "<div style='font-family:JetBrains Mono,monospace;font-size:12px;color:" + fg + "aa;"
    + "margin-top:6px;'>Combined risk score: " + str(combined_score) + "/100</div>"
    + "</div>"
    + "<div style='text-align:right;max-width:420px;'>"
    + "<div style='font-family:JetBrains Mono,monospace;font-size:12px;color:" + fg + "99;"
    + "word-break:break-word;'>" + subj + "</div>"
    + "<div style='font-family:JetBrains Mono,monospace;font-size:11px;color:" + fg + "66;"
    + "margin-top:5px;'>" + s_name + " &lt;" + s_addr + "&gt;</div>"
    + "</div></div>",
    height=130,
    scrolling=False,
)

# ─── Score inline bar (compact, always visible) ──────────────────────────────────
_components.html(
    "<style>@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');</style>"
    + "<div style='display:flex;align-items:center;gap:14px;padding:10px 4px;'>"
    # mini bar
    + "<div style='flex:1;background:#131a2a;border-radius:4px;height:6px;overflow:hidden;display:flex;'>"
    + "<div style='width:" + str(bar_p) + "%;background:" + fg + ";opacity:0.9;'></div>"
    + "<div style='width:" + str(bar_e) + "%;background:" + fg + ";opacity:0.4;'></div>"
    + "</div>"
    # equation
    + "<div style='font-family:JetBrains Mono,monospace;font-size:11px;color:#5a6a8a;white-space:nowrap;flex-shrink:0;'>"
    + "<span style='color:#8899bb;'>" + str(parser_score) + " parser</span>"
    + " <span style='color:#3a4a6a;'>+</span> "
    + "<span style='color:#8899bb;'>+" + str(enrichment_score) + " threat intel</span>"
    + " <span style='color:#3a4a6a;'>=</span> "
    + "<span style='color:" + fg + ";font-weight:700;'>" + str(combined_score) + "/100</span>"
    + "</div>"
    + "</div>",
    height=40,
    scrolling=False,
)

# ─── Collapsible score guide ─────────────────────────────────────────────────────
with st.expander("📊  How is this score calculated?", expanded=False):
    _components.html(
        "<style>@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');</style>"
        + "<div style='padding:4px 0;'>"
        # legend row
        + "<div style='display:flex;gap:24px;flex-wrap:wrap;margin-bottom:14px;'>"
        + "<div style='display:flex;align-items:center;gap:7px;'>"
        + "<div style='width:10px;height:10px;border-radius:2px;background:" + fg + ";opacity:0.9;flex-shrink:0;'></div>"
        + "<span style='font-family:JetBrains Mono,monospace;font-size:11px;color:#8899bb;'>"
        + "Parser score <b style='color:#c8d0e0;'>" + str(parser_score) + "</b>"
        + " &mdash; header + content analysis, no internet needed"
        + "</span></div>"
        + "<div style='display:flex;align-items:center;gap:7px;'>"
        + "<div style='width:10px;height:10px;border-radius:2px;background:" + fg + ";opacity:0.4;flex-shrink:0;'></div>"
        + "<span style='font-family:JetBrains Mono,monospace;font-size:11px;color:#8899bb;'>"
        + "Enrichment <b style='color:#c8d0e0;'>+" + str(enrichment_score) + "</b>"
        + " &mdash; live VirusTotal + AbuseIPDB (capped at 100 total)"
        + "</span></div></div>"
        # threshold cards
        + "<div style='display:grid;grid-template-columns:repeat(4,1fr);gap:8px;'>"
        + "<div style='background:#0d1220;border-radius:6px;padding:8px 10px;border-left:3px solid #ff3b5c;'>"
        + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#ff3b5c;font-weight:700;margin-bottom:3px;'>CRITICAL &nbsp;70-100</div>"
        + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#5a6a8a;line-height:1.5;'>High confidence phishing. Multiple threats confirmed. Do not interact.</div>"
        + "</div>"
        + "<div style='background:#0d1220;border-radius:6px;padding:8px 10px;border-left:3px solid #f97316;'>"
        + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#f97316;font-weight:700;margin-bottom:3px;'>HIGH &nbsp;45-69</div>"
        + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#5a6a8a;line-height:1.5;'>Strong phishing indicators. Manual review before any action.</div>"
        + "</div>"
        + "<div style='background:#0d1220;border-radius:6px;padding:8px 10px;border-left:3px solid #eab308;'>"
        + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#eab308;font-weight:700;margin-bottom:3px;'>MEDIUM &nbsp;20-44</div>"
        + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#5a6a8a;line-height:1.5;'>Suspicious patterns present. Verify the sender carefully.</div>"
        + "</div>"
        + "<div style='background:#0d1220;border-radius:6px;padding:8px 10px;border-left:3px solid #22c55e;'>"
        + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#22c55e;font-weight:700;margin-bottom:3px;'>LOW &nbsp;0-19</div>"
        + "<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#5a6a8a;line-height:1.5;'>Few indicators found. Likely legitimate but always verify.</div>"
        + "</div></div></div>",
        height=165,
        scrolling=False,
    )

# ─── Metrics ─────────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Risk Score",    f"{combined_score}/100",  help="Parser score + enrichment score combined. Max 100.")
c2.metric("URLs Found",    len(report.iocs.urls),    help="Links extracted from email headers and body.")
c3.metric("Domains",       len(report.iocs.domains), help="Unique domains submitted to VirusTotal for reputation check.")
c4.metric("IPs",           len(report.iocs.ips),     help="IP addresses checked against AbuseIPDB.")
c5.metric("Risk Factors",  len(all_factors),         help="Individual detection rules triggered by this email.")
c6.metric("MITRE Tactics", len(report.mitre_techniques), help="ATT&CK techniques mapped from the findings above.")

st.markdown('<div style="height:0.25rem;"></div>', unsafe_allow_html=True)

# ─── PDF Download ────────────────────────────────────────────────────────────────
from pdf_report import generate_report as _gen_pdf
import datetime as _dt

_pdf_col, _spacer = st.columns([1, 4])
with _pdf_col:
    try:
        _pdf_bytes = _gen_pdf(report, enriched)
        _ts        = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        st.download_button(
            label="📄  Download PDF Report",
            data=_pdf_bytes,
            file_name=f"phishing_report_{_ts}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    except Exception as _e:
        st.caption(f"PDF unavailable: {_e}")

st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)


# ─── Tabs ────────────────────────────────────────────────────────────────────────
t_hdr, t_url, t_con, t_ioc, t_intel, t_mit = st.tabs([
    "📋  Headers", "🔗  URLs", "📝  Content",
    "🔍  IOCs",    "🛡  Threat Intel", "⚔️   MITRE",
])


# ════════ HEADERS ════════════════════════════════════════════════════════════════
with t_hdr:
    h    = report.headers
    l, r = st.columns(2)

    with l:
        section_header("Header Anomalies", "🚨")
        card("".join(flag_row(lbl, trig) for lbl, trig in [
            ("Display name spoofing",  h.display_name_spoofing),
            ("Reply-To mismatch",      h.reply_to_mismatch),
            ("Return-Path mismatch",   h.return_path_mismatch),
            ("Free email provider",    h.free_email_sender),
            ("Suspicious Message-ID",  h.suspicious_message_id),
        ]))

    with r:
        section_header("Header Values", "📬")
        fields = [
            ("From",              f"{safe(h.sender_display_name)} &lt;{safe(h.sender_email)}&gt;"),
            ("Reply-To",          safe(h.reply_to) or "—"),
            ("Return-Path",       safe(h.return_path) or "—"),
            ("Subject",           safe(h.subject)),
            ("Date",              safe(h.date) or "—"),
            ("Message-ID",        safe((h.message_id or "")[:60])),
            ("X-Mailer",          safe(h.x_mailer) or "—"),
            ("X-Originating-IP",  safe(h.x_originating_ip) or "—"),
        ]
        rows = "".join(
            f'<div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid #131a2a;">'
            f'<span style="color:#5a6a8a;font-family:JetBrains Mono,monospace;font-size:11px;'
            f'min-width:128px;flex-shrink:0;">{k}</span>'
            f'<span style="color:#c8d0e0;font-family:JetBrains Mono,monospace;font-size:11px;'
            f'word-break:break-all;">{v}</span></div>'
            for k, v in fields
        )
        card(rows)

    if h.received_chain:
        section_header("Received Chain", "📡")
        with st.expander(f"Show {len(h.received_chain)} hops"):
            for i, hop in enumerate(h.received_chain, 1):
                st.code(f"Hop {i}: {hop[:200]}", language=None)


# ════════ URLS ═══════════════════════════════════════════════════════════════════
with t_url:
    if not report.urls:
        st.info("No URLs found in this email.")
    else:
        section_header(f"{len(report.urls)} URL(s) Extracted", "🔗")
        for u in report.urls:
            issues = []
            if u.ip_based:             issues.append("IP-BASED")
            if u.url_shortener:        issues.append("SHORTENER")
            if u.homograph_risk:       issues.append("HOMOGRAPH")
            if u.typosquat_candidates: issues.append(f"TYPOSQUAT: {', '.join(u.typosquat_candidates)}")
            if u.suspicious_keywords:  issues.append(f"KEYWORDS: {', '.join(u.suspicious_keywords[:2])}")
            if u.encoded_chars:        issues.append("ENCODED")

            sev   = ("#ff3b5c" if (u.ip_based or u.homograph_risk or u.typosquat_candidates)
                     else "#eab308" if (u.url_shortener or u.suspicious_keywords)
                     else "#22c55e")
            pills = " ".join(
                f'<span style="background:#1a0a0f;color:#ff3b5c;border:1px solid #ff3b5c33;'
                f'border-radius:4px;padding:1px 8px;font-size:10px;font-family:JetBrains Mono,monospace;">{iss}</span>'
                for iss in issues
            )
            st.markdown(
                f'<div style="background:#0d1220;border:1px solid {sev}33;border-left:3px solid {sev};'
                f'border-radius:8px;padding:10px 14px;margin-bottom:8px;">'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:12px;color:#7dd3fc;'
                f'word-break:break-all;margin-bottom:6px;">{safe(u.raw_url)}</div>'
                f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
                f'<span style="color:#5a6a8a;font-size:11px;font-family:JetBrains Mono,monospace;">'
                f'Domain: <span style="color:#c8d0e0;">{u.domain}</span></span>'
                f'{pills}</div></div>',
                unsafe_allow_html=True,
            )


# ════════ CONTENT ════════════════════════════════════════════════════════════════
with t_con:
    c   = report.content
    ca, cb = st.columns(2)

    with ca:
        section_header("Social Engineering Patterns", "🧠")

        def phrase_block(title, phrases, pill_bg):
            if not phrases:
                return ""
            unique = list(dict.fromkeys(str(p) for p in phrases))[:6]
            pills  = " ".join(ioc_pill(p, pill_bg) for p in unique)
            return (f'<div style="margin-bottom:14px;">'
                    f'<div style="font-size:10px;color:#5a6a8a;font-family:JetBrains Mono,monospace;'
                    f'margin-bottom:6px;letter-spacing:0.07em;">{title}</div>'
                    f'<div>{pills}</div></div>')

        body_html = (
            phrase_block("URGENCY LANGUAGE",  c.urgency_phrases,      "#2a1a00")
          + phrase_block("CREDENTIAL LURES",  c.credential_lures,     "#1a0a1f")
          + phrase_block("THREAT LANGUAGE",   c.threat_phrases,       "#1a0a0f")
          + phrase_block("BRAND REFERENCES",  c.sender_impersonation, "#001a0f")
        )
        if not body_html:
            body_html = '<span style="color:#5a6a8a;font-size:13px;">No patterns detected.</span>'
        card(f'<div style="padding:6px 0;">{body_html}</div>')

    with cb:
        section_header("HTML Structure", "🏗")
        card("".join(flag_row(lbl, trig) for lbl, trig in [
            ("HTML href/text mismatch",                          c.html_text_mismatch),
            (f"Form actions ({len(c.form_actions)})",            bool(c.form_actions)),
            (f"External resources ({len(c.external_resource_domains)})", bool(c.external_resource_domains)),
        ]))
        if c.form_actions:
            section_header("Form Action URLs", "📤")
            for fa in c.form_actions:
                st.code(fa, language=None)

    if report.attachments:
        section_header(f"Attachments ({len(report.attachments)})", "📎")
        for att in report.attachments:
            col = "#ff3b5c" if att.suspicious else "#22c55e"
            lbl = f"⚠ {att.reason}" if att.suspicious else "✓ No known risk"
            st.markdown(
                f'<div style="background:#0d1220;border:1px solid {col}33;border-left:3px solid {col};'
                f'border-radius:8px;padding:10px 14px;margin-bottom:8px;">'
                f'<span style="color:#c8d0e0;font-family:JetBrains Mono,monospace;font-size:13px;">'
                f'{safe(att.filename)}</span>'
                f'<span style="color:#5a6a8a;font-size:11px;font-family:JetBrains Mono,monospace;margin-left:12px;">'
                f'{att.content_type} · {att.size_bytes} bytes</span>'
                f'<div style="color:{col};font-size:12px;font-family:JetBrains Mono,monospace;margin-top:4px;">'
                f'{lbl}</div></div>',
                unsafe_allow_html=True,
            )


# ════════ IOCs ═══════════════════════════════════════════════════════════════════
with t_ioc:
    iocs = report.iocs
    section_header("Extracted Indicators of Compromise", "🔍")

    ic1, ic2 = st.columns(2)

    def mono_label(text):
        return (f'<div style="color:#5a6a8a;font-size:10px;font-family:JetBrains Mono,monospace;'
                f'letter-spacing:0.07em;margin:14px 0 6px;">{text}</div>')

    with ic1:
        st.markdown(mono_label("URLS"), unsafe_allow_html=True)
        if iocs.urls:
            for url in iocs.urls:
                st.code(url, language=None)
        else:
            st.caption("None found")
        st.markdown(mono_label("IP ADDRESSES"), unsafe_allow_html=True)
        if iocs.ips:
            for ip in iocs.ips:
                st.code(ip, language=None)
        else:
            st.caption("None found")

    with ic2:
        st.markdown(mono_label("DOMAINS"), unsafe_allow_html=True)
        if iocs.domains:
            for d in iocs.domains:
                st.code(d, language=None)
        else:
            st.caption("None found")
        st.markdown(mono_label("EMAIL ADDRESSES IN BODY"), unsafe_allow_html=True)
        if iocs.email_addresses:
            for e in iocs.email_addresses[:10]:
                st.code(e, language=None)
        else:
            st.caption("None found")

    section_header("All Risk Factors", "⚠️")
    if not all_factors:
        st.caption("No risk factors triggered.")
    for i, factor in enumerate(all_factors, 1):
        fl = str(factor).lower()
        fc = ("#ff3b5c" if any(w in fl for w in ["malicious","critical","malware","tor"])
              else "#eab308" if any(w in fl for w in ["suspicious","shortener","mismatch","typo","spoof"])
              else "#8899bb")
        st.markdown(
            f'<div style="display:flex;gap:12px;align-items:flex-start;padding:7px 0;'
            f'border-bottom:1px solid #131a2a;">'
            f'<span style="color:#2a3a5a;font-family:JetBrains Mono,monospace;font-size:11px;'
            f'min-width:26px;">{i:02d}</span>'
            f'<span style="color:{fc};font-size:13px;line-height:1.5;">{safe(factor)}</span></div>',
            unsafe_allow_html=True,
        )


# ════════ THREAT INTEL ═══════════════════════════════════════════════════════════
with t_intel:
    if not enriched:
        if not (has_vt or has_abuse):
            st.markdown("""
            <div style="background:#0d1220;border:1px solid #1e2740;border-radius:12px;
                        padding:2.5rem;text-align:center;">
                <div style="font-size:32px;margin-bottom:12px;">🔑</div>
                <div style="color:#c8d0e0;font-size:15px;font-weight:600;margin-bottom:8px;">
                    API keys not configured</div>
                <div style="color:#5a6a8a;font-size:13px;font-family:JetBrains Mono,monospace;line-height:1.8;">
                    Add your free keys to config.py<br>
                    VirusTotal → virustotal.com &nbsp;·&nbsp; AbuseIPDB → abuseipdb.com
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("Enable 'Live threat intel' and click Analyse again to run enrichment.")
    else:
        e1, e2, e3 = st.columns(3)
        e1.metric("Malicious IOCs",   enriched.total_malicious,
                  help="IOCs flagged MALICIOUS by VirusTotal or AbuseIPDB.")
        e2.metric("Suspicious IOCs",  enriched.total_suspicious,
                  help="IOCs flagged SUSPICIOUS but not confirmed malicious.")
        e3.metric("Points Added to Score", f"+{enrichment_score}",
                  help=f"Raw enrichment was +{enriched.enrichment_risk_score}, but score is capped at 100. Only +{enrichment_score} points were added.")
        st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)

        def vt_card(r):
            fg2, bg2 = {"MALICIOUS": ("#ff3b5c","#1a0508"),
                        "SUSPICIOUS":("#eab308","#1a1500"),
                        "CLEAN":     ("#22c55e","#051a0a")}.get(r.verdict, ("#5a6a8a","#0d1220"))
            t_str = ", ".join(r.threat_names[:3]) if r.threat_names else "—"
            c_str = ", ".join(r.categories[:3])   if r.categories   else "—"
            link  = (f'<a href="{r.vt_link}" target="_blank" style="color:#3b82f6;font-size:11px;'
                     f'font-family:JetBrains Mono,monospace;text-decoration:none;">View on VirusTotal →</a>'
                     ) if r.vt_link else ""
            inner = (f'<div style="color:#ff6b6b;font-size:12px;">Error: {safe(r.error)}</div>'
                     if r.error else
                     f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;'
                     f'font-family:JetBrains Mono,monospace;color:#5a6a8a;">'
                     f'<div>Detections: <span style="color:{fg2};font-weight:700;">{r.detection_ratio}</span></div>'
                     f'<div>Last scan: <span style="color:#8899bb;">{r.last_analysis_date or "—"}</span></div>'
                     f'<div style="grid-column:1/-1;">Threats: <span style="color:#c8d0e0;">{t_str}</span></div>'
                     f'<div style="grid-column:1/-1;">Categories: <span style="color:#c8d0e0;">{c_str}</span></div>'
                     f'</div>{link}')
            st.markdown(
                f'<div style="background:{bg2};border:1px solid {fg2}33;border-left:3px solid {fg2};'
                f'border-radius:8px;padding:12px 16px;margin-bottom:10px;">'
                f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:8px;">'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:12px;color:#7dd3fc;'
                f'word-break:break-all;">{safe(r.indicator[:70])}</span>'
                f'{verdict_badge(r.verdict)}</div>{inner}</div>',
                unsafe_allow_html=True,
            )

        def abuse_card(r):
            fg2, bg2 = {"MALICIOUS": ("#ff3b5c","#1a0508"),
                        "SUSPICIOUS":("#eab308","#1a1500"),
                        "CLEAN":     ("#22c55e","#051a0a")}.get(r.verdict, ("#5a6a8a","#0d1220"))
            tor_row = ('<div style="grid-column:1/-1;color:#ff3b5c;font-weight:700;margin-top:4px;">⚠ Tor Exit Node</div>'
                       if r.is_tor else "")
            inner = (f'<div style="color:#ff6b6b;font-size:12px;">Error: {safe(r.error)}</div>'
                     if r.error else
                     f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;'
                     f'font-family:JetBrains Mono,monospace;color:#5a6a8a;">'
                     f'<div>Abuse score: <span style="color:{fg2};font-weight:700;font-size:15px;">'
                     f'{r.abuse_confidence_score}/100</span></div>'
                     f'<div>Reports: <span style="color:#c8d0e0;">{r.total_reports}</span></div>'
                     f'<div>Country: <span style="color:#c8d0e0;">{r.country_code or "—"}</span></div>'
                     f'<div>ISP: <span style="color:#c8d0e0;">{safe(r.isp or "—")[:30]}</span></div>'
                     f'<div style="grid-column:1/-1;">Usage: <span style="color:#c8d0e0;">{r.usage_type or "—"}</span></div>'
                     f'{tor_row}</div>')
            st.markdown(
                f'<div style="background:{bg2};border:1px solid {fg2}33;border-left:3px solid {fg2};'
                f'border-radius:8px;padding:12px 16px;margin-bottom:10px;">'
                f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:13px;color:#7dd3fc;">{r.ip}</span>'
                f'{verdict_badge(r.verdict)}</div>{inner}</div>',
                unsafe_allow_html=True,
            )

        vt_all = enriched.vt_urls + enriched.vt_domains + enriched.vt_ips
        if vt_all:
            section_header("VirusTotal Results", "🦠")
            for r in vt_all:
                vt_card(r)
        if enriched.abuse_ips:
            section_header("AbuseIPDB Results", "🌐")
            for r in enriched.abuse_ips:
                abuse_card(r)


# ════════ MITRE ══════════════════════════════════════════════════════════════════
with t_mit:
    if not report.mitre_techniques:
        st.info("No MITRE ATT&CK techniques mapped for this email.")
    else:
        section_header(f"{len(report.mitre_techniques)} Technique(s) Mapped", "⚔️")
        for t in report.mitre_techniques:
            tid  = t["id"]
            name = t["name"]
            url  = f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
            st.markdown(
                f'<div style="background:#0d1220;border:1px solid #1e2740;border-left:3px solid #3b82f6;'
                f'border-radius:8px;padding:14px 18px;margin-bottom:10px;'
                f'display:flex;align-items:center;gap:16px;">'
                f'<div style="background:#1e2740;border-radius:6px;padding:6px 14px;'
                f'font-family:JetBrains Mono,monospace;font-size:13px;color:#3b82f6;'
                f'font-weight:700;white-space:nowrap;">{tid}</div>'
                f'<div><div style="color:#c8d0e0;font-size:14px;font-weight:600;margin-bottom:4px;">{name}</div>'
                f'<a href="{url}" target="_blank" style="color:#3b82f6;font-size:11px;'
                f'font-family:JetBrains Mono,monospace;text-decoration:none;">'
                f'View on MITRE ATT&amp;CK →</a></div></div>',
                unsafe_allow_html=True,
            )
