"""
pdf_report.py
-------------
Generates a professional phishing analysis PDF report.
Returns the PDF as bytes so Streamlit can offer it as a download.

Usage:
    from pdf_report import generate_report
    pdf_bytes = generate_report(report, enriched)
    st.download_button("Download PDF", pdf_bytes, "phishing_report.pdf", "application/pdf")
"""

import io
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Colour palette (matches the dark UI, rendered on white paper) ─────────────
C_BLACK      = colors.HexColor("#0a0e17")
C_DARK       = colors.HexColor("#1a2235")
C_MID        = colors.HexColor("#2a3a5a")
C_BLUE       = colors.HexColor("#1d4ed8")
C_BLUE_LIGHT = colors.HexColor("#3b82f6")
C_TEXT       = colors.HexColor("#1e293b")
C_MUTED      = colors.HexColor("#64748b")
C_BORDER     = colors.HexColor("#e2e8f0")
C_BG_LIGHT   = colors.HexColor("#f8fafc")
C_BG_MID     = colors.HexColor("#f1f5f9")

C_CRITICAL   = colors.HexColor("#ff3b5c")
C_HIGH       = colors.HexColor("#f97316")
C_MEDIUM     = colors.HexColor("#eab308")
C_LOW        = colors.HexColor("#22c55e")
C_CLEAN      = colors.HexColor("#22c55e")
C_MALICIOUS  = colors.HexColor("#ff3b5c")
C_SUSPICIOUS = colors.HexColor("#f97316")

RISK_COLOUR = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


def _styles():
    return {
        "title": ParagraphStyle("title",
            fontName="Helvetica-Bold", fontSize=22, textColor=C_BLACK,
            spaceAfter=2, leading=26),
        "subtitle": ParagraphStyle("subtitle",
            fontName="Helvetica", fontSize=10, textColor=C_MUTED,
            spaceAfter=6, leading=14),
        "section": ParagraphStyle("section",
            fontName="Helvetica-Bold", fontSize=11, textColor=C_BLUE,
            spaceBefore=14, spaceAfter=4, leading=16,
            borderPad=0),
        "body": ParagraphStyle("body",
            fontName="Helvetica", fontSize=9, textColor=C_TEXT,
            leading=14, spaceAfter=3),
        "mono": ParagraphStyle("mono",
            fontName="Courier", fontSize=8, textColor=C_TEXT,
            leading=12, spaceAfter=2),
        "mono_muted": ParagraphStyle("mono_muted",
            fontName="Courier", fontSize=8, textColor=C_MUTED,
            leading=12, spaceAfter=2),
        "label": ParagraphStyle("label",
            fontName="Helvetica-Bold", fontSize=8, textColor=C_MUTED,
            leading=11, spaceAfter=1, spaceBefore=4),
        "caption": ParagraphStyle("caption",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            leading=11),
        "verdict": ParagraphStyle("verdict",
            fontName="Helvetica-Bold", fontSize=28, textColor=C_BLACK,
            leading=32, spaceAfter=2),
        "risk_score": ParagraphStyle("risk_score",
            fontName="Helvetica", fontSize=10, textColor=C_MUTED,
            leading=14),
        "factor_ok": ParagraphStyle("factor_ok",
            fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#166534"),
            leading=13, spaceAfter=1),
        "factor_warn": ParagraphStyle("factor_warn",
            fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#92400e"),
            leading=13, spaceAfter=1),
        "factor_bad": ParagraphStyle("factor_bad",
            fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#7f1d1d"),
            leading=13, spaceAfter=1),
        "footer": ParagraphStyle("footer",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            alignment=TA_CENTER, leading=11),
    }


def _hr(story, colour=C_BORDER, thickness=0.5):
    story.append(HRFlowable(width="100%", thickness=thickness,
                             color=colour, spaceAfter=6, spaceBefore=4))


def _section(story, title, styles):
    story.append(Spacer(1, 4))
    story.append(Paragraph(title.upper(), styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE_LIGHT,
                             spaceAfter=6, spaceBefore=2))


def _kv_table(data, col_widths, styles):
    """Two-column key/value table."""
    table_data = []
    for k, v in data:
        table_data.append([
            Paragraph(str(k), styles["label"]),
            Paragraph(str(v)[:120], styles["mono"]),
        ])
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW",    (0, 0), (-1, -2), 0.3, C_BORDER),
    ]))
    return t


def generate_report(report, enriched=None) -> bytes:
    """
    Generate a PDF analysis report.

    Args:
        report:   AnalysisReport from PhishingParser.analyse()
        enriched: EnrichedIOCs from ThreatIntel.enrich_iocs() — optional

    Returns:
        PDF as bytes (ready for st.download_button)
    """
    buf    = io.BytesIO()
    styles = _styles()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title="Phishing Email Analysis Report",
        author="Theeadeyemi — Phishing Analyser",
    )

    content_w = PAGE_W - 2 * MARGIN
    story     = []

    # ── HEADER BLOCK ────────────────────────────────────────────────────────
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    header_data = [[
        Paragraph("PHISHING EMAIL ANALYSIS REPORT", styles["title"]),
        Paragraph(f"Generated: {now}", ParagraphStyle("hdr_r",
            fontName="Helvetica", fontSize=8, textColor=C_MUTED,
            alignment=TA_RIGHT, leading=12)),
    ]]
    ht = Table(header_data, colWidths=[content_w * 0.65, content_w * 0.35])
    ht.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "BOTTOM"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))
    story.append(ht)
    story.append(Paragraph("by Theeadeyemi", styles["subtitle"]))
    _hr(story, C_DARK, 1.5)

    # ── VERDICT BLOCK ────────────────────────────────────────────────────────
    _parser_score     = report.risk_score
    _raw_enrichment   = enriched.enrichment_risk_score if enriched else 0
    combined_score    = min(_parser_score + _raw_enrichment, 100)
    # enrichment_added = points that actually contributed after the 100 cap
    _enrichment_added = combined_score - min(_parser_score, 100)
    final_label = _score_label(combined_score)
    v_colour    = RISK_COLOUR.get(final_label, C_MUTED)

    verdict_data = [[
        Paragraph(final_label, ParagraphStyle("v_big",
            fontName="Helvetica-Bold", fontSize=32, textColor=v_colour, leading=36)),
        Table([
            [Paragraph("COMBINED RISK SCORE", styles["label"])],
            [Paragraph(f"{combined_score} / 100", ParagraphStyle("score_num",
                fontName="Helvetica-Bold", fontSize=20, textColor=v_colour, leading=24))],
            [Paragraph(f"Parser: {_parser_score}  |  Enrichment: +{_enrichment_added}  |  Total: {combined_score}/100",
                styles["caption"])],
        ], colWidths=[content_w * 0.4]),
        Table([
            [Paragraph("SUBJECT", styles["label"])],
            [Paragraph(_trunc(report.raw_subject, 80), styles["mono"])],
            [Paragraph("FROM", styles["label"])],
            [Paragraph(_trunc(f"{report.headers.sender_display_name} <{report.headers.sender_email}>", 80), styles["mono"])],
        ], colWidths=[content_w * 0.42]),
    ]]
    vt = Table(verdict_data, colWidths=[
        content_w * 0.15,
        content_w * 0.40,
        content_w * 0.45,
    ])
    vt.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
        ("BACKGROUND",   (0, 0), (-1, -1), C_BG_LIGHT),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEAFTER",    (0, 0), (0, 0), 1,   v_colour),
        ("LINEAFTER",    (1, 0), (1, 0), 0.5, C_BORDER),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(Spacer(1, 6))
    story.append(vt)
    story.append(Spacer(1, 10))

    # ── SUMMARY METRICS ──────────────────────────────────────────────────────
    all_factors = report.risk_factors + (enriched.enrichment_risk_factors if enriched else [])
    metrics = [
        ("URLs Extracted",    len(report.iocs.urls)),
        ("Domains",           len(report.iocs.domains)),
        ("IP Addresses",      len(report.iocs.ips)),
        ("Risk Factors",      len(all_factors)),
        ("MITRE Techniques",  len(report.mitre_techniques)),
        ("Attachments",       len(report.attachments)),
    ]
    m_data = [[
        Table([[Paragraph(str(v), ParagraphStyle("mv",
                    fontName="Helvetica-Bold", fontSize=16, textColor=C_BLUE, leading=20))],
               [Paragraph(k, styles["caption"])]],
              colWidths=[(content_w / 6) - 4])
        for k, v in metrics
    ]]
    mt = Table(m_data, colWidths=[(content_w / 6)] * 6)
    mt.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND",   (0, 0), (-1, -1), C_BG_MID),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEAFTER",    (0, 0), (4, 0),   0.3, C_BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
    ]))
    story.append(mt)
    story.append(Spacer(1, 4))

    # ── SECTION 1: HEADER ANALYSIS ───────────────────────────────────────────
    _section(story, "1. Email Header Analysis", styles)

    h = report.headers
    flags = [
        ("Display name spoofing",  h.display_name_spoofing),
        ("Reply-To mismatch",      h.reply_to_mismatch),
        ("Return-Path mismatch",   h.return_path_mismatch),
        ("Free email provider",    h.free_email_sender),
        ("Suspicious Message-ID",  h.suspicious_message_id),
    ]
    flag_data = []
    for label, triggered in flags:
        icon    = "✗  TRIGGERED" if triggered else "✓  CLEAR"
        style_k = "factor_bad" if triggered else "factor_ok"
        flag_data.append([
            Paragraph(label, styles["body"]),
            Paragraph(icon, styles[style_k]),
        ])
    ft = Table(flag_data, colWidths=[content_w * 0.6, content_w * 0.4])
    ft.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("LINEBELOW",    (0, 0), (-1, -2), 0.3, C_BORDER),
        ("BACKGROUND",   (0, 0), (-1, -1), C_BG_LIGHT),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
    ]))
    story.append(ft)
    story.append(Spacer(1, 6))

    hdr_kv = [
        ("From",             f"{h.sender_display_name} <{h.sender_email}>"),
        ("Reply-To",         h.reply_to or "—"),
        ("Return-Path",      h.return_path or "—"),
        ("Date",             h.date or "—"),
        ("Message-ID",       (h.message_id or "—")[:80]),
        ("X-Mailer",         h.x_mailer or "—"),
        ("X-Originating-IP", h.x_originating_ip or "—"),
    ]
    story.append(_kv_table(hdr_kv, [content_w * 0.28, content_w * 0.72], styles))

    # ── SECTION 2: URLS ──────────────────────────────────────────────────────
    _section(story, "2. URL Analysis", styles)

    if not report.urls:
        story.append(Paragraph("No URLs extracted from this email.", styles["body"]))
    else:
        url_rows = [
            [Paragraph("URL", ParagraphStyle("th", fontName="Helvetica-Bold",
                fontSize=8, textColor=colors.white)),
             Paragraph("Domain", ParagraphStyle("th", fontName="Helvetica-Bold",
                fontSize=8, textColor=colors.white)),
             Paragraph("Flags", ParagraphStyle("th", fontName="Helvetica-Bold",
                fontSize=8, textColor=colors.white))],
        ]
        for u in report.urls:
            flags_list = []
            if u.ip_based:             flags_list.append("IP-BASED")
            if u.url_shortener:        flags_list.append("SHORTENER")
            if u.homograph_risk:       flags_list.append("HOMOGRAPH")
            if u.typosquat_candidates: flags_list.append(f"TYPOSQUAT")
            if u.suspicious_keywords:  flags_list.append("SUSP.KEYWORDS")
            flags_str = ", ".join(flags_list) if flags_list else "—"
            flag_colour = C_MALICIOUS if flags_list else C_CLEAN
            url_rows.append([
                Paragraph(_trunc(u.raw_url, 55), styles["mono"]),
                Paragraph(u.domain or "—", styles["mono"]),
                Paragraph(flags_str, ParagraphStyle("flag_cell",
                    fontName="Helvetica-Bold", fontSize=8,
                    textColor=flag_colour, leading=11)),
            ])
        url_t = Table(url_rows, colWidths=[
            content_w * 0.50,
            content_w * 0.25,
            content_w * 0.25,
        ])
        url_t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("LINEBELOW",    (0, 1), (-1, -1), 0.3, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ]))
        story.append(url_t)

    # ── SECTION 3: CONTENT ANALYSIS ──────────────────────────────────────────
    _section(story, "3. Content Analysis", styles)

    c = report.content
    content_items = []
    if c.urgency_phrases:
        content_items.append(("Urgency language",
            ", ".join(list(dict.fromkeys(c.urgency_phrases))[:5])))
    if c.credential_lures:
        content_items.append(("Credential lures",
            ", ".join(list(dict.fromkeys(c.credential_lures))[:5])))
    if c.threat_phrases:
        content_items.append(("Threat language",
            ", ".join(list(dict.fromkeys(c.threat_phrases))[:5])))
    if c.sender_impersonation:
        content_items.append(("Brand references",
            ", ".join(list(dict.fromkeys(c.sender_impersonation))[:5])))
    if c.html_text_mismatch:
        content_items.append(("HTML mismatch", "Hyperlink display text differs from actual destination"))
    if c.form_actions:
        content_items.append(("Form actions", "; ".join(c.form_actions[:3])))

    if content_items:
        clean_items = [(k, _strip_html(v)) for k, v in content_items]
        story.append(_kv_table(clean_items, [content_w * 0.28, content_w * 0.72], styles))
    else:
        story.append(Paragraph("No notable social engineering patterns detected.", styles["body"]))

    # ── SECTION 4: IOC SUMMARY ───────────────────────────────────────────────
    _section(story, "4. Extracted IOCs", styles)

    ioc_blocks = []
    if report.iocs.urls:
        ioc_blocks.append(("URLs", report.iocs.urls))
    if report.iocs.domains:
        ioc_blocks.append(("Domains", report.iocs.domains))
    if report.iocs.ips:
        ioc_blocks.append(("IP Addresses", report.iocs.ips))
    if report.iocs.email_addresses:
        ioc_blocks.append(("Email Addresses", report.iocs.email_addresses[:8]))

    if not any(v for _, v in ioc_blocks):
        story.append(Paragraph("No IOCs extracted.", styles["body"]))
    else:
        for label, items in ioc_blocks:
            if not items:
                continue
            story.append(Paragraph(label, styles["label"]))
            for item in items:
                story.append(Paragraph(f"  {item}", styles["mono"]))
            story.append(Spacer(1, 4))

    # ── SECTION 5: THREAT INTEL ──────────────────────────────────────────────
    if enriched:
        _section(story, "5. Live Threat Intelligence", styles)

        ti_summary = [
            ("Malicious indicators",  str(enriched.total_malicious)),
            ("Suspicious indicators", str(enriched.total_suspicious)),
            ("Enrichment risk added", f"+{enriched.enrichment_risk_score} points"),
        ]
        story.append(_kv_table(ti_summary, [content_w * 0.35, content_w * 0.65], styles))
        story.append(Spacer(1, 6))

        all_vt = enriched.vt_urls + enriched.vt_domains + enriched.vt_ips
        if all_vt:
            story.append(Paragraph("VirusTotal Results", styles["label"]))
            vt_rows = [[
                Paragraph("Indicator", ParagraphStyle("th2", fontName="Helvetica-Bold",
                    fontSize=8, textColor=colors.white)),
                Paragraph("Type", ParagraphStyle("th2", fontName="Helvetica-Bold",
                    fontSize=8, textColor=colors.white)),
                Paragraph("Verdict", ParagraphStyle("th2", fontName="Helvetica-Bold",
                    fontSize=8, textColor=colors.white)),
                Paragraph("Detections", ParagraphStyle("th2", fontName="Helvetica-Bold",
                    fontSize=8, textColor=colors.white)),
            ]]
            for r in all_vt:
                vc = (C_MALICIOUS if r.verdict == "MALICIOUS"
                      else C_SUSPICIOUS if r.verdict == "SUSPICIOUS"
                      else C_CLEAN)
                vt_rows.append([
                    Paragraph(_trunc(r.indicator, 45), styles["mono"]),
                    Paragraph(r.indicator_type, styles["caption"]),
                    Paragraph(r.verdict, ParagraphStyle("verd",
                        fontName="Helvetica-Bold", fontSize=8,
                        textColor=vc, leading=11)),
                    Paragraph(r.detection_ratio, styles["mono"]),
                ])
            vt_t = Table(vt_rows, colWidths=[
                content_w * 0.46, content_w * 0.14,
                content_w * 0.20, content_w * 0.20,
            ])
            vt_t.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("LEFTPADDING",  (0, 0), (-1, -1), 5),
                ("LINEBELOW",    (0, 1), (-1, -1), 0.3, C_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
                ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ]))
            story.append(vt_t)
            story.append(Spacer(1, 6))

        if enriched.abuse_ips:
            story.append(Paragraph("AbuseIPDB Results", styles["label"]))
            ab_rows = [[
                Paragraph(h, ParagraphStyle("th3", fontName="Helvetica-Bold",
                    fontSize=8, textColor=colors.white))
                for h in ["IP Address", "Abuse Score", "Country", "ISP", "Reports"]
            ]]
            for r in enriched.abuse_ips:
                sc = (C_MALICIOUS if r.abuse_confidence_score >= 75
                      else C_SUSPICIOUS if r.abuse_confidence_score >= 25
                      else C_CLEAN)
                ab_rows.append([
                    Paragraph(r.ip, styles["mono"]),
                    Paragraph(f"{r.abuse_confidence_score}/100",
                        ParagraphStyle("ab_score", fontName="Helvetica-Bold",
                            fontSize=8, textColor=sc, leading=11)),
                    Paragraph(r.country_code or "—", styles["caption"]),
                    Paragraph(_trunc(r.isp or "—", 28), styles["caption"]),
                    Paragraph(str(r.total_reports), styles["caption"]),
                ])
            ab_t = Table(ab_rows, colWidths=[
                content_w*0.22, content_w*0.15, content_w*0.12,
                content_w*0.35, content_w*0.16,
            ])
            ab_t.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("LEFTPADDING",  (0, 0), (-1, -1), 5),
                ("LINEBELOW",    (0, 1), (-1, -1), 0.3, C_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
                ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ]))
            story.append(ab_t)

    # ── SECTION 6: RISK FACTORS ──────────────────────────────────────────────
    sec_num = 6 if enriched else 5
    _section(story, f"{sec_num}. Risk Factors Triggered", styles)

    all_factors = report.risk_factors + (enriched.enrichment_risk_factors if enriched else [])
    if not all_factors:
        story.append(Paragraph("No risk factors triggered.", styles["body"]))
    else:
        for i, factor in enumerate(all_factors, 1):
            fl  = factor.lower()
            sty = ("factor_bad"  if any(w in fl for w in ["malicious","critical","malware","tor"])
                   else "factor_warn" if any(w in fl for w in ["suspicious","shortener","mismatch","typo","spoof","ip-based"])
                   else "body")
            story.append(Paragraph(f"{i:02d}.  {_strip_html(factor)}", styles[sty]))

    # ── SECTION 7: MITRE ATT&CK ──────────────────────────────────────────────
    sec_num += 1
    _section(story, f"{sec_num}. MITRE ATT&CK Mapping", styles)

    if not report.mitre_techniques:
        story.append(Paragraph("No MITRE ATT&CK techniques mapped.", styles["body"]))
    else:
        mit_rows = [[
            Paragraph(h, ParagraphStyle("th4", fontName="Helvetica-Bold",
                fontSize=8, textColor=colors.white))
            for h in ["Technique ID", "Name", "Reference"]
        ]]
        for t in report.mitre_techniques:
            tid = t["id"]
            url = f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
            mit_rows.append([
                Paragraph(tid, ParagraphStyle("tid",
                    fontName="Courier-Bold", fontSize=9,
                    textColor=C_BLUE_LIGHT, leading=12)),
                Paragraph(t["name"], styles["body"]),
                Paragraph(url, ParagraphStyle("url_style",
                    fontName="Courier", fontSize=7,
                    textColor=C_BLUE, leading=10)),
            ])
        mit_t = Table(mit_rows, colWidths=[
            content_w * 0.18, content_w * 0.42, content_w * 0.40,
        ])
        mit_t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("LINEBELOW",    (0, 1), (-1, -1), 0.3, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ]))
        story.append(mit_t)

    # ── ATTACHMENTS ──────────────────────────────────────────────────────────
    if report.attachments:
        sec_num += 1
        _section(story, f"{sec_num}. Attachments", styles)
        for a in report.attachments:
            flag = "SUSPICIOUS" if a.suspicious else "CLEAN"
            fc   = C_MALICIOUS if a.suspicious else C_CLEAN
            story.append(Paragraph(
                f"{a.filename}  |  {a.content_type}  |  {a.size_bytes} bytes  "
                f"— <font color='#{_hex(fc)}'>{flag}</font>"
                + (f": {a.reason}" if a.reason else ""),
                styles["body"],
            ))

    # ── FOOTER ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 12))
    _hr(story, C_BORDER)
    story.append(Paragraph(
        f"Phishing Email Analyser  ·  by Theeadeyemi  ·  "
        f"Generated {now}  ·  For educational and professional use",
        styles["footer"],
    ))

    doc.build(story)
    return buf.getvalue()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _trunc(text: str, n: int) -> str:
    text = _strip_html(str(text))
    return text[:n] + "..." if len(text) > n else text

def _strip_html(text: str) -> str:
    """Remove any HTML/XML tags from a string so ReportLab doesn't choke."""
    import re
    return re.sub(r"<[^>]+>", "", str(text))

def _score_label(score: int) -> str:
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

def _hex(colour) -> str:
    """Convert ReportLab colour to hex string for use in Paragraph markup."""
    r = int(colour.red   * 255)
    g = int(colour.green * 255)
    b = int(colour.blue  * 255)
    return f"{r:02x}{g:02x}{b:02x}"
