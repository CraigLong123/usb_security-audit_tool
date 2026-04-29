"""
PDF Report Generation Module
 
Generates a professional, structured PDF security assessment report
from the aggregated risk data produced by the risk calculator.
 
The report is structured to serve two audiences simultaneously:
    Technical staff: Detailed findings, scores, and remediation steps
    Management:      Executive summary with plain-language risk verdict
 
Report structure:
    1. Cover page         - Tool name, date, overall risk verdict
    2. Executive Summary  - Headline finding, module overview table
    3. Firewall Section   - Findings, explanations, recommendations
    4. Password Section   - Findings, explanations, recommendations
    5. Port Section       - Findings, explanations, recommendations
    6. System Section     - Findings, explanations, recommendations
    7. Recommendations    - Prioritised remediation list
    8. Framework Reference- Standards referenced in this assessment
 
Academic context:
    Transparent, educational reporting is a core contribution of this
    research. Each finding includes an explanation of the security
    implication, fulfilling the accessibility objective identified in
    the research introduction. This approach is consistent with the
    NIST SP 800-30 guidance that risk communication should be
    understandable to the intended audience.
 
Dependencies:
    reportlab >= 3.6.0  (pip install reportlab)
"""
 
import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
 
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
 
 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
 
 
# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
 
COLOUR_CRITICAL = colors.HexColor('#C0392B')
COLOUR_HIGH     = colors.HexColor('#E67E22')
COLOUR_MEDIUM   = colors.HexColor('#F39C12')
COLOUR_LOW      = colors.HexColor('#27AE60')
COLOUR_INFO     = colors.HexColor('#2980B9')
COLOUR_DARK     = colors.HexColor('#2C3E50')
COLOUR_LIGHT    = colors.HexColor('#ECF0F1')
COLOUR_WHITE    = colors.white
COLOUR_MID      = colors.HexColor('#BDC3C7')
 
 
def _risk_colour(risk_label: str):
    return {
        'Critical': COLOUR_CRITICAL,
        'High':     COLOUR_HIGH,
        'Medium':   COLOUR_MEDIUM,
        'Low':      COLOUR_LOW,
    }.get(risk_label, COLOUR_INFO)
 
 
def _severity_colour(severity: str):
    return {
        'CRITICAL': COLOUR_CRITICAL,
        'HIGH':     COLOUR_HIGH,
        'MEDIUM':   COLOUR_MEDIUM,
        'LOW':      COLOUR_LOW,
        'INFO':     COLOUR_INFO,
    }.get(severity, COLOUR_INFO)
 
 
# ---------------------------------------------------------------------------
# Educational explanations
# Fulfils dissertation commitment to "educational context explaining
# security implications" for each finding area.
# ---------------------------------------------------------------------------
 
FINDING_EXPLANATIONS = {
    'firewall': (
        "The Windows Firewall acts as a barrier between your computer and the "
        "network, controlling which connections are permitted. A disabled or "
        "misconfigured firewall exposes services running on your system to "
        "direct network attack. The Verizon Data Breach Investigations Report "
        "(2023) consistently identifies network-level attacks as a leading "
        "breach vector, making firewall configuration a priority control under "
        "CIS Controls v8 (Control 4)."
    ),
    'password': (
        "Password policies define the rules users must follow when creating and "
        "maintaining passwords. Weak policies enable credential-based attacks "
        "including brute force (automated password guessing) and credential "
        "stuffing (replaying leaked passwords from other breaches). NIST SP "
        "800-63B recommends a minimum of 8 characters, while CIS Benchmarks "
        "recommend 14+ characters. Account lockout policies limit failed login "
        "attempts, preventing automated guessing attacks (CIS Control 5)."
    ),
    'port': (
        "Every open network port is a potential entry point for attackers. "
        "Services listening on ports may contain exploitable vulnerabilities. "
        "The principle of least exposure dictates only necessary services should "
        "be accessible. Standard Windows services such as RPC (135), NetBIOS "
        "(139), and SMB (445) are required for normal operation but must be "
        "protected by an active firewall. NIST SP 800-115 recommends local port "
        "enumeration as part of any host security assessment (CIS Control 12)."
    ),
    'system': (
        "The system patch status directly determines exposure to known "
        "vulnerabilities. Unpatched systems remain vulnerable to exploits for "
        "which fixes are publicly available. End-of-life operating systems no "
        "longer receive security updates, leaving all subsequently discovered "
        "vulnerabilities permanently unpatched. CIS Controls v8 identifies patch "
        "management as a foundational security control."
    ),
}
 
 
FRAMEWORK_REFERENCES = [
    ('NIST SP 800-63B',           'Password Policy',  'Minimum 8 character passwords; check against breached password lists'),
    ('NIST SP 800-115',           'Port Assessment',  'Local port enumeration for host security assessment'),
    ('NIST SP 800-30 Rev 1',      'Risk Scoring',     'Weighted risk assessment considering likelihood and impact'),
    ('CIS Controls v8 — Ctrl 4',  'Firewall',         'Secure configuration; firewall enabled on all profiles'),
    ('CIS Controls v8 — Ctrl 5',  'Password Policy',  '14+ character minimum; lockout after 5 attempts'),
    ('CIS Controls v8 — Ctrl 12', 'Port Assessment',  'Disable unnecessary services; network infrastructure management'),
    ('Microsoft Security Baseline','Password Policy',  'Enable complexity; 14 character minimum; lockout threshold of 10'),
    ('OWASP Testing Guide v4',    'Port Assessment',  'Network port and service identification as part of security testing'),
]
 
 
# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
 
def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle('RTitle', parent=base['Title'],
            fontSize=26, textColor=COLOUR_WHITE, alignment=TA_CENTER,
            fontName='Helvetica-Bold', spaceAfter=4),
        'subtitle': ParagraphStyle('RSub', parent=base['Normal'],
            fontSize=12, textColor=COLOUR_WHITE, alignment=TA_CENTER,
            fontName='Helvetica', spaceAfter=4),
        'h1': ParagraphStyle('RH1', parent=base['Heading1'],
            fontSize=15, textColor=COLOUR_DARK, spaceBefore=12,
            spaceAfter=4, fontName='Helvetica-Bold'),
        'h2': ParagraphStyle('RH2', parent=base['Heading2'],
            fontSize=12, textColor=COLOUR_DARK, spaceBefore=8,
            spaceAfter=3, fontName='Helvetica-Bold'),
        'body': ParagraphStyle('RBody', parent=base['Normal'],
            fontSize=10, textColor=COLOUR_DARK, spaceAfter=5,
            leading=14, fontName='Helvetica'),
        'body_bold': ParagraphStyle('RBodyB', parent=base['Normal'],
            fontSize=10, textColor=COLOUR_DARK, fontName='Helvetica-Bold',
            spaceAfter=3),
        'small': ParagraphStyle('RSmall', parent=base['Normal'],
            fontSize=8, textColor=colors.grey, fontName='Helvetica'),
        'explanation': ParagraphStyle('RExp', parent=base['Normal'],
            fontSize=9, textColor=colors.HexColor('#555555'),
            fontName='Helvetica-Oblique', leftIndent=8, rightIndent=8,
            spaceAfter=8, leading=13),
        'finding': ParagraphStyle('RFind', parent=base['Normal'],
            fontSize=9, textColor=COLOUR_DARK, fontName='Helvetica',
            leftIndent=6, spaceAfter=3, leading=13),
        'recommendation': ParagraphStyle('RRec', parent=base['Normal'],
            fontSize=9, textColor=COLOUR_DARK, fontName='Helvetica',
            leftIndent=8, spaceAfter=4, leading=13),
        'th': ParagraphStyle('RTH', parent=base['Normal'],
            fontSize=9, textColor=COLOUR_WHITE, fontName='Helvetica-Bold',
            alignment=TA_CENTER),
        'td': ParagraphStyle('RTD', parent=base['Normal'],
            fontSize=9, textColor=COLOUR_DARK, fontName='Helvetica'),
        'td_small': ParagraphStyle('RTDSm', parent=base['Normal'],
            fontSize=8, textColor=COLOUR_DARK, fontName='Helvetica'),
    }
 
 
# ---------------------------------------------------------------------------
# Page decorators
# ---------------------------------------------------------------------------
 
def _on_cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(COLOUR_DARK)
    canvas.rect(0, A4[1] - 7.5 * cm, A4[0], 7.5 * cm, fill=True, stroke=False)
    canvas.setFillColor(COLOUR_INFO)
    canvas.rect(0, A4[1] - 7.5 * cm - 3, A4[0], 3, fill=True, stroke=False)
    canvas.restoreState()
 
 
def _on_page(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(COLOUR_DARK)
    canvas.rect(0, h - 1.1 * cm, w, 1.1 * cm, fill=True, stroke=False)
    canvas.setFont('Helvetica-Bold', 8)
    canvas.setFillColor(COLOUR_WHITE)
    canvas.drawString(1 * cm, h - 0.78 * cm, "Windows Security Audit Report")
    canvas.drawRightString(w - 1 * cm, h - 0.78 * cm,
                           datetime.now().strftime('%Y-%m-%d'))
    canvas.setStrokeColor(COLOUR_MID)
    canvas.line(1 * cm, 1.1 * cm, w - 1 * cm, 1.1 * cm)
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(1 * cm, 0.65 * cm, "Confidential — Security Assessment Report")
    canvas.drawRightString(w - 1 * cm, 0.65 * cm, f"Page {doc.page}")
    canvas.restoreState()
 
 
# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------
 
def _cover(styles, risk_report):
    summary       = risk_report.get('summary', {})
    overall_risk  = summary.get('overall_risk', 'Unknown')
    overall_score = summary.get('overall_score', 0)
    ts            = summary.get('assessment_timestamp', '')
    try:
        date_str = datetime.fromisoformat(ts).strftime('%d %B %Y  %H:%M')
    except Exception:
        date_str = datetime.now().strftime('%d %B %Y  %H:%M')
 
    els = [Spacer(1, 6 * cm)]
    els.append(Paragraph("Windows Security Audit Report", styles['title']))
    els.append(Spacer(1, 0.3 * cm))
    els.append(Paragraph(f"Assessment performed: {date_str}", styles['subtitle']))
    els.append(Spacer(1, 1.8 * cm))
 
    rc = _risk_colour(overall_risk)
    badge = Table([[
        Paragraph(f"<b>Overall Risk: {overall_risk}</b>",
                  ParagraphStyle('cb', fontSize=16, textColor=COLOUR_WHITE,
                                 fontName='Helvetica-Bold', alignment=TA_CENTER)),
        Paragraph(f"<b>{overall_score} / 10</b>",
                  ParagraphStyle('cs', fontSize=16, textColor=COLOUR_WHITE,
                                 fontName='Helvetica-Bold', alignment=TA_CENTER)),
    ]], colWidths=[10 * cm, 5 * cm])
    badge.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (0, 0), rc),
        ('BACKGROUND',    (1, 0), (1, 0), COLOUR_DARK),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    els.append(badge)
    els.append(Spacer(1, 1.2 * cm))
 
    c  = summary.get('critical_findings', 0)
    hi = summary.get('high_findings', 0)
    me = summary.get('medium_findings', 0)
    mo = summary.get('modules_assessed', 0)
 
    stats = Table(
        [['Modules Run', 'Critical', 'High', 'Medium'],
         [str(mo), str(c), str(hi), str(me)]],
        colWidths=[3.75 * cm] * 4
    )
    stats.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), COLOUR_DARK),
        ('TEXTCOLOR',     (0, 0), (-1, 0), COLOUR_WHITE),
        ('BACKGROUND',    (0, 1), (-1, 1), COLOUR_LIGHT),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME',      (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0), 8),
        ('FONTSIZE',      (0, 1), (-1, 1), 13),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('GRID',          (0, 0), (-1, -1), 0.5, COLOUR_MID),
    ]))
    els.append(stats)
    els.append(Spacer(1, 0.8 * cm))
    els.append(Paragraph(summary.get('headline', ''), styles['body']))
    els.append(Spacer(1, 0.4 * cm))
    els.append(HRFlowable(width="100%", thickness=0.5, color=COLOUR_MID))
    els.append(Spacer(1, 0.2 * cm))
    els.append(Paragraph(
        "This report was generated by the Windows Security Audit Tool. "
        "Findings should be reviewed before implementing remediation. "
        "Frameworks referenced: NIST SP 800-63B, CIS Controls v8, "
        "Microsoft Security Baseline, OWASP Testing Guide v4.",
        styles['small']
    ))
    els.append(PageBreak())
    return els
 
 
def _executive_summary(styles, risk_report):
    summary   = risk_report.get('summary', {})
    breakdown = summary.get('module_breakdown', {})
 
    els = [Paragraph("Executive Summary", styles['h1']),
           HRFlowable(width="100%", thickness=1, color=COLOUR_DARK),
           Spacer(1, 0.3 * cm),
           Paragraph(summary.get('headline', ''), styles['body']),
           Spacer(1, 0.3 * cm),
           Paragraph("Module Risk Breakdown", styles['h2'])]
 
    hdr = [['Assessment Area', 'Weight', 'Score', 'Risk Level', 'Data']]
    rows = []
    for mod, info in breakdown.items():
        rl = info.get('risk_label', 'Unknown')
        rows.append([
            Paragraph(info.get('label', mod), styles['td']),
            Paragraph(info.get('weight_pct', ''), styles['td']),
            Paragraph(f"{info.get('raw_score', 0)}/10", styles['td']),
            Paragraph(f"<b>{rl}</b>", ParagraphStyle(
                'rlcell', fontSize=9, fontName='Helvetica-Bold',
                textColor=_risk_colour(rl))),
            Paragraph('Yes' if info.get('data_available') else 'No', styles['td']),
        ])
 
    t = Table(
        [[Paragraph(h, styles['th']) for h in hdr[0]]] + rows,
        colWidths=[6 * cm, 2 * cm, 2.2 * cm, 3 * cm, 2.3 * cm]
    )
    t.setStyle(TableStyle([
        ('BACKGROUND',     (0, 0), (-1, 0), COLOUR_DARK),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOUR_WHITE, COLOUR_LIGHT]),
        ('ALIGN',          (0, 0), (-1, -1), 'CENTER'),
        ('ALIGN',          (0, 1), (0, -1), 'LEFT'),
        ('VALIGN',         (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID',           (0, 0), (-1, -1), 0.5, COLOUR_MID),
        ('TOPPADDING',     (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), 5),
        ('LEFTPADDING',    (0, 0), (-1, -1), 5),
    ]))
    els.append(t)
    els.append(Spacer(1, 0.4 * cm))
 
    overall_risk  = summary.get('overall_risk', 'Unknown')
    overall_score = summary.get('overall_score', 0)
    els.append(Paragraph(
        f"<b>Overall Risk Score: {overall_score}/10 — {overall_risk}</b>",
        ParagraphStyle('ovr', fontSize=12, fontName='Helvetica-Bold',
                       textColor=_risk_colour(overall_risk), spaceAfter=6)
    ))
    els.append(PageBreak())
    return els
 
 
def _module_section(styles, module_name, module_label,
                    module_score_data, all_findings, all_recs):
    raw_score = module_score_data.get('raw_score', 0)
    label = 'Low'
    for (lo, hi), lbl in [((8, 11), 'Critical'), ((6, 8), 'High'),
                           ((3, 6), 'Medium'),   ((0, 3), 'Low')]:
        if lo <= raw_score < hi:
            label = lbl
            break
 
    rc = _risk_colour(label)
 
    head = Table([[
        Paragraph(f"<b>{module_label}</b>",
                  ParagraphStyle('sh', fontSize=13, textColor=COLOUR_WHITE,
                                 fontName='Helvetica-Bold', alignment=TA_LEFT)),
        Paragraph(f"<b>{label} — {raw_score}/10</b>",
                  ParagraphStyle('sb', fontSize=11, textColor=COLOUR_WHITE,
                                 fontName='Helvetica-Bold', alignment=TA_RIGHT)),
    ]], colWidths=[11 * cm, 5.5 * cm])
    head.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (0, 0), COLOUR_DARK),
        ('BACKGROUND',    (1, 0), (1, 0), rc),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (0, 0),  10),
        ('RIGHTPADDING',  (1, 0), (1, 0),  10),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
 
    els = [KeepTogether([head]), Spacer(1, 0.3 * cm)]
 
    # Educational explanation
    explanation = FINDING_EXPLANATIONS.get(module_name, '')
    if explanation:
        els.append(Paragraph("About this assessment area:", styles['body_bold']))
        els.append(Paragraph(explanation, styles['explanation']))
 
    # Findings
    mod_findings = [f for f in all_findings
                    if f.get('module', '').lower() == module_name.lower()]
    if mod_findings:
        els.append(Paragraph("Findings", styles['h2']))
        for item in mod_findings:
            sev = item.get('severity', 'INFO')
            sc  = _severity_colour(sev)
            row = Table([[
                Paragraph(f"<b>{sev}</b>",
                          ParagraphStyle('sv', fontSize=7, textColor=COLOUR_WHITE,
                                         fontName='Helvetica-Bold', alignment=TA_CENTER)),
                Paragraph(item.get('finding', ''), styles['finding']),
            ]], colWidths=[1.6 * cm, 14.9 * cm])
            row.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (0, 0), sc),
                ('BACKGROUND',    (1, 0), (1, 0), COLOUR_LIGHT),
                ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING',    (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING',   (0, 0), (0, 0),  3),
                ('LEFTPADDING',   (1, 0), (1, 0),  6),
                ('LINEBELOW',     (0, 0), (-1, -1), 0.4, COLOUR_MID),
            ]))
            els.append(row)
            els.append(Spacer(1, 0.08 * cm))
 
    # Recommendations
    mod_recs = [r for r in all_recs
                if r.get('module', '').lower() == module_name.lower()]
    if mod_recs:
        els.append(Spacer(1, 0.3 * cm))
        els.append(Paragraph("Recommendations", styles['h2']))
        for i, item in enumerate(mod_recs, 1):
            els.append(Paragraph(
                f"{i}. {item['recommendation']}", styles['recommendation']
            ))
 
    els.append(Spacer(1, 0.4 * cm))
    els.append(HRFlowable(width="100%", thickness=0.5, color=COLOUR_MID))
    els.append(PageBreak())
    return els
 
 
def _recommendations_page(styles, all_recs):
    els = [
        Paragraph("Prioritised Remediation Plan", styles['h1']),
        HRFlowable(width="100%", thickness=1, color=COLOUR_DARK),
        Spacer(1, 0.3 * cm),
        Paragraph(
            "Recommendations are ordered by the risk score of their source module. "
            "Addressing these items in order achieves the greatest risk reduction.",
            styles['body']
        ),
        Spacer(1, 0.3 * cm),
    ]
 
    if not all_recs:
        els.append(Paragraph("No remediation actions required.", styles['body']))
        els.append(PageBreak())
        return els
 
    rows = [[Paragraph(h, styles['th']) for h in ['#', 'Area', 'Recommended Action']]]
    for i, item in enumerate(all_recs, 1):
        rows.append([
            Paragraph(str(i), styles['td']),
            Paragraph(item.get('module', ''), styles['td']),
            Paragraph(item.get('recommendation', ''), styles['td_small']),
        ])
 
    t = Table(rows, colWidths=[1 * cm, 3.2 * cm, 12.3 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',     (0, 0), (-1, 0), COLOUR_DARK),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOUR_WHITE, COLOUR_LIGHT]),
        ('ALIGN',          (0, 0), (1, -1), 'CENTER'),
        ('ALIGN',          (2, 1), (2, -1), 'LEFT'),
        ('VALIGN',         (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID',           (0, 0), (-1, -1), 0.5, COLOUR_MID),
        ('TOPPADDING',     (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), 5),
        ('LEFTPADDING',    (0, 0), (-1, -1), 5),
    ]))
    els.append(t)
    els.append(PageBreak())
    return els
 
 
def _framework_page(styles):
    els = [
        Paragraph("Appendix: Assessment Frameworks", styles['h1']),
        HRFlowable(width="100%", thickness=1, color=COLOUR_DARK),
        Spacer(1, 0.3 * cm),
        Paragraph(
            "This assessment references the following authoritative security "
            "frameworks. Findings are mapped to multiple standards to provide "
            "comparative compliance analysis rather than imposing a single "
            "configuration standard, as described in the research objectives.",
            styles['body']
        ),
        Spacer(1, 0.3 * cm),
    ]
 
    rows = [[Paragraph(h, styles['th'])
             for h in ['Framework', 'Area', 'Relevant Guidance']]]
    for fw, area, guidance in FRAMEWORK_REFERENCES:
        rows.append([
            Paragraph(f"<b>{fw}</b>", styles['td_small']),
            Paragraph(area, styles['td_small']),
            Paragraph(guidance, styles['td_small']),
        ])
 
    t = Table(rows, colWidths=[5 * cm, 3 * cm, 8.5 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',     (0, 0), (-1, 0), COLOUR_DARK),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOUR_WHITE, COLOUR_LIGHT]),
        ('ALIGN',          (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN',         (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID',           (0, 0), (-1, -1), 0.5, COLOUR_MID),
        ('TOPPADDING',     (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), 5),
        ('LEFTPADDING',    (0, 0), (-1, -1), 5),
    ]))
    els.append(t)
    els.append(Spacer(1, 0.5 * cm))
    els.append(Paragraph(
        "References: Verizon (2023) Data Breach Investigations Report; "
        "NIST SP 800-30 Rev 1; NIST SP 800-63B; NIST SP 800-115; "
        "CIS Controls v8 (2021); Microsoft Security Baseline Windows 11; "
        "OWASP Testing Guide v4.",
        styles['small']
    ))
    return els
 
 
# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------
 
class ReportGenerator:
    """
    Generates a professional PDF security assessment report.
 
    Attributes:
        styles (dict): Paragraph styles for the report.
    """
 
    def __init__(self):
        self.styles = _build_styles()
        logger.info("ReportGenerator initialised")
 
    def generate(self, risk_report: Dict, output_path: str) -> str:
        """
        Generates the full PDF report and saves it to disk.
 
        Args:
            risk_report:  Output from RiskCalculator.calculate().
            output_path:  Destination path (with or without .pdf extension).
 
        Returns:
            str: Full path to the generated PDF file.
        """
        if not output_path.endswith('.pdf'):
            output_path += '.pdf'
 
        logger.info(f"Generating PDF report: {output_path}")
 
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=1.5 * cm,
            rightMargin=1.5 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            title="Windows Security Audit Report",
            author="Windows Security Audit Tool",
            subject="Security Configuration Assessment",
        )
 
        story = []
 
        # 1. Cover
        story += _cover(self.styles, risk_report)
 
        # 2. Executive summary
        story += _executive_summary(self.styles, risk_report)
 
        # 3. Per-module sections
        module_scores = risk_report.get('module_scores', {})
        all_findings  = risk_report.get('all_findings', [])
        all_recs      = risk_report.get('all_recommendations', [])
 
        module_labels = {
            'firewall': 'Firewall Configuration',
            'password': 'Password Policy',
            'port':     'Network Port Exposure',
            'system':   'System Information',
        }
 
        for mod_name, label in module_labels.items():
            mod_data = module_scores.get(mod_name, {})
            if mod_data.get('data_available', False):
                story += _module_section(
                    self.styles, mod_name, label,
                    mod_data, all_findings, all_recs
                )
 
        # 4. Prioritised recommendations
        story += _recommendations_page(self.styles, all_recs)
 
        # 5. Framework appendix
        story += _framework_page(self.styles)
 
        doc.build(story, onFirstPage=_on_cover, onLaterPages=_on_page)
 
        logger.info(f"PDF report generated: {output_path}")
        return output_path
 
 
# ---------------------------------------------------------------------------
# Convenience function (called by audit.py)
# ---------------------------------------------------------------------------
 
def generate_report(risk_report: Dict, output_path: str) -> str:
    """
    Convenience function for use by audit.py.
 
    Args:
        risk_report:  Output from RiskCalculator.calculate().
        output_path:  Destination file path (without extension).
 
    Returns:
        str: Path to the generated PDF.
    """
    return ReportGenerator().generate(risk_report, output_path)
 
 
# ---------------------------------------------------------------------------
# Testing block
# ---------------------------------------------------------------------------
 
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
    from modules.risk_calculator import calculate_risk
 
    print("=" * 60)
    print("Report Generator - Test Run")
    print("=" * 60)
 
    mock_firewall = {
        'firewall_profiles': {
            'domain':  {'enabled': True, 'risk_level': 'Low'},
            'private': {'enabled': True, 'risk_level': 'Low'},
            'public':  {'enabled': True, 'risk_level': 'Low'},
        },
        'defender_status': {
            'realtime_protection_enabled': True,
            'antivirus_enabled': True,
            'signatures_outdated': False,
            'status_available': True,
        },
        'risk_assessment': {
            'risk_score': 0,
            'findings': ['No significant firewall security issues detected'],
            'recommendations': ['Maintain current firewall configuration'],
        }
    }
 
    mock_password = {
        'password_policy': {
            'min_password_length': 0,
            'max_password_age_days': 42,
            'min_password_age_days': 0,
            'password_history_count': 0,
            'lockout_threshold': 0,
            'complexity_enabled': None,
            'retrieval_successful': True,
        },
        'compliance': {'compliance_level': 'Poor', 'compliance_percentage': 25.0},
        'risk_assessment': {
            'risk_score': 8,
            'findings': [
                'CRITICAL: Minimum password length is only 0 characters',
                'HIGH: Account lockout is disabled',
                'MEDIUM: Password history only remembers 0 passwords',
                'LOW: No minimum password age',
            ],
            'recommendations': [
                'Increase minimum password length to at least 8 characters',
                'Enable account lockout with 5-10 attempt threshold',
                'Increase password history to at least 24 passwords',
            ]
        }
    }
 
    mock_port = {
        'listening_ports': {
            'enumeration_successful': True,
            'tcp_ports': [135, 139, 445],
            'total_listening': 63,
            'port_details': [
                {'port': 135, 'protocol': 'TCP', 'address': '0.0.0.0', 'status': 'LISTENING', 'pid': 1},
                {'port': 139, 'protocol': 'TCP', 'address': '0.0.0.0', 'status': 'LISTENING', 'pid': 1},
                {'port': 445, 'protocol': 'TCP', 'address': '0.0.0.0', 'status': 'LISTENING', 'pid': 1},
            ]
        },
        'dangerous_ports_found': {
            'critical_risk_ports': [
                {'port': 135, 'service': 'MS-RPC',  'risk': 'Critical', 'reason': 'Windows RPC'},
                {'port': 139, 'service': 'NetBIOS', 'risk': 'Critical', 'reason': 'Legacy file sharing'},
                {'port': 445, 'service': 'SMB',     'risk': 'Critical', 'reason': 'Ransomware vector'},
            ],
            'high_risk_ports': [], 'medium_risk_ports': [],
            'analysis_available': True,
        },
        'risk_assessment': {
            'risk_score': 10,
            'findings': [
                'CRITICAL: MS-RPC (port 135) is listening',
                'CRITICAL: NetBIOS (port 139) is listening',
                'CRITICAL: SMB (port 445) is listening',
                'MEDIUM: Large number of open ports (63 listening)',
            ],
            'recommendations': ['Verify Windows Firewall blocks external access']
        }
    }
 
    mock_system = {
        'risk_assessment': {
            'risk_score': 1,
            'findings': ['INFO: Operating system is current and supported'],
            'recommendations': ['Keep system updated with latest patches'],
        }
    }
 
    print("\n  Calculating risk scores...")
    report = calculate_risk(
        firewall_data=mock_firewall,
        password_data=mock_password,
        port_data=mock_port,
        system_data=mock_system,
    )
 
    print("  Building PDF...")
    path = ReportGenerator().generate(report, "test_audit_report")
    print(f"\n  Report saved to: {path}")
    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)