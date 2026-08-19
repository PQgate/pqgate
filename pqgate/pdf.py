"""Render the readiness report Markdown to PDF.

reportlab is pure-Python with no system libraries, so this works inside an air-gapped
container. The PDF is a rendering of the same bytes the attestation covers - verification
is always performed against the Markdown.
"""
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

COBALT = colors.HexColor("#1F4FD8")
BANNER = colors.HexColor("#175229")
INK = colors.HexColor("#16212B")
INK2 = colors.HexColor("#5A6875")
LINE = colors.HexColor("#DDE3E9")

_INLINE = [
    (re.compile(r"\*\*(.+?)\*\*"), r"<b>\1</b>"),
    (re.compile(r"`(.+?)`"), r'<font face="Courier" size="8.5">\1</font>'),
    (re.compile(r"\*(.+?)\*"), r"<i>\1</i>"),
]


def _inline(text):
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for rx, repl in _INLINE:
        text = rx.sub(repl, text)
    return text


def _styles():
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold",
                             fontSize=20, textColor=INK, spaceAfter=4),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=12.5, textColor=COBALT, spaceBefore=16, spaceAfter=6),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica",
                               fontSize=9.5, leading=14, textColor=INK, alignment=TA_LEFT),
        "bullet": ParagraphStyle("bullet", parent=base["BodyText"], fontName="Helvetica",
                                 fontSize=9, leading=13, leftIndent=12, textColor=INK),
        "mono": ParagraphStyle("mono", parent=base["BodyText"], fontName="Courier",
                               fontSize=7.5, leading=10, textColor=INK2),
        "banner": ParagraphStyle("banner", parent=base["BodyText"], fontName="Courier-Bold",
                                 fontSize=8, textColor=colors.white),
    }


def _table(rows, st):
    data = [[Paragraph(_inline(c), st["body"]) for c in row] for row in rows]
    t = Table(data, hAlign="LEFT", colWidths=None, repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF1FD")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _split_row(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def render_pdf(markdown_text, out_path, org="", enforcing_profile="CNSA 2.0"):
    st = _styles()
    flow = []

    banner = Table([[Paragraph(
        "CNSA 2.0 PROFILE - ENFORCING &nbsp;&nbsp;//&nbsp;&nbsp; AIR-GAP MODE - EVIDENCE ARTIFACT",
        st["banner"])]], colWidths=[6.9 * inch])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BANNER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    flow += [banner, Spacer(1, 14)]

    lines = markdown_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if not line.strip():
            i += 1
            continue
        if line.startswith("# "):
            flow.append(Paragraph(_inline(line[2:]), st["h1"]))
        elif line.startswith("## "):
            flow.append(Paragraph(_inline(line[3:]), st["h2"]))
        elif line.startswith("|"):
            rows, j = [], i
            while j < len(lines) and lines[j].strip().startswith("|"):
                cells = _split_row(lines[j])
                if not all(set(c) <= set("-: ") for c in cells):
                    rows.append(cells)
                j += 1
            flow += [_table(rows, st), Spacer(1, 6)]
            i = j
            continue
        elif line.startswith("- "):
            flow.append(Paragraph("&bull; " + _inline(line[2:]), st["bullet"]))
        elif line.lower().startswith("cbom content hash") or line.lower().startswith("report attestation"):
            flow.append(Paragraph(_inline(line), st["mono"]))
        else:
            flow.append(Paragraph(_inline(line), st["body"]))
        i += 1

    doc = SimpleDocTemplate(
        out_path, pagesize=LETTER,
        leftMargin=0.8 * inch, rightMargin=0.8 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        title="CNSA 2.0 Readiness Report" + (" - " + org if org else ""),
        author="PQgate",
    )
    doc.build(flow, onLaterPages=_footer, onFirstPage=_footer)
    return out_path


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Courier", 7)
    canvas.setFillColor(INK2)
    canvas.drawString(0.8 * inch, 0.45 * inch,
                      "PQgate evidence artifact - verify with: pqgate verify <report.md>")
    canvas.drawRightString(7.7 * inch, 0.45 * inch, "page " + str(canvas.getPageNumber()))
    canvas.restoreState()
