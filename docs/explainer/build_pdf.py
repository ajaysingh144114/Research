"""Build docs/QSign-How-It-Works.pdf.

    pip install reportlab
    python3 docs/explainer/build_pdf.py

Uses the DejaVu fonts that ship with most Linux systems (fonts-dejavu-core).
"""

from __future__ import annotations

from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = Path(__file__).resolve().parents[1] / "QSign-How-It-Works.pdf"
FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
pdfmetrics.registerFont(TTFont("Sans", FONT_DIR / "DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("Sans-Bold", FONT_DIR / "DejaVuSans-Bold.ttf"))
pdfmetrics.registerFont(TTFont("Mono", FONT_DIR / "DejaVuSansMono.ttf"))
pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-Bold", italic="Sans", boldItalic="Sans-Bold")

# ---------- palette ----------
INK = colors.HexColor("#1b1f24")
MUTED = colors.HexColor("#5b6470")
LINE = colors.HexColor("#d5dae0")
BLUE = colors.HexColor("#1f5fbf")
BLUE_BG = colors.HexColor("#e8f0fb")
GREEN = colors.HexColor("#1d7a3e")
GREEN_BG = colors.HexColor("#e6f4ea")
AMBER = colors.HexColor("#9a6700")
AMBER_BG = colors.HexColor("#fdf3d7")
RED = colors.HexColor("#b42318")
RED_BG = colors.HexColor("#fdecea")
GREY_BG = colors.HexColor("#f3f5f7")

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# ---------- text styles ----------
body = ParagraphStyle("body", fontName="Sans", fontSize=10, leading=14.5, textColor=INK, spaceAfter=6)
small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=12, textColor=MUTED)
h1 = ParagraphStyle("h1", fontName="Sans-Bold", fontSize=19, leading=24, textColor=INK, spaceBefore=0, spaceAfter=4)
kicker = ParagraphStyle("kicker", fontName="Sans-Bold", fontSize=8.5, leading=11, textColor=BLUE, spaceAfter=2)
h2 = ParagraphStyle("h2", fontName="Sans-Bold", fontSize=12.5, leading=16, textColor=INK, spaceBefore=10, spaceAfter=4)
lead = ParagraphStyle("lead", parent=body, fontSize=11, leading=16, textColor=MUTED, spaceAfter=10)
cell = ParagraphStyle("cell", parent=body, fontSize=9, leading=12.5, spaceAfter=0)
cell_b = ParagraphStyle("cellb", parent=cell, fontName="Sans-Bold")
bullet = ParagraphStyle("bullet", parent=body, leftIndent=12, bulletIndent=2, spaceAfter=3)
code = ParagraphStyle("code", fontName="Mono", fontSize=7.6, leading=10.2, textColor=INK)


def P(text, style=body):
    return Paragraph(text, style)


def bullets(items):
    return [Paragraph(t, bullet, bulletText="•") for t in items]


def chapter(num, title, intro=None):
    out = [P(f"PART {num}", kicker), P(title, h1)]
    if intro:
        out.append(P(intro, lead))
    return out


def table(rows, widths, header=True, zebra=True, pad=5):
    data = [[c if not isinstance(c, str) else P(c, cell_b if (header and i == 0) else cell) for c in r]
            for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), pad),
        ("BOTTOMPADDING", (0, 0), (-1, -1), pad),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), GREY_BG), ("LINEBELOW", (0, 0), (-1, 0), 1, INK)]
    t.setStyle(TableStyle(style))
    return t


def callout(title, text, fg=BLUE, bg=BLUE_BG):
    inner = [P(f"<b>{title}</b>", ParagraphStyle("ct", parent=cell, textColor=fg, fontSize=9.5)), P(text, cell)]
    t = Table([[inner]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 3, fg),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return KeepTogether([Spacer(1, 4), t, Spacer(1, 8)])


# ---------- diagram helpers ----------
def box(d, x, y, w, h, title, sub="", fill=BLUE_BG, stroke=BLUE, title_size=8.5):
    d.add(Rect(x, y, w, h, rx=5, ry=5, fillColor=fill, strokeColor=stroke, strokeWidth=1))
    lines = [title] + ([s for s in sub.split("\n")] if sub else [])
    total = 11 + 9.5 * (len(lines) - 1)
    ty = y + h / 2 + total / 2 - 8.5
    d.add(String(x + w / 2, ty, title, fontName="Sans-Bold", fontSize=title_size, fillColor=INK, textAnchor="middle"))
    for i, s in enumerate(lines[1:]):
        d.add(String(x + w / 2, ty - 11 - 9.5 * i, s, fontName="Sans", fontSize=7.2, fillColor=MUTED, textAnchor="middle"))


def arrow(d, x1, y1, x2, y2, label="", color=MUTED, label_dx=0, label_dy=4):
    d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=1.1))
    import math

    ang = math.atan2(y2 - y1, x2 - x1)
    s = 5
    p1 = (x2 - s * math.cos(ang - 0.45), y2 - s * math.sin(ang - 0.45))
    p2 = (x2 - s * math.cos(ang + 0.45), y2 - s * math.sin(ang + 0.45))
    d.add(Polygon([x2, y2, *p1, *p2], fillColor=color, strokeColor=color, strokeWidth=0.5))
    if label:
        d.add(String((x1 + x2) / 2 + label_dx, (y1 + y2) / 2 + label_dy, label, fontName="Sans", fontSize=7,
                     fillColor=INK, textAnchor="middle"))


def badge(d, x, y, n, color=BLUE):
    from reportlab.graphics.shapes import Circle

    d.add(Circle(x, y, 7, fillColor=color, strokeColor=color))
    d.add(String(x, y - 2.6, str(n), fontName="Sans-Bold", fontSize=7.5, fillColor=colors.white, textAnchor="middle"))


def diagram_hash():
    d = Drawing(CONTENT_W, 92)
    box(d, 0, 22, 120, 50, "contract.pdf", "any size\n(e.g. 2 MB)", fill=GREY_BG, stroke=LINE)
    arrow(d, 122, 47, 186, 47, "SHA-512")
    box(d, 188, 22, 170, 50, "Fingerprint (hash)", "128 characters, always\n9f86d0…a1c3e7 ", fill=BLUE_BG, stroke=BLUE)
    box(d, 380, 22, CONTENT_W - 380, 50, "Change 1 comma", "completely different\nfingerprint", fill=RED_BG, stroke=RED)
    d.add(String(0, 6, "The same file always gives the same fingerprint. You cannot work backwards from the fingerprint to the file.",
                 fontName="Sans", fontSize=7.4, fillColor=MUTED))
    return d


def diagram_keys():
    d = Drawing(CONTENT_W, 120)
    box(d, 0, 52, 130, 56, "Private key", "kept secret inside\nAWS KMS hardware", fill=AMBER_BG, stroke=AMBER)
    box(d, 0, 0, 130, 44, "Public key", "published to everyone", fill=GREEN_BG, stroke=GREEN)
    box(d, 175, 52, 140, 56, "SIGN", "fingerprint + private key\n= signature", fill=BLUE_BG, stroke=BLUE)
    box(d, 175, 0, 140, 44, "VERIFY", "signature + public key\n= yes / no", fill=BLUE_BG, stroke=BLUE)
    arrow(d, 131, 80, 173, 80)
    arrow(d, 131, 22, 173, 22)
    box(d, 360, 52, CONTENT_W - 360, 56, "Only the key holder", "can create a valid\nsignature", fill=GREY_BG, stroke=LINE)
    box(d, 360, 0, CONTENT_W - 360, 44, "Anyone", "can check it, offline", fill=GREY_BG, stroke=LINE)
    arrow(d, 316, 80, 358, 80)
    arrow(d, 316, 22, 358, 22)
    return d


def diagram_hybrid():
    d = Drawing(CONTENT_W, 118)
    box(d, 0, 38, 120, 50, "Manifest", "fingerprint + who\n+ when + consent", fill=GREY_BG, stroke=LINE)
    box(d, 165, 66, 160, 46, "ML-DSA-65", "post-quantum (FIPS 204)", fill=BLUE_BG, stroke=BLUE)
    box(d, 165, 8, 160, 46, "ECDSA P-384", "classical, widely trusted", fill=BLUE_BG, stroke=BLUE)
    arrow(d, 121, 70, 163, 89)
    arrow(d, 121, 56, 163, 31)
    box(d, 370, 38, CONTENT_W - 370, 50, "Valid only if BOTH pass", "forger must break both", fill=GREEN_BG, stroke=GREEN)
    arrow(d, 326, 89, 368, 70)
    arrow(d, 326, 31, 368, 56)
    return d


def diagram_architecture():
    W = CONTENT_W
    d = Drawing(W, 300)
    # browser column
    box(d, 0, 210, 118, 70, "Your browser", "hashes the file\nfile never leaves\nyour computer", fill=GREY_BG, stroke=LINE)
    box(d, 0, 112, 118, 70, "Signers", "other people's\nbrowsers", fill=GREY_BG, stroke=LINE)
    box(d, 0, 14, 118, 70, "Anyone", "verifies a signature\nno account needed", fill=GREY_BG, stroke=LINE)
    # AWS frame
    d.add(Rect(140, 0, W - 140, 296, rx=8, ry=8, fillColor=None, strokeColor=AMBER, strokeWidth=1, strokeDashArray=[4, 3]))
    d.add(String(150, 284, "AWS account (your region: Mumbai, Frankfurt, US...)", fontName="Sans-Bold", fontSize=7.5, fillColor=AMBER))
    R = 384  # right column x
    box(d, 152, 206, 106, 62, "Amazon Cognito", "login + MFA\ninvite-only", fill=AMBER_BG, stroke=AMBER)
    box(d, 152, 112, 106, 70, "API Gateway", "checks the login\ntoken on every call", fill=AMBER_BG, stroke=AMBER)
    box(d, 276, 112, 90, 70, "Lambda", "QSign code\n(the brain)", fill=BLUE_BG, stroke=BLUE)
    box(d, R, 206, W - R - 8, 62, "AWS KMS", "ML-DSA-65 key\nECDSA P-384 key", fill=AMBER_BG, stroke=AMBER)
    box(d, R, 112, W - R - 8, 70, "DynamoDB", "envelopes\naudit trail", fill=AMBER_BG, stroke=AMBER)
    box(d, R, 14, W - R - 8, 74, "S3 Object Lock", "write-once copy of\nevery signature", fill=AMBER_BG, stroke=AMBER)
    box(d, 152, 14, 214, 74, "CloudWatch + SNS + SES", "logs, alarms by email,\n'please sign' emails", fill=AMBER_BG, stroke=AMBER)
    arrow(d, 119, 252, 150, 240, "login", label_dx=-4, label_dy=7)
    arrow(d, 119, 218, 150, 172, "hash only", label_dx=-22, label_dy=-4)
    arrow(d, 119, 147, 150, 147)
    arrow(d, 119, 49, 150, 125, "verify", label_dx=-14)
    arrow(d, 259, 147, 274, 147)
    arrow(d, 330, 183, R - 2, 236, "sign", label_dx=-12, label_dy=2)
    arrow(d, 367, 147, R - 2, 147)
    arrow(d, 350, 111, R - 2, 62)
    arrow(d, 300, 111, 290, 90)
    return d


def diagram_sign_steps():
    W = CONTENT_W
    d = Drawing(W, 128)
    steps = [
        ("Choose file", "browser makes\nSHA-512 fingerprint"),
        ("Tick consent", "'I agree to sign\nelectronically'"),
        ("Check login", "Cognito token\n+ MFA verified"),
        ("Build manifest", "fingerprint, who,\nwhen, why"),
        ("KMS signs twice", "ML-DSA-65 +\nECDSA P-384"),
        ("Record + return", "audit + S3 lock;\nyou get .qsig.json"),
    ]
    bw, gap = (W - 5 * 10) / 6, 10
    for i, (t, s) in enumerate(steps):
        x = i * (bw + gap)
        fill, stroke = (GREY_BG, LINE) if i < 2 else (BLUE_BG, BLUE) if i < 4 else (AMBER_BG, AMBER)
        box(d, x, 20, bw, 76, t, s, fill=fill, stroke=stroke, title_size=7.8)
        badge(d, x + bw / 2, 106, i + 1)
        if i < 5:
            arrow(d, x + bw + 1, 58, x + bw + gap - 1, 58)
    d.add(String(0, 4, "Grey = in your browser   Blue = QSign code   Amber = AWS services", fontName="Sans", fontSize=7.2, fillColor=MUTED))
    return d


def diagram_envelope():
    W = CONTENT_W
    d = Drawing(W, 168)
    box(d, 0, 92, 108, 62, "Sender", "creates envelope:\ndocument fingerprint\n+ signers in order", fill=GREY_BG, stroke=LINE)
    box(d, 138, 92, 100, 62, "Signer 1", "gets email, opens\nsame file, signs", fill=BLUE_BG, stroke=BLUE)
    box(d, 268, 92, 100, 62, "Signer 2", "notified only after\nsigner 1 signs", fill=BLUE_BG, stroke=BLUE)
    box(d, 390, 92, W - 390, 62, "Completion seal", "QSign signs the list\nof all signatures", fill=GREEN_BG, stroke=GREEN)
    arrow(d, 109, 123, 136, 123)
    arrow(d, 239, 123, 266, 123)
    arrow(d, 369, 123, 388, 123)
    box(d, 138, 10, 230, 56, "Each signer's own signature", "ML-DSA + ECDSA over: fingerprint, their\nidentity, time, envelope id, their position", fill=GREY_BG, stroke=LINE)
    arrow(d, 188, 91, 220, 67)
    arrow(d, 318, 91, 290, 67)
    box(d, 390, 10, W - 390, 56, "Evidence pack", ".json file: envelope,\nsignatures + seal", fill=GREEN_BG, stroke=GREEN)
    arrow(d, 390 + (W - 390) / 2, 91, 390 + (W - 390) / 2, 67)
    return d


def diagram_verify():
    W = CONTENT_W
    d = Drawing(W, 70)
    checks = [
        ("1  Signatures", "ML-DSA and ECDSA\nmath both pass"),
        ("2  Document", "fingerprint of your\nfile matches"),
        ("3  Keys", "fingerprints are the\norganisation's own"),
        ("4  Seal (envelopes)", "no signature added,\nremoved or swapped"),
    ]
    bw = (W - 3 * 10) / 4
    for i, (t, s) in enumerate(checks):
        box(d, i * (bw + 10), 6, bw, 58, t, s, fill=GREEN_BG, stroke=GREEN, title_size=8)
    return d


# ---------- page decoration ----------
def on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Sans", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, 10 * mm, "QSign: how it works  ·  v0.2  ·  October 2026")
    canvas.drawRightString(PAGE_W - MARGIN, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(LINE)
    canvas.line(MARGIN, 13 * mm, PAGE_W - MARGIN, 13 * mm)
    canvas.restoreState()


def on_cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(BLUE)
    canvas.rect(0, PAGE_H - 92 * mm, PAGE_W, 92 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Sans-Bold", 34)
    canvas.drawString(MARGIN, PAGE_H - 45 * mm, "QSign")
    canvas.setFont("Sans", 16)
    canvas.drawString(MARGIN, PAGE_H - 58 * mm, "How quantum-safe e-signatures work")
    canvas.setFont("Sans", 10)
    canvas.drawString(MARGIN, PAGE_H - 70 * mm, "A plain-language guide for owners, customers and security teams")
    canvas.setFillColor(MUTED)
    canvas.setFont("Sans", 8.5)
    canvas.drawString(MARGIN, 18 * mm, "Version 0.2  ·  October 2026  ·  Justivia Legal Ventures LLP  ·  Apache License 2.0")
    canvas.drawString(MARGIN, 13 * mm, "This guide explains technology. It is not legal advice.")
    canvas.restoreState()


# ---------- content ----------
def build():
    s = []
    # Cover page body (below the blue band)
    s.append(Spacer(1, 88 * mm))
    s.append(P("What is in this guide", h2))
    s.append(table([
        ["Part", "What you will learn"],
        ["1  The problem", "Why today's digital signatures need replacing, and why it matters now"],
        ["2  Five ideas", "Fingerprints, keys, signatures, post-quantum, hybrid: no maths needed"],
        ["3  The system", "Which AWS services QSign uses and what each one does"],
        ["4  Signing", "Step by step, what happens when someone signs"],
        ["5  Envelopes", "Several signers, signing order and the evidence pack"],
        ["6  Verifying", "How anyone can check a signature, and what a failure means"],
        ["7  Security", "Who can do what, and how common attacks are stopped"],
        ["8  The law", "Where QSign stands in the USA, India and the EU"],
        ["9  Running it", "Deploying, onboarding a customer, and what comes next"],
    ], [38 * mm, CONTENT_W - 38 * mm], pad=3))
    s.append(Spacer(1, 10))
    s.append(callout("In one sentence",
                     "QSign signs documents twice, once with a new quantum-safe method and once with today's trusted method, "
                     "using keys locked inside AWS hardware, and keeps a tamper-proof record so anyone can later prove "
                     "who signed what, and when."))
    s.append(PageBreak())

    # Part 1
    s += chapter(1, "The problem", "Every digital signature in use today relies on maths that a large quantum computer will be able to break.")
    s.append(P("Almost all e-signatures (PDF signatures, Aadhaar eSign, DocuSign certificates, website certificates) use "
               "<b>RSA</b> or <b>elliptic-curve</b> cryptography. Their safety rests on maths problems that ordinary computers "
               "cannot solve in any reasonable time. In 1994 Peter Shor showed that a sufficiently large quantum computer could "
               "solve them quickly. Such a machine does not exist yet, but governments are planning for the day it does."))
    s.append(P("Why act now?", h2))
    s += bullets([
        "<b>Contracts live a long time.</b> A property deed, loan or employment contract signed today may be disputed in 10, "
        "20 or 30 years. If its signature can be forged by then, it proves nothing.",
        "<b>Deadlines are set.</b> The US NSA (CNSA 2.0) and NIST plan to phase out RSA and elliptic-curve signatures between "
        "2030 and 2035. The EU asked member states to start moving in 2026 and to protect high-risk systems by 2030.",
        "<b>The replacement is ready.</b> In August 2024 NIST published <b>FIPS 204 (ML-DSA)</b>, a signature standard designed "
        "to resist quantum computers. AWS KMS has supported ML-DSA keys since 2025.",
    ])
    s.append(callout("What QSign does about it",
                     "It signs with ML-DSA now, while still adding a classical ECDSA signature that today's tools trust. "
                     "Customers get protection against tomorrow's attacks without losing compatibility today.",
                     GREEN, GREEN_BG))
    s.append(PageBreak())

    # Part 2
    s += chapter(2, "Five ideas you need", "These five ideas explain everything QSign does. None of them need maths.")
    s.append(P("1. A fingerprint (hash)", h2))
    s.append(P("A hash function turns any file into a short, fixed-length code. QSign uses <b>SHA-512</b>. It works like a "
               "fingerprint: unique to the file, and useless for rebuilding the file."))
    s.append(diagram_hash())
    s.append(P("This is why QSign never needs your document. Your browser computes the fingerprint and only that is sent. "
               "If anyone later changes even one letter, the fingerprint no longer matches."))
    s.append(P("2 and 3. Keys and signatures", h2))
    s.append(P("A signing key comes as a pair. The <b>private key</b> creates signatures and must stay secret. The "
               "<b>public key</b> checks them and is shared with everyone. A signature is the result of combining a "
               "fingerprint with the private key."))
    s.append(diagram_keys())
    s.append(P("4. Post-quantum", h2))
    s.append(P("<b>ML-DSA</b> (Module-Lattice Digital Signature Algorithm) is built on a different kind of maths "
               "(lattices) for which no fast quantum attack is known. QSign uses <b>ML-DSA-65</b>, the middle security level, "
               "roughly comparable to the strength of 192-bit classical security."))
    s.append(P("5. Hybrid", h2))
    s.append(P("ML-DSA is new. Experts recommend using it <i>alongside</i> a proven classical signature during the transition, "
               "so a mistake in either one is not enough to forge a signature."))
    s.append(diagram_hybrid())
    s.append(PageBreak())

    # Part 3
    s += chapter(3, "The system", "QSign is built only from managed AWS services, so there are no servers to patch and nothing to keep running overnight.")
    s.append(diagram_architecture())
    s.append(Spacer(1, 8))
    s.append(table([
        ["AWS service", "Its job in QSign"],
        ["<b>AWS KMS</b>", "Holds the two signing keys in hardware security modules validated to FIPS 140-3 Level 3. "
                          "Keys are created inside and can never be exported. QSign can only <i>ask</i> KMS to sign."],
        ["<b>Amazon Cognito</b>", "User accounts. Invite-only, strong passwords, and an authenticator app (MFA) for everyone. "
                                 "Stores each user's organisation and whether they are an admin."],
        ["<b>API Gateway</b>", "The front door. Checks the Cognito login token before any private request reaches QSign. "
                              "Writes an access log line for every request and limits request rates."],
        ["<b>AWS Lambda</b>", "Runs the QSign code only when a request arrives. Can also run as a container (ECS, EKS)."],
        ["<b>DynamoDB</b>", "Stores envelopes and the audit trail. Point-in-time recovery and deletion protection are on."],
        ["<b>S3 Object Lock</b>", "Keeps a write-once copy of every signature and evidence pack. In compliance mode nobody, "
                                 "not even the account owner, can delete or alter them until the retention period ends (10 years by default)."],
        ["<b>CloudWatch, SNS, SES</b>", "Logs and alarms (emailed to your operations team) and the 'please sign' emails."],
    ], [38 * mm, CONTENT_W - 38 * mm], pad=3))
    s.append(PageBreak())

    # Part 4
    s += chapter(4, "What happens when someone signs", "The same six steps happen whether you sign a document yourself or as part of an envelope.")
    s.append(diagram_sign_steps())
    s.append(Spacer(1, 6))
    s.append(table([
        ["Step", "What happens", "Why it matters"],
        ["1", "The browser reads the file and computes its SHA-512 fingerprint.", "The document never leaves the signer's computer. Privacy by design."],
        ["2", "The signer ticks 'I have reviewed this document and I agree to sign it electronically'.", "Laws in the USA, India and the EU require clear intent and consent. The exact sentence is signed too."],
        ["3", "API Gateway (or QSign itself, when run as a container) checks the Cognito login token.", "The signer's name and email come from the verified login, never from what is typed in the form."],
        ["4", "QSign builds the <b>manifest</b>: fingerprint, file name and size, signer identity and organisation, time (UTC), reason, location, jurisdiction and, for envelopes, the envelope and signing order.", "This small record is what actually gets signed. It ties the person to the exact file and moment."],
        ["5", "QSign asks KMS to sign the manifest with the ML-DSA-65 key and with the ECDSA P-384 key.", "The private keys never leave KMS. Every request is logged by AWS CloudTrail."],
        ["6", "QSign writes an audit record, archives the signature in S3 Object Lock, and returns a <b>.qsig.json</b> file.", "The signer keeps the file next to the document. The organisation keeps a copy nobody can tamper with."],
    ], [15 * mm, 76 * mm, CONTENT_W - 91 * mm]))
    s.append(callout("Why a separate signature file?",
                     "QSign produces a detached signature (a small JSON file) instead of changing the document. "
                     "It works for any file type (PDF, Word, images, code) and the original stays byte-for-byte unchanged. "
                     "Embedding signatures inside PDFs (PAdES) is on the roadmap."))
    s.append(PageBreak())

    # Part 5
    s += chapter(5, "Envelopes: several signers, one proof", "An envelope is how a company sends one document to several people and gets back a single proof that everyone signed it.")
    s.append(diagram_envelope())
    s.append(Spacer(1, 4))
    s += bullets([
        "<b>Create.</b> The sender picks the document (only its fingerprint is sent), lists up to 25 signers, chooses "
        "<i>in order</i> or <i>any order</i>, adds a message and an expiry date (1 to 365 days).",
        "<b>Invite.</b> Signers who have no account get a guest account automatically, with an email invitation. "
        "Guests can sign what was sent to them but cannot send envelopes.",
        "<b>Sign.</b> When it is their turn, each signer opens the envelope and selects their copy of the document. "
        "QSign accepts the signature only if the fingerprint matches the one in the envelope. They could not sign a different file even by mistake.",
        "<b>Decline or cancel.</b> A signer can decline with a reason; the sender or an organisation admin can cancel. Either stops the envelope.",
        "<b>Seal.</b> When the last person signs, QSign signs a list of every signer's signature (its own fingerprint, order, "
        "email and time). This <b>completion seal</b> is the lock on the envelope.",
        "<b>Evidence pack.</b> One JSON file containing the envelope, every signature and the seal. Hand it to an auditor, "
        "a court or the other party; they can verify it without an account.",
    ])
    s.append(callout("What the seal prevents",
                     "Without a seal, someone could quietly drop a signer, add a fake signature, or swap the order. With it, "
                     "any such change breaks the seal's ML-DSA and ECDSA signatures and verification fails.",
                     GREEN, GREEN_BG))
    s.append(PageBreak())

    # Part 6
    s += chapter(6, "Verifying a signature", "Verification needs only the document and its signature file or evidence pack. No account, and no trust in QSign itself.")
    s.append(diagram_verify())
    s.append(Spacer(1, 6))
    s.append(P("Three ways to verify", h2))
    s.append(table([
        ["Where", "How"],
        ["QSign web page", "Open the <b>Verify</b> tab, choose the document and the .qsig.json or evidence file. The fingerprint is computed in the browser."],
        ["QSign command line", "<font name='Mono' size='8'>qsign verify contract.pdf contract.pdf.qsig.json --trust &lt;key fingerprint&gt;</font>"],
        ["Independent tools", "OpenSSL 3.5 or newer, or any library that supports ML-DSA. The repository README lists the exact commands."],
    ], [38 * mm, CONTENT_W - 38 * mm], pad=3))
    s.append(P("What a failure means", h2))
    s.append(table([
        ["Message", "Meaning", "What to do"],
        ["Document does not match", "The file is not the one that was signed, or it was changed afterwards.", "Ask for the original file."],
        ["Signature is not valid", "The signature file was edited, or was not made by those keys.", "Treat as forged."],
        ["No valid post-quantum signature", "Someone removed the ML-DSA part, leaving only the classical one.", "Treat as forged."],
        ["Keys not trusted", "The maths is fine, but the keys are not this organisation's published keys.", "Check who really made it."],
        ["Not the one that was sealed", "A signature in an evidence pack was swapped, added or removed.", "Treat the pack as tampered."],
    ], [44 * mm, 76 * mm, CONTENT_W - 120 * mm], pad=3))
    sample = """{
  "format": "qsign/1",
  "manifest": {                          <- this part is what gets signed
    "document":  { "name": "msa.pdf", "size": 48213, "sha512": "9f86d0...a1c3e7" },
    "signer":    { "name": "Asha Rao", "email": "asha@acme.com", "org_id": "acme",
                   "verified_by": "cognito:https://cognito-idp.ap-south-1..." },
    "intent":    "I have reviewed this document and I intend to sign it electronically.",
    "jurisdiction": "IN",  "signed_at": "2026-10-08T07:43:29Z",
    "envelope":  { "id": "4b1e...", "signer_order": 1, "total_signers": 2 }
  },
  "signatures": [
    { "alg": "ML-DSA-65",         "key_fingerprint": "c41a...", "signature": "..." },
    { "alg": "ECDSA-P384-SHA384", "key_fingerprint": "7be2...", "signature": "..." }
  ]
}"""
    t = Table([[Preformatted(sample, code)]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), GREY_BG), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    s.append(KeepTogether([P("What is inside a signature file", h2), t,
                           P("Each signature also carries the public key it was made with, so it can be checked offline.", small)]))
    s.append(PageBreak())

    # Part 7
    s += chapter(7, "Security", "Who can do what, and how QSign stops the attacks that matter for e-signatures.")
    s.append(P("Who can do what", h2))
    s.append(table([
        ["Role", "Can", "Cannot"],
        ["Anyone (no account)", "Verify signatures and evidence packs; see the published key fingerprints.", "Sign, see envelopes."],
        ["Guest (external signer)", "Sign envelopes sent to them; sign their own documents.", "Send envelopes; see other people's envelopes."],
        ["Member of an organisation", "Everything a guest can, plus send envelopes.", "See envelopes they are not part of; invite users."],
        ["Organisation admin", "Invite colleagues (and other admins); see all their organisation's envelopes and audit trail; cancel envelopes.", "See other organisations' data. Change who signed what."],
        ["AWS account owner", "Deploy, rotate keys, read logs.", "Export the private keys. Delete or edit locked signatures before retention ends."],
    ], [38 * mm, 78 * mm, CONTENT_W - 116 * mm], pad=3))
    s.append(P("Attacks and defences", h2))
    s.append(table([
        ["Attack", "Defence"],
        ["Steal the signing key", "Keys exist only inside KMS hardware and cannot be exported. Only QSign's role may use them, and every use is logged in CloudTrail."],
        ["Sign as someone else", "Identity comes only from a verified Cognito token. Passwords plus an authenticator app (MFA). Request bodies cannot set identity."],
        ["Change a document after signing", "Its fingerprint changes, so verification fails."],
        ["Edit the signature file", "Both ML-DSA and ECDSA signatures fail."],
        ["Future quantum computer breaks ECDSA", "The ML-DSA signature still holds, and a signature is only valid if every part verifies."],
        ["Add, drop or reorder envelope signers", "The completion seal no longer matches."],
        ["Sign the wrong file in an envelope", "QSign rejects any fingerprint that differs from the envelope's."],
        ["Two people act at the same moment", "Optimistic locking: the second change is rejected and must retry."],
        ["Insider deletes or rewrites history", "S3 Object Lock (compliance mode) and DynamoDB deletion protection with point-in-time recovery."],
        ["Organisation A reads organisation B's data", "Every request is scoped to the caller's organisation; others get 'not found'."],
        ["Forged login token (container mode)", "QSign checks the token's RS256 signature, issuer, audience, type and expiry itself."],
        ["Test settings left on in production", "QSign refuses to start in development mode with real KMS keys."],
    ], [56 * mm, CONTENT_W - 56 * mm], pad=3))
    s.append(PageBreak())

    # Part 8
    s += chapter(8, "The law: USA, India, EU", "Strong cryptography is necessary but not sufficient. Each region also cares about who vouches for the signer's identity.")
    s.append(table([
        ["", "QSign today", "Needed for the highest level"],
        ["<b>USA</b><br/>ESIGN Act, UETA", "Valid for most business contracts. The law is technology-neutral: intent, consent, a link to the record and a retained record, all of which QSign provides.",
         "Federal agencies: FedRAMP authorisation (e.g. AWS GovCloud) and identity proofing to NIST SP 800-63. Some documents (wills, court orders) are excluded from e-signing."],
        ["<b>India</b><br/>IT Act 2000", "Useful supporting evidence, but not a 'digital signature' or 'electronic signature' that gets automatic legal recognition.",
         "Integrate a CCA-empanelled eSign Service Provider (Aadhaar eSign) or a licensed Certifying Authority. QSign then adds its ML-DSA signature on top for quantum safety."],
        ["<b>European Union</b><br/>eIDAS / eIDAS 2", "An <i>advanced</i> electronic signature (AdES) with MFA-verified signers and a full audit trail.",
         "A <i>qualified</i> signature (QES) needs a Qualified Trust Service Provider on the EU Trusted List. Integrate a QTSP's remote signing service."],
    ], [32 * mm, 64 * mm, CONTENT_W - 96 * mm]))
    s.append(callout("Why the hybrid design helps legally",
                     "Licensed providers in India and the EU still issue RSA and elliptic-curve certificates. QSign can carry their "
                     "legally recognised classical signature together with its own ML-DSA signature: valid under today's rules, "
                     "and protected against tomorrow's quantum attacks.", AMBER, AMBER_BG))
    s.append(P("Data location: deploy in Mumbai (ap-south-1) or Hyderabad (ap-south-2) for Indian customers (DPDP Act 2023), "
               "Frankfurt (eu-central-1) for EU customers (GDPR), and a US region or GovCloud for US customers. "
               "The full analysis is in <b>docs/COMPLIANCE.md</b>.", small))
    s.append(PageBreak())

    # Part 9
    s += chapter(9, "Running it", "From an empty AWS account to a customer's first signed envelope.")
    s.append(table([
        ["Step", "Command or action"],
        ["1  Deploy", "<font name='Mono' size='8'>cd infra &amp;&amp; sam build &amp;&amp; sam deploy --guided --stack-name qsign</font><br/>Use ArchiveRetentionDays = 1 while testing; locked records cannot be deleted early."],
        ["2  Email", "Verify your sending address in Amazon SES and connect Cognito to SES for invitation emails."],
        ["3  First customer", "<font name='Mono' size='8'>scripts/create-org-admin.sh qsign acme admin@acme.com \"Asha Admin\"</font>"],
        ["4  First sign-in", "The admin opens the App URL, sets a password and scans the authenticator key."],
        ["5  Invite and send", "The admin invites colleagues from the Admin tab; anyone can send an envelope."],
        ["6  Publish keys", "Share the fingerprints from /api/keys on your website so customers and courts can confirm them."],
    ], [32 * mm, CONTENT_W - 32 * mm]))
    s.append(P("Operating it", h2))
    s += bullets([
        "<b>Alarms</b> email your team when signing errors, throttling or server errors appear.",
        "<b>Key rotation</b>: create new KMS keys, list the old fingerprints as retired, and old signatures stay trusted.",
        "<b>Backups</b>: DynamoDB point-in-time recovery (35 days) plus write-once S3 copies of every signature.",
        "<b>Containers</b>: the same code runs on ECS, EKS or on-premises with built-in token checking.",
    ])
    s.append(P("What comes next", h2))
    s.append(table([
        ["Roadmap item", "Benefit"],
        ["Trusted timestamps (RFC 3161)", "Independent proof of <i>when</i> a document was signed."],
        ["Signatures inside PDFs (PAdES)", "Adobe Reader and similar tools show the signature directly."],
        ["India eSign / EU QTSP integration", "Highest legal recognition in India and the EU."],
        ["ML-DSA certificates from AWS Private CA", "Keys formally tied to your company name."],
        ["CloudFront + AWS WAF", "Web application firewall for internet-facing deployments."],
    ], [70 * mm, CONTENT_W - 70 * mm]))
    s.append(Spacer(1, 10))
    s.append(P("Source code, tests and detailed guides: README.md, docs/OPERATIONS.md, docs/API.md, docs/COMPLIANCE.md and "
               "SECURITY.md in this repository. Regenerate this PDF with <font name='Mono' size='8'>python3 docs/explainer/build_pdf.py</font>.", small))

    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN,
                            bottomMargin=20 * mm, title="QSign: how quantum-safe e-signatures work",
                            author="Justivia Legal Ventures LLP", subject="QSign architecture and operation explained",
                            keywords="QSign, ML-DSA, FIPS 204, post-quantum, e-signature, AWS KMS")
    doc.build(s, onFirstPage=on_cover, onLaterPages=on_page)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    build()
