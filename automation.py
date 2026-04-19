#!/usr/bin/env python3
"""
AikenGuard v0.4 — Automation complète
Lit les emails → Lance l'audit → Envoie le rapport PDF

Usage: python3 automation.py
"""

import imaplib
import email
import smtplib
import subprocess
import json
import tempfile
import os
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import cm
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────
IMAP_SERVER   = "ssl0.ovh.net"
IMAP_PORT     = 993
SMTP_SERVER   = "ssl0.ovh.net"
SMTP_PORT     = 465
EMAIL_ADDRESS = "audit@aikenguard.io"
EMAIL_PASSWORD = os.environ.get("AIKENGUARD_EMAIL_PASSWORD", "")
AIKENGUARD_PY = "/home/ubuntu/AikenGuard/Aikenguard.py"
WALLET        = "addr1qx3xa7e02hntguhplrl97ynp6l79pvkqkdcd2q4uwe3w2yn6z7pp6gdm3am8252g5rk2lp4a3ew9eryqss8te68n2x8qgmtg8l"


# ── 1. Lire les emails entrants ────────────────────────────────
def fetch_audit_emails():
    """Récupère les emails non lus avec des fichiers .ak en pièce jointe"""
    results = []
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        mail.select("INBOX")

        _, messages = mail.search(None, "UNSEEN")
        for msg_id in messages[0].split():
            _, msg_data = mail.fetch(msg_id, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])

            sender = email.utils.parseaddr(msg["From"])[1]
            subject = msg.get("Subject", "Audit Request")
            ak_files = []

            for part in msg.walk():
                if part.get_filename() and part.get_filename().endswith(".ak"):
                    ak_files.append({
                        "filename": part.get_filename(),
                        "content": part.get_payload(decode=True)
                    })

            if ak_files:
                results.append({
                    "sender": sender,
                    "subject": subject,
                    "files": ak_files,
                    "msg_id": msg_id
                })
                # Marquer comme lu
                mail.store(msg_id, "+FLAGS", "\\Seen")

        mail.logout()
    except Exception as e:
        print(f"IMAP error: {e}")
    return results


# ── 2. Lancer AikenGuard ──────────────────────────────────────
def run_audit(ak_files):
    """Lance AikenGuard sur les fichiers .ak et retourne le rapport"""
    with tempfile.TemporaryDirectory() as tmp:
        # Sauvegarder les fichiers
        for f in ak_files:
            Path(f"{tmp}/{f['filename']}").write_bytes(f["content"])

        # Lancer AikenGuard Couche 1
        report_path = f"{tmp}/report.json"
        subprocess.run(
            ["python3", AIKENGUARD_PY, tmp, report_path],
            capture_output=True, text=True
        )

        try:
            return json.loads(Path(report_path).read_text())
        except:
            return {"error": "Audit failed", "score": 0, "findings": []}


# ── 3. Générer le rapport PDF ─────────────────────────────────
def generate_pdf(report, sender, output_path):
    """Génère un rapport PDF CIP-0052 professionnel"""
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Titre
    title_style = styles["Title"]
    story.append(Paragraph("🛡️ AikenGuard Security Audit Report", title_style))
    story.append(Paragraph("CIP-0052 Compliant", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    # Infos
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    info_data = [
        ["Project", report.get("project", "Unknown")],
        ["Date", date_str],
        ["Files scanned", str(report.get("files_scanned", 0))],
        ["Score", f"{report.get('score', 0)}/100"],
        ["Audited by", "AikenGuard v0.4 + Gemma 4"],
        ["Standard", "CIP-0052 Cardano Audit Guidelines"],
    ]
    info_table = Table(info_data, colWidths=[5*cm, 11*cm])
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0a0a0f")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#2EFFB5")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.5*cm))

    # Résumé
    story.append(Paragraph("Summary", styles["Heading2"]))
    summary = report.get("summary", {})
    summary_data = [
        ["Severity", "Count"],
        ["CRITICAL", str(summary.get("critical", 0))],
        ["HIGH", str(summary.get("high", 0))],
        ["MEDIUM", str(summary.get("medium", 0))],
        ["LOW", str(summary.get("low", 0))],
        ["TOTAL", str(summary.get("total", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[8*cm, 8*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a0a0f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5*cm))

    # Findings
    story.append(Paragraph("Findings", styles["Heading2"]))
    for f in report.get("findings", []):
        sev = f.get("severity", "LOW")
        sev_color = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF8800",
            "MEDIUM": "#0088FF",
            "LOW": "#888888"
        }.get(sev, "#888888")

        story.append(Paragraph(
            f'<font color="{sev_color}">[{sev}]</font> {f.get("rule_id")} — {f.get("title")}',
            styles["Heading3"]
        ))
        story.append(Paragraph(f'📄 {f.get("file", "")}:{f.get("line", "")}', styles["Normal"]))
        story.append(Paragraph(f.get("description", ""), styles["Normal"]))
        story.append(Paragraph(f'→ {f.get("recommendation", "")}', styles["Normal"]))
        story.append(Spacer(1, 0.3*cm))

    # Footer
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        f"Audited by AikenGuard v0.4 · aikenguard.io · {date_str}",
        styles["Normal"]
    ))
    story.append(Paragraph(
        f"Wallet: {WALLET[:20]}...{WALLET[-10:]}",
        styles["Normal"]
    ))

    doc.build(story)
    return output_path


# ── 4. Envoyer le rapport par email ───────────────────────────
def send_report(to_email, pdf_path, project_name, score):
    """Envoie le rapport PDF par email au client"""
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg["Subject"] = f"AikenGuard Audit Report — {project_name} — Score: {score}/100"

    body = f"""
Hello,

Your AikenGuard security audit is complete!

Project  : {project_name}
Score    : {score}/100
Standard : CIP-0052 Cardano Audit Guidelines

Please find your detailed PDF report attached.

If you have questions, reply to this email.

---
AikenGuard v0.4
https://aikenguard.io
Built by Kipepeo Wallet
    """
    msg.attach(MIMEText(body, "plain"))

    # Attacher le PDF
    with open(pdf_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="aikenguard_report.pdf"')
        msg.attach(part)

    # Envoyer
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())

    print(f"Rapport envoyé à {to_email}")


# ── 5. Pipeline complète ──────────────────────────────────────
def process_audit_request(sender, ak_files, subject="Audit"):
    """Pipeline complète : audit → PDF → email"""
    print(f"Audit pour {sender} — {len(ak_files)} fichiers")

    # Lancer l'audit
    report = run_audit(ak_files)
    score = report.get("score", 0)
    project = report.get("project", "Smart Contract")

    # Générer le PDF
    pdf_path = f"/tmp/aikenguard_report_{sender.replace('@','_')}.pdf"
    generate_pdf(report, sender, pdf_path)

    # Envoyer le rapport
    send_report(sender, pdf_path, project, score)

    # Nettoyer
    Path(pdf_path).unlink(missing_ok=True)
    print(f"Audit terminé — Score: {score}/100")
    return report


# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("AikenGuard Automation — en attente d'emails...")
    emails = fetch_audit_emails()

    if not emails:
        print("Aucun email d'audit en attente")
    else:
        for e in emails:
            process_audit_request(e["sender"], e["files"], e["subject"])
