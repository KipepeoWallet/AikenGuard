#!/usr/bin/env python3
"""AikenGuard v0.4 — API FastAPI complète"""

from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
import subprocess, json, tempfile, smtplib
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = FastAPI(title="AikenGuard API", version="0.4")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

WALLET        = "addr1qx3xa7e02hntguhplrl97ynp6l79pvkqkdcd2q4uwe3w2yn6z7pp6gdm3am8252g5rk2lp4a3ew9eryqss8te68n2x8qgmtg8l"
AIKENGUARD_PY = "/home/ubuntu/AikenGuard/Aikenguard.py"
SMTP_SERVER   = "ssl0.ovh.net"
SMTP_PORT     = 465
EMAIL_FROM    = "audit@aikenguard.io"
EMAIL_PASS    = "Aikenmail2026"


@app.get("/")
def root():
    return {
        "status": "AikenGuard v0.4 en ligne",
        "serveur": "OVH Beauharnois QC",
        "version": "0.4"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/submit")
async def submit(
    email: str = Form(...),
    plan: str = Form(...),
    files: list[UploadFile] = File(...)
):
    """Reçoit les fichiers .ak + email → lance l'audit → envoie confirmation"""

    with tempfile.TemporaryDirectory() as tmp:
        # Sauvegarder les fichiers
        ak_files = []
        for f in files:
            if f.filename.endswith(".ak"):
                content = await f.read()
                path = f"{tmp}/{f.filename}"
                Path(path).write_bytes(content)
                ak_files.append(f.filename)

        if not ak_files:
            return {"error": "Aucun fichier .ak trouvé"}

        # Lancer AikenGuard Couche 1
        report_path = f"{tmp}/report.json"
        subprocess.run(
            ["python3", AIKENGUARD_PY, tmp, report_path],
            capture_output=True, text=True
        )

        # Lire le rapport
        try:
            report = json.loads(Path(report_path).read_text())
            score = report.get("score", 0)
            findings = len(report.get("findings", []))
        except:
            score = 0
            findings = 0

        # Envoyer email de confirmation au client
        try:
            send_confirmation(email, ak_files, plan, score, findings)
        except Exception as e:
            print(f"Email error: {e}")

        # Envoyer notification à audit@aikenguard.io
        try:
            send_notification(email, ak_files, plan, score)
        except Exception as e:
            print(f"Notification error: {e}")

        print(f"Audit soumis — {email} — {len(ak_files)} fichiers — Plan {plan} ADA — Score {score}/100")
        return {
            "status": "ok",
            "message": f"Contracts received! Send {plan} ADA to complete your audit.",
            "files": ak_files,
            "score_preview": score
        }


def send_confirmation(to_email, files, plan, score, findings):
    """Envoie email de confirmation au client"""
    msg = MIMEMultipart()
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = f"AikenGuard — Contracts received! Send {plan} ADA to proceed"

    body = f"""
Hello,

We have received your Aiken smart contracts for audit.

Files received : {", ".join(files)}
Plan selected  : {plan} ADA
Preview score  : {score}/100 ({findings} findings)

To complete your audit, please send {plan} ADA to:
{WALLET}

Once payment is confirmed, your full PDF report (CIP-0052) will be sent to this email within 30 minutes.

---
AikenGuard v0.4
https://aikenguard.io
audit@aikenguard.io
    """
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(EMAIL_FROM, EMAIL_PASS)
        server.sendmail(EMAIL_FROM, to_email, msg.as_string())
    print(f"Confirmation envoyée à {to_email}")


def send_notification(client_email, files, plan, score):
    """Envoie notification interne à audit@aikenguard.io"""
    msg = MIMEMultipart()
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_FROM
    msg["Subject"] = f"🔔 Nouveau client : {client_email} — Plan {plan} ADA"

    body = f"""
Nouveau client en attente de paiement !

Client  : {client_email}
Plan    : {plan} ADA
Fichiers: {", ".join(files)}
Score   : {score}/100
    """
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(EMAIL_FROM, EMAIL_PASS)
        server.sendmail(EMAIL_FROM, EMAIL_FROM, msg.as_string())


@app.post("/webhook")
async def webhook(request: Request):
    try:
        payload = await request.json()
        outputs = payload["payload"][0]["outputs"]
        for output in outputs:
            if output["address"] == WALLET:
                amount = int(output["amount"][0]["quantity"])
                lovelaces = amount / 1_000_000
                print(f"Paiement recu : {lovelaces} ADA")
    except Exception as e:
        print(f"Webhook error: {e}")
    return {"status": "ok"}
