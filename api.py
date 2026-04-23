#!/usr/bin/env python3
"""AikenGuard v0.5 — API FastAPI complète avec boucle automatique"""

from fastapi import FastAPI, UploadFile, File, Form, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import subprocess, json, tempfile, smtplib, os, shutil
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

app = FastAPI(title="AikenGuard API", version="0.5")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# ── Configuration ──────────────────────────────────────────────
WALLET         = "addr1qx3xa7e02hntguhplrl97ynp6l79pvkqkdcd2q4uwe3w2yn6z7pp6gdm3am8252g5rk2lp4a3ew9eryqss8te68n2x8qgmtg8l"
AIKENGUARD_PY  = "/home/ubuntu/AikenGuard/Aikenguard.py"
AIKENGUARD_LLM = "/home/ubuntu/AikenGuard/aikenguard_llm.py"
SMTP_SERVER    = "ssl0.ovh.net"
SMTP_PORT      = 465
EMAIL_FROM     = "audit@aikenguard.io"
EMAIL_PASS     = "A!kenma!l"

# Stockage persistant sur disque — survive aux redémarrages
PENDING_DIR    = Path("/home/ubuntu/pending_audits")
PENDING_DIR.mkdir(exist_ok=True)


# ── Gestion des audits en attente — sur disque ─────────────────
def save_pending(email, files_data, plan):
    """Sauvegarde les fichiers en attente sur disque"""
    safe_email = email.replace("@", "_at_").replace(".", "_")
    audit_dir = PENDING_DIR / safe_email
    audit_dir.mkdir(exist_ok=True)

    # Sauvegarder les fichiers .ak
    for fname, fcontent in files_data.items():
        (audit_dir / fname).write_bytes(fcontent)

    # Sauvegarder les métadonnées
    meta = {
        "email": email,
        "plan": plan,
        "timestamp": datetime.now().isoformat(),
        "files": list(files_data.keys())
    }
    (audit_dir / "meta.json").write_text(json.dumps(meta))
    print(f"Audit sauvegarde sur disque: {audit_dir}")


def find_pending_by_amount(lovelaces):
    """Trouve un audit en attente par montant ADA"""
    for audit_dir in PENDING_DIR.iterdir():
        meta_path = audit_dir / "meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text())
            plan_amount = int(meta["plan"])
            # Tolérance de 5 ADA pour les frais
            if abs(lovelaces - plan_amount) <= 5:
                # Lire les fichiers .ak
                files_data = {}
                for ak_file in audit_dir.glob("*.ak"):
                    files_data[ak_file.name] = ak_file.read_bytes()
                return meta["email"], files_data, meta["plan"]
        except:
            pass
    return None, None, None


def delete_pending(email):
    """Supprime l'audit en attente après traitement"""
    safe_email = email.replace("@", "_at_").replace(".", "_")
    audit_dir = PENDING_DIR / safe_email
    if audit_dir.exists():
        shutil.rmtree(audit_dir)
        print(f"Audit supprime: {audit_dir}")


# ── Utilitaires email ──────────────────────────────────────────
def send_email(to, subject, body):
    msg = MIMEMultipart()
    msg["From"] = EMAIL_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(EMAIL_FROM, EMAIL_PASS)
        server.sendmail(EMAIL_FROM, to, msg.as_string())
    print(f"Email envoye a {to}")


# ── Pipeline d audit complet ───────────────────────────────────
def run_full_audit(email, files_data, plan):
    """Lance l audit complet et envoie le rapport par email"""
    print(f"Audit lance pour {email} — plan {plan} ADA")

    with tempfile.TemporaryDirectory() as tmp:
        # Sauvegarder les fichiers
        for fname, fcontent in files_data.items():
            Path(f"{tmp}/{fname}").write_bytes(fcontent)

        # Couche 1 — analyse statique
        report_path = f"{tmp}/report.json"
        subprocess.run(
            ["python3", AIKENGUARD_PY, tmp, report_path],
            capture_output=True, text=True
        )

        try:
            report = json.loads(Path(report_path).read_text())
        except:
            report = {"score": 0, "findings": [], "project": "Unknown"}

        score = report.get("score", 0)
        findings = report.get("findings", [])
        nb_critical = len([f for f in findings if f.get("severity") == "CRITICAL"])
        nb_high = len([f for f in findings if f.get("severity") == "HIGH"])

        # Couche 2 — LLM + RAG pour Pro et Certified
        llm_risks = []
        if int(plan) >= 179:
            try:
                llm_path = f"{tmp}/report_llm.json"
                subprocess.run(
                    ["python3", AIKENGUARD_LLM, tmp, llm_path],
                    capture_output=True, text=True, timeout=180
                )
                llm_data = json.loads(Path(llm_path).read_text())
                llm_risks = llm_data.get("multi_contract_risks", [])
            except:
                pass

        # Construire le rapport
        files_list = ", ".join(files_data.keys())
        findings_text = ""
        for f in findings[:10]:
            findings_text += f"\n  [{f.get('severity')}] {f.get('rule_id')} — {f.get('title')}"
            findings_text += f"\n  → {f.get('recommendation', '')[:100]}\n"

        llm_text = ""
        for r in llm_risks[:5]:
            llm_text += f"\n  [{r.get('severity')}] {r.get('title')}"
            llm_text += f"\n  {r.get('description', '')[:150]}"
            llm_text += f"\n  → {r.get('recommendation', '')[:100]}\n"

        mainnet = score >= 80 and nb_critical == 0
        mainnet_str = "Pret pour mainnet" if mainnet else "Corrections recommandees avant mainnet"

        body = f"""Bonjour,

Votre audit AikenGuard v0.5 est termine !

RESUME DE L AUDIT
Fichiers          : {files_list}
Plan              : {plan} ADA
Score securite    : {score}/100
CRITICAL          : {nb_critical}
HIGH              : {nb_high}
Total findings    : {len(findings)}
Mainnet           : {mainnet_str}
Standard          : CIP-0052
Date              : {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}

FINDINGS COUCHE 1 - ANALYSE STATIQUE (21 regles)
{findings_text if findings_text else "  Aucune vulnerabilite detectee"}

{"FINDINGS COUCHE 2 - ANALYSE IA + RAG CARDANO" if llm_risks else ""}
{llm_text}

Pour toute question, repondez a cet email.

AikenGuard v0.5 — 21 detecteurs — 100% CTF Vacuumlabs
https://aikenguard.io
audit@aikenguard.io"""

        try:
            send_email(
                email,
                f"AikenGuard Audit — Score {score}/100 — {files_list}",
                body
            )
            print(f"Rapport envoye a {email} — Score {score}/100")
        except Exception as e:
            print(f"Erreur envoi rapport: {e}")

        # Notification interne
        try:
            send_email(
                EMAIL_FROM,
                f"Audit termine — {email} — {plan} ADA — Score {score}/100",
                f"Client: {email}\nPlan: {plan} ADA\nScore: {score}/100"
            )
        except:
            pass


# ── Endpoints ──────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "status": "AikenGuard v0.5 en ligne",
        "detecteurs": 21,
        "ctf_detection": "100%",
        "rag": True
    }


@app.get("/health")
def health():
    pending = len(list(PENDING_DIR.iterdir()))
    return {"status": "ok", "version": "0.5", "pending_audits": pending}


@app.post("/submit")
async def submit(
    background_tasks: BackgroundTasks,
    email: str = Form(...),
    plan: str = Form(...),
    files: list[UploadFile] = File(...)
):
    """Reçoit les fichiers — sauvegarde sur disque — envoie confirmation"""
    files_data = {}
    for f in files:
        if f.filename.endswith(".ak"):
            files_data[f.filename] = await f.read()

    if not files_data:
        return {"error": "Aucun fichier .ak trouve"}

    # Sauvegarder sur disque — résiste aux redémarrages
    save_pending(email, files_data, plan)

    # Confirmation au client
    try:
        send_email(
            email,
            f"AikenGuard — Contrats recus ! Envoyez {plan} ADA",
            f"""Bonjour,

Vos contrats Aiken ont ete recus avec succes !

Fichiers recus : {", ".join(files_data.keys())}
Plan choisi    : {plan} ADA

Pour lancer votre audit, envoyez {plan} ADA a cette adresse :
{WALLET}

Important : Incluez votre email ({email}) dans les metadonnees.

Votre rapport PDF CIP-0052 sera envoye dans les 30 minutes.

AikenGuard v0.5
https://aikenguard.io"""
        )
    except Exception as e:
        print(f"Erreur confirmation: {e}")

    print(f"Soumission — {email} — {len(files_data)} fichiers — {plan} ADA — sauvegarde sur disque")

    return {
        "status": "ok",
        "message": f"Contrats recus ! Envoyez {plan} ADA pour lancer l audit.",
        "files": list(files_data.keys()),
        "wallet": WALLET
    }


@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """Reçoit Blockfrost — paiement detecte — lance audit"""
    try:
        payload = await request.json()
        outputs = payload["payload"][0]["outputs"]

        for output in outputs:
            if output["address"] == WALLET:
                amount = int(output["amount"][0]["quantity"])
                lovelaces = amount / 1_000_000
                print(f"Paiement recu : {lovelaces} ADA")

                # Chercher le client sur disque
                client_email, client_files, client_plan = find_pending_by_amount(lovelaces)

                if client_email:
                    print(f"Client identifie : {client_email} — {lovelaces} ADA")
                    delete_pending(client_email)
                    background_tasks.add_task(
                        run_full_audit,
                        client_email,
                        client_files,
                        client_plan
                    )
                else:
                    print(f"Paiement {lovelaces} ADA — client non identifie")
                    try:
                        send_email(
                            EMAIL_FROM,
                            f"Paiement recu {lovelaces} ADA — client non identifie",
                            f"Verifier manuellement les audits en attente.\nMontant: {lovelaces} ADA"
                        )
                    except:
                        pass

    except Exception as e:
        print(f"Webhook error: {e}")

    return {"status": "ok"}
