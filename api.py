#!/usr/bin/env python3
"""
AikenGuard API v0.5
FastAPI backend pour audit de smart contracts Aiken
Couche 1 : analyse statique (21 règles)
Couche 2 : LLM Groq + RAG Cardano
Support multilingue : EN / FR / ES
"""

# ── Chargement des secrets AVANT tout import qui en dépend ─────
from dotenv import load_dotenv
import os
load_dotenv("/home/ubuntu/.env_aikenguard")

# ── Imports standards ──────────────────────────────────────────
import subprocess
import json
import tempfile
import shutil
import traceback
from pathlib import Path
from datetime import datetime

# ── Imports tiers ──────────────────────────────────────────────
import resend
from fastapi import FastAPI, UploadFile, File, Form, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

# ── Configuration ──────────────────────────────────────────────
app = FastAPI(title="AikenGuard API", version="0.5")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

WALLET         = "addr1qx3xa7e02hntguhplrl97ynp6l79pvkqkdcd2q4uwe3w2yn6z7pp6gdm3am8252g5rk2lp4a3ew9eryqss8te68n2x8qgmtg8l"
AIKENGUARD_PY  = "/home/ubuntu/AikenGuard/Aikenguard.py"
AIKENGUARD_LLM = "/home/ubuntu/AikenGuard/aikenguard_llm.py"
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM     = os.environ.get("EMAIL_FROM", "audit@aikenguard.io")
PENDING_DIR    = Path("/home/ubuntu/pending_audits")
PENDING_DIR.mkdir(exist_ok=True)

# Validation des secrets au démarrage
if not RESEND_API_KEY:
    print("⚠️  ATTENTION: RESEND_API_KEY non trouvée dans .env_aikenguard")

# Langues supportées
SUPPORTED_LANGS = {"en", "fr", "es"}

# ── Templates email multilingues ───────────────────────────────
EMAIL_TEMPLATES = {
    "en": {
        "greeting":      "Hello,",
        "intro":         "Your AikenGuard v0.5 audit is complete!",
        "summary_title": "AUDIT SUMMARY",
        "files":         "Files",
        "plan":          "Plan",
        "score":         "Score",
        "critical":      "CRITICAL",
        "high":          "HIGH",
        "total":         "Total findings",
        "mainnet":       "Mainnet",
        "standard":      "Standard",
        "date":          "Date",
        "model":         "Model",
        "static_only":   "Static analysis only",
        "layer1_title":  "LAYER 1 - STATIC ANALYSIS (21 rules)",
        "layer2_title":  "LAYER 2 - AI ANALYSIS + RAG CARDANO",
        "no_vulns":      "  No vulnerabilities detected",
        "ready":         "Ready for mainnet",
        "needs_fix":     "Corrections recommended before mainnet",
        "footer":        "For questions reply to this email.",
        "costs_title":   "ESTIMATED EXECUTION COSTS",
        "costs_cpu":     "CPU",
        "costs_memory":  "Memory",
        "costs_validators": "Validators",
        "costs_decoding": "Data decoding",
        "costs_refinputs": "Reference inputs",
        "costs_risk":    "risk(s) detected",
        "costs_ok":      "OK",
        "costs_no_risk": "  No cost risk detected",
        # Confirmation email
        "confirm_subject": "AikenGuard -- Contracts received! Send {plan} ADA",
        "confirm_body":    "Files: {files}\nSend {plan} ADA to:\n{wallet}\nInclude your email in metadata.",
    },
    "fr": {
        "greeting":      "Bonjour,",
        "intro":         "Votre audit AikenGuard v0.5 est complété !",
        "summary_title": "RÉSUMÉ DE L'AUDIT",
        "files":         "Fichiers",
        "plan":          "Plan",
        "score":         "Score",
        "critical":      "CRITIQUE",
        "high":          "ÉLEVÉ",
        "total":         "Total des findings",
        "mainnet":       "Mainnet",
        "standard":      "Standard",
        "date":          "Date",
        "model":         "Modèle",
        "static_only":   "Analyse statique uniquement",
        "layer1_title":  "COUCHE 1 - ANALYSE STATIQUE (21 règles)",
        "layer2_title":  "COUCHE 2 - ANALYSE IA + RAG CARDANO",
        "no_vulns":      "  Aucune vulnérabilité détectée",
        "ready":         "Prêt pour le mainnet",
        "needs_fix":     "Corrections recommandées avant mainnet",
        "footer":        "Pour toute question, répondez à ce courriel.",
        "costs_title":   "ESTIMATION DES COÛTS D'EXÉCUTION",
        "costs_cpu":     "CPU",
        "costs_memory":  "Mémoire",
        "costs_validators": "Validateurs",
        "costs_decoding": "Décodage Data",
        "costs_refinputs": "Reference inputs",
        "costs_risk":    "risque(s) détecté(s)",
        "costs_ok":      "OK",
        "costs_no_risk": "  Aucun risque de coût détecté",
        # Confirmation email
        "confirm_subject": "AikenGuard -- Contrats reçus ! Envoyez {plan} ADA",
        "confirm_body":    "Fichiers : {files}\nEnvoyez {plan} ADA à :\n{wallet}\nIncluez votre courriel dans les métadonnées.",
    },
    "es": {
        "greeting":      "Hola,",
        "intro":         "¡Su auditoría AikenGuard v0.5 está completa!",
        "summary_title": "RESUMEN DE LA AUDITORÍA",
        "files":         "Archivos",
        "plan":          "Plan",
        "score":         "Puntuación",
        "critical":      "CRÍTICO",
        "high":          "ALTO",
        "total":         "Total de hallazgos",
        "mainnet":       "Mainnet",
        "standard":      "Estándar",
        "date":          "Fecha",
        "model":         "Modelo",
        "static_only":   "Solo análisis estático",
        "layer1_title":  "CAPA 1 - ANÁLISIS ESTÁTICO (21 reglas)",
        "layer2_title":  "CAPA 2 - ANÁLISIS IA + RAG CARDANO",
        "no_vulns":      "  No se detectaron vulnerabilidades",
        "ready":         "Listo para mainnet",
        "needs_fix":     "Correcciones recomendadas antes de mainnet",
        "footer":        "Para preguntas, responda a este correo.",
        "costs_title":   "ESTIMACIÓN DE COSTOS DE EJECUCIÓN",
        "costs_cpu":     "CPU",
        "costs_memory":  "Memoria",
        "costs_validators": "Validadores",
        "costs_decoding": "Decodificación de datos",
        "costs_refinputs": "Reference inputs",
        "costs_risk":    "riesgo(s) detectado(s)",
        "costs_ok":      "OK",
        "costs_no_risk": "  Sin riesgos de costo detectados",
        # Confirmation email
        "confirm_subject": "AikenGuard -- ¡Contratos recibidos! Envíe {plan} ADA",
        "confirm_body":    "Archivos: {files}\nEnvíe {plan} ADA a:\n{wallet}\nIncluya su correo en los metadatos.",
    },
}


def normalize_lang(lang):
    """Valide et normalise la langue. Retombe sur 'en' si invalide."""
    lang = (lang or "en").lower().strip()
    if lang not in SUPPORTED_LANGS:
        return "en"
    return lang


# ── Gestion des audits en attente ──────────────────────────────
def save_pending(email, files_data, plan, lang="en"):
    """Sauvegarde un audit en attente de paiement."""
    lang = normalize_lang(lang)
    safe = email.replace("@", "_at_").replace(".", "_")
    d = PENDING_DIR / safe
    d.mkdir(exist_ok=True)
    for fname, fc in files_data.items():
        (d / fname).write_bytes(fc)
    (d / "meta.json").write_text(json.dumps({
        "email":     email,
        "plan":      plan,
        "lang":      lang,
        "timestamp": datetime.now().isoformat(),
        "files":     list(files_data.keys()),
    }))
    print(f"Audit sauvegarde: {d}")


def find_pending_by_amount(lovelaces):
    """Cherche un audit pending dont le plan correspond au montant payé (±5 ADA)."""
    for d in PENDING_DIR.iterdir():
        mp = d / "meta.json"
        if not mp.exists():
            continue
        try:
            meta = json.loads(mp.read_text())
            if abs(lovelaces - int(meta["plan"])) <= 5:
                files = {f.name: f.read_bytes() for f in d.glob("*.ak")}
                return meta["email"], files, meta["plan"], meta.get("lang", "en")
        except Exception as e:
            print(f"find_pending error pour {d}: {e}")
    return None, None, None, "en"


def delete_pending(email):
    """Supprime un audit pending après traitement."""
    d = PENDING_DIR / email.replace("@", "_at_").replace(".", "_")
    if d.exists():
        shutil.rmtree(d)
        print(f"Audit supprime: {d}")


# ── Email ──────────────────────────────────────────────────────
def send_email(to, subject, body):
    """Envoie un email via Resend."""
    resend.api_key = RESEND_API_KEY
    resend.Emails.send({
        "from":    EMAIL_FROM,
        "to":      to,
        "subject": subject,
        "text":    body,
    })
    print(f"Email envoye a {to}")


def build_report_email(email, files_list, plan, score, findings, all_risks,
                       nb_crit, nb_high, llm_model, lang):
    """Construit le corps du rapport email dans la langue demandée."""
    lang = normalize_lang(lang)
    t    = EMAIL_TEMPLATES[lang]

    # Liste Layer 1 (analyse statique)
    ft = "".join(
        f"\n  [{f.get('severity')}] {f.get('rule_id')} -- {f.get('title')}\n  -> {f.get('recommendation','')[:100]}\n"
        for f in findings[:10]
    )

    # Liste Layer 2 (LLM + RAG)
    lt = "".join(
        f"\n  [{r.get('severity')}] {r.get('title')}\n  {r.get('description','')[:150]}\n  -> {r.get('recommendation','')[:100]}\n"
        for r in all_risks[:5]
    )

    # Verdict mainnet
    mainnet_ready = score >= 80 and nb_crit == 0
    ms = t["ready"] if mainnet_ready else t["needs_fix"]

    # Section couche 2 (seulement si findings IA)
    layer2_section = f"\n{t['layer2_title']}\n{lt}" if all_risks else ""

    # Section coûts (AK-022a-e)
    ak022_findings = [f for f in findings if f.get('rule_id', '').startswith('AK-022')]
    cpu_count        = len([f for f in ak022_findings if f.get('rule_id') == 'AK-022a'])
    memory_count     = len([f for f in ak022_findings if f.get('rule_id') == 'AK-022b'])
    validators_count = len([f for f in ak022_findings if f.get('rule_id') == 'AK-022c'])
    decoding_count   = len([f for f in ak022_findings if f.get('rule_id') == 'AK-022d'])
    refinputs_count  = len([f for f in ak022_findings if f.get('rule_id') == 'AK-022e'])

    def fmt_cost(count):
        if count == 0:
            return f"✅ {t['costs_ok']}"
        return f"⚠️  {count} {t['costs_risk']}"

    if ak022_findings:
        costs_section = f"""
💰 {t['costs_title']}
   {t['costs_cpu']:11s}: {fmt_cost(cpu_count)}
   {t['costs_memory']:11s}: {fmt_cost(memory_count)}
   {t['costs_validators']:11s}: {fmt_cost(validators_count)}
   {t['costs_decoding']:11s}: {fmt_cost(decoding_count)}
   {t['costs_refinputs']:11s}: {fmt_cost(refinputs_count)}
"""
    else:
        costs_section = f"""
💰 {t['costs_title']}
{t['costs_no_risk']}
"""

    body = f"""{t['greeting']}

{t['intro']}

{t['summary_title']}
{t['files']}    : {files_list}
{t['plan']}     : {plan} ADA
{t['score']}    : {score}/100
{t['critical']} : {nb_crit}
{t['high']}     : {nb_high}
{t['total']}    : {len(findings) + len(all_risks)}
{t['mainnet']}  : {ms}
{t['standard']} : CIP-0052
{t['date']}     : {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}
{costs_section}
{t['layer1_title']}
{ft if ft else t['no_vulns']}{layer2_section}

{t['footer']}
AikenGuard v0.5 -- https://aikenguard.io -- audit@aikenguard.io"""

    return body


# ── Audit complet ──────────────────────────────────────────────
def run_full_audit(email, files_data, plan, lang="en"):
    """Exécute l'audit complet (Couche 1 + Couche 2) et envoie le rapport par email."""
    lang = normalize_lang(lang)
    print(f"Audit lance pour {email} -- plan {plan} ADA -- lang {lang}")

    with tempfile.TemporaryDirectory() as tmp:
        # Écriture des fichiers .ak dans le dossier temporaire
        for fname, fc in files_data.items():
            Path(f"{tmp}/{fname}").write_bytes(fc)

        # ── COUCHE 1 — Analyse statique ────────────────────────
        report_path = f"{tmp}/report.json"
        try:
            l1 = subprocess.run(
                ["python3", AIKENGUARD_PY, tmp, report_path, lang],
                capture_output=True, text=True, timeout=300,
            )
            if l1.returncode != 0:
                print(f"Couche 1 returncode: {l1.returncode}")
                if l1.stderr:
                    print(f"Couche 1 stderr:\n{l1.stderr}")
        except Exception as e:
            print(f"Erreur Couche 1: {e}")

        try:
            report = json.loads(Path(report_path).read_text())
        except Exception:
            report = {"score": 0, "findings": [], "project": "Unknown"}

        score    = report.get("score", 0)
        findings = report.get("findings", [])
        nb_crit  = len([f for f in findings if f.get("severity") == "CRITICAL"])
        nb_high  = len([f for f in findings if f.get("severity") == "HIGH"])

        # ── COUCHE 2 — LLM + RAG ───────────────────────────────
        llm_risks    = []
        llm_findings = []
        llm_model    = None

        # Tous les plans payants (10 ADA et plus) ont accès à la couche 2
        try:
            plan_int = int(plan)
        except (ValueError, TypeError):
            plan_int = 0

        if plan_int >= 279:
            llm_model = "qwen/qwen3-32b"
        elif plan_int >= 10:
            llm_model = "qwen/qwen3-32b"

        if llm_model:
            try:
                llm_path = f"{tmp}/report_llm.json"
                print(f"LLM subprocess: python3 {AIKENGUARD_LLM} {tmp} {llm_path} {llm_model} {lang}")
                result = subprocess.run(
                    ["python3", AIKENGUARD_LLM, tmp, llm_path, llm_model, lang],
                    capture_output=True, text=True, timeout=1200,
                )
                print(f"LLM returncode: {result.returncode}")
                if result.stdout:
                    print(f"LLM stdout:\n{result.stdout}")
                if result.stderr:
                    print(f"LLM stderr:\n{result.stderr}")
                if not Path(llm_path).exists():
                    print(f"LLM ERROR: {llm_path} n'a pas ete cree par le subprocess")
                    raise FileNotFoundError(f"{llm_path} not created")

                llm_data     = json.loads(Path(llm_path).read_text())
                llm_findings = llm_data.get("layer2_findings", [])
                llm_risks    = llm_data.get("multi_contract_risks", [])
                if llm_data.get("score"):
                    score = llm_data["score"]
            except Exception as e:
                print(f"LLM error: {e}")
                traceback.print_exc()

        # ── Recompter CRITICAL/HIGH avec couche 2 incluse ──────
        all_findings = findings + llm_findings
        nb_crit = len([f for f in all_findings if f.get("severity") == "CRITICAL"])
        nb_high = len([f for f in all_findings if f.get("severity") == "HIGH"])

        all_risks  = llm_findings + llm_risks
        files_list = ", ".join(files_data.keys())

        # ── Construction et envoi de l'email rapport ───────────
        body = build_report_email(
            email=email,
            files_list=files_list,
            plan=plan,
            score=score,
            findings=findings,
            all_risks=all_risks,
            nb_crit=nb_crit,
            nb_high=nb_high,
            llm_model=llm_model,
            lang=lang,
        )

        # Sujet en anglais (universel)
        subject = f"AikenGuard Audit -- Score {score}/100 -- {files_list}"

        try:
            send_email(email, subject, body)
        except Exception as e:
            print(f"Erreur envoi rapport client: {e}")
            traceback.print_exc()

        # Notification interne (toujours en anglais pour ton suivi)
        try:
            send_email(
                EMAIL_FROM,
                f"Audit termine -- {email} -- {plan} ADA -- Score {score}/100",
                f"Client: {email}\nPlan: {plan} ADA\nLang: {lang}\nScore: {score}/100",
            )
        except Exception:
            pass


# ── Routes API ─────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "AikenGuard v0.5", "detecteurs": 21, "ctf": "100%"}


@app.get("/health")
def health():
    return {
        "status":         "ok",
        "version":        "0.5",
        "pending_audits": len(list(PENDING_DIR.iterdir())),
        "languages":      sorted(SUPPORTED_LANGS),
    }


@app.post("/submit")
async def submit(
    background_tasks: BackgroundTasks,
    email: str = Form(...),
    plan:  str = Form(...),
    lang:  str = Form(default="en"),
    files: list[UploadFile] = File(...),
):
    """Reçoit les fichiers .ak du client et envoie l'email de confirmation."""
    lang = normalize_lang(lang)

    files_data = {f.filename: await f.read() for f in files if f.filename.endswith(".ak")}
    if not files_data:
        return {"error": "Aucun fichier .ak"}

    save_pending(email, files_data, plan, lang)

    # Email de confirmation dans la langue du client
    t = EMAIL_TEMPLATES[lang]
    try:
        send_email(
            email,
            t["confirm_subject"].format(plan=plan),
            t["confirm_body"].format(
                files=", ".join(files_data.keys()),
                plan=plan,
                wallet=WALLET,
            ),
        )
    except Exception as e:
        print(f"Erreur confirmation: {e}")

    print(f"Soumission -- {email} -- {len(files_data)} fichiers -- {plan} ADA -- lang {lang}")
    return {
        "status":  "ok",
        "message": f"Contracts received! Send {plan} ADA.",
        "files":   list(files_data.keys()),
        "lang":    lang,
        "wallet":  WALLET,
    }


@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """Reçoit les notifications de paiement de Blockfrost."""
    try:
        payload = await request.json()

        # Vérification défensive de la structure du payload
        if "payload" not in payload or not payload["payload"]:
            print("Webhook: payload vide")
            return {"status": "ok"}

        for tx in payload["payload"]:
            for output in tx.get("outputs", []):
                if output.get("address") != WALLET:
                    continue

                amount_list = output.get("amount", [])
                if not amount_list:
                    continue

                try:
                    lovelaces = int(amount_list[0]["quantity"]) / 1_000_000
                except (KeyError, ValueError, TypeError) as e:
                    print(f"Webhook: amount invalide -- {e}")
                    continue

                print(f"Paiement recu : {lovelaces} ADA")
                client_email, client_files, client_plan, client_lang = find_pending_by_amount(lovelaces)

                if client_email:
                    print(f"Client identifie : {client_email} -- lang {client_lang}")
                    delete_pending(client_email)
                    background_tasks.add_task(
                        run_full_audit,
                        client_email, client_files, client_plan, client_lang,
                    )
                else:
                    print(f"Paiement {lovelaces} ADA -- client non identifie")
                    try:
                        send_email(
                            EMAIL_FROM,
                            f"Paiement {lovelaces} ADA -- non identifie",
                            "Verifier manuellement.",
                        )
                    except Exception:
                        pass
    except Exception as e:
        print(f"Webhook error: {e}")
        traceback.print_exc()

    return {"status": "ok"}

