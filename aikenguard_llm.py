#!/usr/bin/env python3
"""
AikenGuard v0.5 — Couche 2 LLM + RAG Cardano Expert
Utilise Groq API (Qwen3 32B) — ultra rapide et quasi gratuit

Usage: python3 aikenguard_llm.py <dossier> <output.json> [model] [lang]
  lang : en (default) | fr | es
"""

import os
import sys
import json
import re
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer
from groq import Groq
from dotenv import load_dotenv

# ── Chargement des secrets depuis .env_aikenguard ──────────────
load_dotenv("/home/ubuntu/.env_aikenguard")

# ── Configuration ──────────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
MODEL_PRO    = "qwen/qwen3-32b"
MODEL_CERT   = "llama-3.3-70b-versatile"
DB_PATH      = "/home/ubuntu/cardano-rag"
EMBED_MODEL  = "all-MiniLM-L6-v2"
RAG_RESULTS  = 5

if not GROQ_API_KEY:
    print("ERREUR: GROQ_API_KEY non trouvée dans /home/ubuntu/.env_aikenguard")
    sys.exit(1)

# ── Mapping des langues ────────────────────────────────────────
LANG_NAMES = {
    "en": "English",
    "fr": "French (français)",
    "es": "Spanish (español)",
}

LANG_INSTRUCTIONS = {
    "en": "Respond in English.",
    "fr": "Réponds entièrement en français. Tous les champs textuels du JSON (title, description, recommendation, overall_assessment, verdict) doivent être en français.",
    "es": "Responde completamente en español. Todos los campos de texto del JSON (title, description, recommendation, overall_assessment, verdict) deben estar en español.",
}

VERDICT_TRANSLATIONS = {
    "en": {"ready": "Ready for Audit", "needs_fix": "Needs fixes before audit"},
    "fr": {"ready": "Prêt pour audit",  "needs_fix": "Corrections requises avant audit"},
    "es": {"ready": "Listo para auditoría", "needs_fix": "Requiere correcciones antes de auditoría"},
}


def extract_code_only(content):
    """Filtre le code Aiken — supprime commentaires et documentation"""
    lines = content.split("\n")
    code_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("///"):
            continue
        if stripped.startswith("//"):
            continue
        code_lines.append(line)
    cleaned = "\n".join(code_lines)
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    return cleaned.strip()


def get_rag_context(query, n=RAG_RESULTS):
    """Cherche dans ChromaDB les passages les plus pertinents"""
    try:
        client     = chromadb.PersistentClient(path=DB_PATH)
        collection = client.get_collection("cardano_knowledge")
        model      = SentenceTransformer(EMBED_MODEL)
        embedding  = model.encode(query).tolist()
        results    = collection.query(
            query_embeddings=[embedding],
            n_results=n
        )
        parts = []
        for i, doc in enumerate(results["documents"][0]):
            src = results["metadatas"][0][i].get("source", "")
            src_short = "/".join(src.split("/")[-2:])
            parts.append(f"[{src_short}]\n{doc[:400]}")
        return "\n\n---\n\n".join(parts)
    except Exception as e:
        print(f"  RAG warning: {e}")
        return ""


def analyze_security(contracts, rag_context, model, lang="en"):
    """Analyse de sécurité pure avec Groq API.

    Args:
        contracts:   dict {filename: content} des fichiers .ak
        rag_context: str  contexte RAG ChromaDB
        model:       str  nom du modèle Groq
        lang:        str  'en' | 'fr' | 'es' — langue du rapport
    """

    # Normaliser et valider la langue
    lang = (lang or "en").lower()
    if lang not in LANG_INSTRUCTIONS:
        lang = "en"

    lang_full        = LANG_NAMES[lang]
    lang_instruction = LANG_INSTRUCTIONS[lang]

    filtered_code = {}
    for name, content in contracts.items():
        filtered_code[name] = extract_code_only(content)

    code_section = ""
    for name, code in filtered_code.items():
        code_section += f"\n\n=== {name} ===\n{code[:3000]}"

    system_prompt = f"""You are a specialized Cardano eUTxO smart contract security analyzer.

LANGUAGE REQUIREMENT: {lang_instruction}
All textual fields in your JSON output MUST be written in {lang_full}.
Only the JSON keys themselves stay in English (severity, title, description, etc.).
Severity values stay in English: CRITICAL, HIGH, MEDIUM, LOW.

Absolute rules you must always follow:
- You analyze ONLY the Aiken code provided.
- You never talk about internet, APIs, emails, social networks or anything outside this contract.
- You never generate executable code, you never run system commands.
- You never respond outside the requested report format.
- You stay 100% focused on detecting security vulnerabilities.

Your task: Analyze the provided Aiken code and produce a structured report containing ONLY:
- The global risk score (0-100)
- The list of detected vulnerabilities classified by criticality (Critical, High, Medium, Low)
- For each vulnerability: name, line number, short explanation, and fix suggestion
- A clear verdict

Respond ONLY in valid JSON format. Do not put any text before or after the JSON."""

    verdict_ready    = VERDICT_TRANSLATIONS[lang]["ready"]
    verdict_needsfix = VERDICT_TRANSLATIONS[lang]["needs_fix"]

    user_prompt = f"""CARDANO SECURITY KNOWLEDGE BASE:
{rag_context if rag_context else "Not available."}

SECURITY PATTERNS TO DETECT:
1. Double satisfaction — same UTxO consumed multiple times
2. Datum hijacking — arbitrary datum injection
3. Missing datum continuity — state not carried forward
4. Cross-contract privilege escalation
5. Unrestricted minting — no policy enforcement
6. Missing beneficiary verification
7. Unsafe time bounds — upper_bound instead of lower_bound
8. Missing extra_signatories check
9. Free mint via list.find bypass
10. Multi-asset comparison bypass

AIKEN CODE TO ANALYZE (comments stripped):
{code_section}

Respond ONLY with this JSON structure (text fields in {lang_full}, keys and severity in English):
{{
  "score": 0-100,
  "verdict": "{verdict_ready}" or "{verdict_needsfix}",
  "overall_assessment": "2-3 sentences max in {lang_full}",
  "findings": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "short title in {lang_full}",
      "file": "filename.ak",
      "line": 1,
      "description": "precise technical description in {lang_full}",
      "recommendation": "exact fix in {lang_full}",
      "reference": "CIP or source if applicable"
    }}
  ],
  "multi_contract_risks": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "cross-contract risk title in {lang_full}",
      "affected_contracts": ["file1.ak", "file2.ak"],
      "description": "description in {lang_full}",
      "recommendation": "fix in {lang_full}"
    }}
  ]
}}

REMINDER: {lang_instruction}"""

    try:
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt}
            ],
            temperature=0.05,
            max_tokens=2000,
        )
        raw = response.choices[0].message.content or ""

        # Supprimer les balises de raisonnement et les fences markdown
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
        raw = re.sub(r"```json\s*", "", raw)
        raw = re.sub(r"```\s*", "", raw)
        raw = raw.strip()

        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(raw[start:end])
        else:
            return {
                "score": 0,
                "verdict": verdict_needsfix,
                "overall_assessment": raw[:300],
                "findings": [],
                "multi_contract_risks": []
            }
    except Exception as e:
        print(f"  Groq error: {e}")
        return {
            "score": 0,
            "verdict": verdict_needsfix,
            "overall_assessment": f"Analysis failed: {e}",
            "findings": [],
            "multi_contract_risks": []
        }


def run_llm_analysis(contracts_dir, output_path, model=MODEL_PRO, lang="en"):
    """Point d'entrée principal de la couche 2.

    Args:
        contracts_dir: str  dossier contenant les fichiers .ak
        output_path:   str  chemin du fichier JSON de sortie
        model:         str  nom du modèle Groq
        lang:          str  'en' | 'fr' | 'es' — langue du rapport
    """
    # Normaliser la langue
    lang = (lang or "en").lower()
    if lang not in LANG_INSTRUCTIONS:
        lang = "en"

    print(f"\nAikenGuard v0.5 — Couche 2 Groq API")
    print(f"  Modele    : {model}")
    print(f"  Langue    : {lang} ({LANG_NAMES[lang]})")
    print("=" * 45)

    contracts = {}
    for ak_file in Path(contracts_dir).glob("*.ak"):
        contracts[ak_file.name] = ak_file.read_text(encoding="utf-8", errors="ignore")

    if not contracts:
        print("  Aucun fichier .ak trouve")
        return {}

    print(f"  Contrats  : {list(contracts.keys())}")

    # Charger le rapport de la couche 1 si disponible
    layer1_path = output_path.replace(".json", "_layer1.json")
    layer1 = {}
    try:
        layer1 = json.loads(Path(layer1_path).read_text())
        print(f"  Couche 1  : {len(layer1.get('findings', []))} findings")
    except:
        print("  Couche 1  : rapport non disponible")

    # Récupérer le contexte RAG
    rag_query = f"Cardano Aiken eUTxO security vulnerability {' '.join(contracts.keys())}"
    rag = get_rag_context(rag_query)
    print(f"  RAG       : {'OK' if rag else 'non disponible'}")

    # Analyse Groq dans la langue demandée
    print(f"  Analyse   : en cours via Groq...")
    llm_result = analyze_security(contracts, rag, model, lang)

    # Fusion des findings couche 1 + couche 2
    findings_l1  = layer1.get("findings", [])
    findings_l2  = llm_result.get("findings", [])
    all_findings = findings_l1 + findings_l2

    score   = llm_result.get("score", layer1.get("score", 0))
    verdict = llm_result.get("verdict", VERDICT_TRANSLATIONS[lang]["needs_fix"])

    # Détection "ready for audit" indépendante de la langue
    mainnet_ready = verdict == VERDICT_TRANSLATIONS[lang]["ready"]

    report = {
        "files_scanned":       len(contracts),
        "model":               model,
        "language":            lang,
        "score":               score,
        "verdict":             verdict,
        "mainnet_ready":       mainnet_ready,
        "overall_assessment":  llm_result.get("overall_assessment", ""),
        "layer1_findings":     findings_l1,
        "layer2_findings":     findings_l2,
        "multi_contract_risks": llm_result.get("multi_contract_risks", []),
        "summary": {
            "critical":             len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "high":                 len([f for f in all_findings if f.get("severity") == "HIGH"]),
            "medium":               len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
            "low":                  len([f for f in all_findings if f.get("severity") == "LOW"]),
            "total":                len(all_findings),
            "multi_contract_risks": len(llm_result.get("multi_contract_risks", [])),
        },
        "rag_enabled": bool(rag),
    }

    Path(output_path).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"  Score     : {report['score']}/100")
    print(f"  Verdict   : {report['verdict']}")
    print(f"  Risques   : {report['summary']['multi_contract_risks']}")
    print(f"  Rapport   : {output_path}")
    return report


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 aikenguard_llm.py <dossier> <output.json> [model] [lang]")
        print(f"  Models : {MODEL_PRO} (Pro) | {MODEL_CERT} (Certified)")
        print(f"  Lang   : en (default) | fr | es")
        sys.exit(1)

    contracts_dir = sys.argv[1]
    output_path   = sys.argv[2]
    model         = sys.argv[3] if len(sys.argv) > 3 else MODEL_PRO
    lang          = sys.argv[4] if len(sys.argv) > 4 else "en"

    run_llm_analysis(contracts_dir, output_path, model, lang)
