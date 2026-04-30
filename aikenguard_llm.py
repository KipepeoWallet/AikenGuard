#!/usr/bin/env python3
"""
AikenGuard v0.5 — Couche 2 LLM + RAG Cardano Expert
Utilise Groq API (Qwen3 32B) — ultra rapide et quasi gratuit

Usage: python3 aikenguard_llm.py <dossier> <output.json> [model]
"""

import sys
import json
import re
from pathlib import Path
import chromadb
from sentence_transformers import SentenceTransformer
from groq import Groq

# ── Configuration ──────────────────────────────────────────────
GROQ_API_KEY = "VOTRE_CLE_GROQ_ICI"
MODEL_PRO    = "qwen/qwen3-32b"
MODEL_CERT   = "llama-3.3-70b-versatile"
DB_PATH      = "/home/ubuntu/cardano-rag"
EMBED_MODEL  = "all-MiniLM-L6-v2"
RAG_RESULTS  = 5


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


def analyze_security(contracts, rag_context, model):
    """Analyse de securite pure avec Groq API"""

    filtered_code = {}
    for name, content in contracts.items():
        filtered_code[name] = extract_code_only(content)

    code_section = ""
    for name, code in filtered_code.items():
        code_section += f"\n\n=== {name} ===\n{code[:3000]}"

    system_prompt = """You are a specialized Cardano eUTxO smart contract security analyzer.

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
- A clear conclusion: "Ready for Audit" or "Needs fixes before audit"

Respond ONLY in valid JSON format. Do not put any text before or after the JSON."""

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

Respond ONLY with this JSON structure:
{{
  "score": 0-100,
  "verdict": "Ready for Audit" or "Needs fixes before audit",
  "overall_assessment": "2-3 sentences max",
  "findings": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "short title",
      "file": "filename.ak",
      "line": 1,
      "description": "precise technical description",
      "recommendation": "exact fix",
      "reference": "CIP or source if applicable"
    }}
  ],
  "multi_contract_risks": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "cross-contract risk title",
      "affected_contracts": ["file1.ak", "file2.ak"],
      "description": "description",
      "recommendation": "fix"
    }}
  ]
}}"""

    try:
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.05,
            max_tokens=2000,
        )
        raw = response.choices[0].message.content or ""

        # Supprimer les balises de raisonnement
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
                "verdict": "Needs fixes before audit",
                "overall_assessment": raw[:300],
                "findings": [],
                "multi_contract_risks": []
            }
    except Exception as e:
        print(f"  Groq error: {e}")
        return {
            "score": 0,
            "verdict": "Needs fixes before audit",
            "overall_assessment": f"Analysis failed: {e}",
            "findings": [],
            "multi_contract_risks": []
        }


def run_llm_analysis(contracts_dir, output_path, model=MODEL_PRO):
    print(f"\nAikenGuard v0.5 — Couche 2 Groq API")
    print(f"  Modele    : {model}")
    print("=" * 45)

    contracts = {}
    for ak_file in Path(contracts_dir).glob("*.ak"):
        contracts[ak_file.name] = ak_file.read_text(encoding="utf-8", errors="ignore")

    if not contracts:
        print("  Aucun fichier .ak trouve")
        return {}

    print(f"  Contrats  : {list(contracts.keys())}")

    layer1_path = output_path.replace(".json", "_layer1.json")
    layer1 = {}
    try:
        layer1 = json.loads(Path(layer1_path).read_text())
        print(f"  Couche 1  : {len(layer1.get('findings', []))} findings")
    except:
        print("  Couche 1  : rapport non disponible")

    rag_query = f"Cardano Aiken eUTxO security vulnerability {' '.join(contracts.keys())}"
    rag = get_rag_context(rag_query)
    print(f"  RAG       : {'OK' if rag else 'non disponible'}")

    print(f"  Analyse   : en cours via Groq...")
    llm_result = analyze_security(contracts, rag, model)

    findings_l1 = layer1.get("findings", [])
    findings_l2 = llm_result.get("findings", [])
    all_findings = findings_l1 + findings_l2

    score = llm_result.get("score", layer1.get("score", 0))

    report = {
        "files_scanned": len(contracts),
        "model": model,
        "score": score,
        "verdict": llm_result.get("verdict", "Needs fixes before audit"),
        "mainnet_ready": llm_result.get("verdict", "") == "Ready for Audit",
        "overall_assessment": llm_result.get("overall_assessment", ""),
        "layer1_findings": findings_l1,
        "layer2_findings": findings_l2,
        "multi_contract_risks": llm_result.get("multi_contract_risks", []),
        "summary": {
            "critical": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "high":     len([f for f in all_findings if f.get("severity") == "HIGH"]),
            "medium":   len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
            "low":      len([f for f in all_findings if f.get("severity") == "LOW"]),
            "total":    len(all_findings),
            "multi_contract_risks": len(llm_result.get("multi_contract_risks", [])),
        },
        "rag_enabled": bool(rag),
    }

    Path(output_path).write_text(json.dumps(report, indent=2))
    print(f"  Score     : {report['score']}/100")
    print(f"  Verdict   : {report['verdict']}")
    print(f"  Risques   : {report['summary']['multi_contract_risks']}")
    print(f"  Rapport   : {output_path}")
    return report


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 aikenguard_llm.py <dossier> <output.json> [model]")
        print(f"  Models: {MODEL_PRO} (Pro) | {MODEL_CERT} (Certified)")
        sys.exit(1)

    contracts_dir = sys.argv[1]
    output_path   = sys.argv[2]
    model         = sys.argv[3] if len(sys.argv) > 3 else MODEL_PRO

    run_llm_analysis(contracts_dir, output_path, model)
