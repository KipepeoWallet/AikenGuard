#!/usr/bin/env python3
"""
AikenGuard v0.4 — Couche 2 LLM + RAG Cardano Expert
Analyse multi-contrats avec contexte Cardano précis via ChromaDB

Usage: python3 aikenguard_llm.py <dossier_contrats> <rapport_json>
"""

import sys
import json
import requests
from pathlib import Path
import chromadb
from sentence_transformers import SentenceTransformer

# ── Configuration ──────────────────────────────────────────────
OLLAMA_URL  = "http://localhost:11434/api/generate"
MODEL       = "gemma4"
DB_PATH     = "/home/ubuntu/cardano-rag"
EMBED_MODEL = "all-MiniLM-L6-v2"
RAG_RESULTS = 5


# ── RAG — Récupérer le contexte Cardano pertinent ─────────────
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
        context_parts = []
        for i, doc in enumerate(results["documents"][0]):
            src = results["metadatas"][0][i].get("source", "unknown")
            src_short = src.split("/")[-2] + "/" + src.split("/")[-1]
            context_parts.append(f"[Source: {src_short}]\n{doc[:600]}")
        return "\n\n---\n\n".join(context_parts)
    except Exception as e:
        print(f"RAG warning: {e}")
        return ""


# ── Analyse LLM avec RAG ──────────────────────────────────────
def analyze_with_llm(contracts, layer1_report):
    """Analyse multi-contrats avec Gemma + contexte RAG"""

    # Préparer le code des contrats
    code_section = ""
    for name, code in contracts.items():
        code_section += f"\n\n=== {name} ===\n{code[:3000]}"

    # Findings de la Couche 1
    findings_summary = ""
    for f in layer1_report.get("findings", []):
        findings_summary += f"- [{f['severity']}] {f['rule_id']}: {f['title']} ({f['file']}:{f['line']})\n"

    # Requête RAG — chercher contexte pertinent
    rag_query = f"Cardano Aiken smart contract security vulnerabilities eUTxO {' '.join(contracts.keys())}"
    rag_context = get_rag_context(rag_query)

    if rag_context:
        print(f"  RAG: {RAG_RESULTS} passages pertinents trouvés dans ChromaDB")
    else:
        print("  RAG: ChromaDB non disponible — analyse sans contexte")

    # Prompt complet
    prompt = f"""You are an expert Cardano smart contract security auditor.
You have deep knowledge of eUTxO model, Aiken language, CIP-0052, and Cardano security patterns.

CARDANO SECURITY KNOWLEDGE BASE (from official sources):
{rag_context if rag_context else "Not available."}

LAYER 1 STATIC ANALYSIS FINDINGS:
{findings_summary if findings_summary else "No findings from static analysis."}

SMART CONTRACTS TO AUDIT:
{code_section}

TASK:
Perform a deep multi-contract security analysis. Focus on:
1. Cross-contract interactions and shared state risks
2. eUTxO-specific vulnerabilities (double satisfaction, datum hijacking, etc.)
3. Business logic flaws not caught by static analysis
4. Patterns matching known Cardano vulnerabilities from the knowledge base
5. CIP-0052 compliance issues

For each finding, cite the relevant source from the knowledge base if applicable.

Respond ONLY with a valid JSON object:
{{
  "multi_contract_risks": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "Short title",
      "description": "Detailed description with reference to knowledge base if applicable",
      "affected_contracts": ["contract1.ak", "contract2.ak"],
      "recommendation": "How to fix",
      "reference": "Source from knowledge base or CIP number"
    }}
  ],
  "overall_assessment": "2-3 sentence summary of the security posture",
  "mainnet_ready": true or false,
  "confidence": "high|medium|low"
}}"""

    # Appel à Gemma via Ollama
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model":  MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 2000
                }
            },
            timeout=120
        )
        raw = response.json().get("response", "")

        # Extraire le JSON
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(raw[start:end])
        else:
            return {
                "multi_contract_risks": [],
                "overall_assessment": raw[:500],
                "mainnet_ready": False,
                "confidence": "low"
            }
    except Exception as e:
        return {
            "multi_contract_risks": [],
            "overall_assessment": f"LLM analysis failed: {e}",
            "mainnet_ready": False,
            "confidence": "low"
        }


# ── Pipeline principale ───────────────────────────────────────
def run_llm_analysis(contracts_dir, layer1_report_path, output_path):
    print("\nAikenGuard Couche 2 — LLM + RAG Cardano Expert")
    print("=" * 50)

    # Charger les contrats
    contracts = {}
    for ak_file in Path(contracts_dir).glob("*.ak"):
        contracts[ak_file.name] = ak_file.read_text(encoding="utf-8", errors="ignore")

    if not contracts:
        print("Aucun fichier .ak trouvé")
        return {}

    print(f"Contrats chargés: {list(contracts.keys())}")

    # Charger le rapport Couche 1
    layer1_report = {}
    try:
        layer1_report = json.loads(Path(layer1_report_path).read_text())
        print(f"Couche 1: {len(layer1_report.get('findings', []))} findings")
    except:
        print("Couche 1: rapport non disponible")

    # Analyse LLM + RAG
    print("Analyse LLM + RAG en cours...")
    llm_result = analyze_with_llm(contracts, layer1_report)

    # Fusionner avec le rapport Couche 1
    final_report = {
        "project": contracts_dir,
        "files_scanned": len(contracts),
        "score": layer1_report.get("score", 0),
        "layer1_findings": layer1_report.get("findings", []),
        "layer2_llm": llm_result,
        "summary": {
            "critical": len([f for f in layer1_report.get("findings", []) if f.get("severity") == "CRITICAL"]),
            "high":     len([f for f in layer1_report.get("findings", []) if f.get("severity") == "HIGH"]),
            "medium":   len([f for f in layer1_report.get("findings", []) if f.get("severity") == "MEDIUM"]),
            "low":      len([f for f in layer1_report.get("findings", []) if f.get("severity") == "LOW"]),
            "total":    len(layer1_report.get("findings", [])),
            "multi_contract_risks": len(llm_result.get("multi_contract_risks", [])),
        },
        "mainnet_ready":       llm_result.get("mainnet_ready", False),
        "overall_assessment":  llm_result.get("overall_assessment", ""),
        "rag_enabled":         True,
    }

    # Sauvegarder
    Path(output_path).write_text(json.dumps(final_report, indent=2))
    print(f"\nRapport complet sauvegardé: {output_path}")
    print(f"Mainnet ready: {final_report['mainnet_ready']}")
    print(f"Risques multi-contrats: {final_report['summary']['multi_contract_risks']}")
    return final_report


# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 aikenguard_llm.py <dossier> <rapport_output>")
        sys.exit(1)

    contracts_dir = sys.argv[1]
    output_path   = sys.argv[2]
    layer1_path   = output_path.replace(".json", "_layer1.json")

    run_llm_analysis(contracts_dir, layer1_path, output_path)
