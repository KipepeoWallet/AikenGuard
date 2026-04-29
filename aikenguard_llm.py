#!/usr/bin/env python3
"""
AikenGuard v0.5 — Couche 2 LLM + RAG Cardano Expert
Architecture a deux vitesses :
  - qwen3.5:9b  pour Plan Pro 179 ADA (3-4 min)
  - qwen3.5:27b pour Plan Certified 279 ADA (15-20 min)

Usage: python3 aikenguard_llm.py <dossier> <output.json> [model]
"""

import sys
import json
import re
import requests
from pathlib import Path
import chromadb
from sentence_transformers import SentenceTransformer

# ── Configuration ──────────────────────────────────────────────
OLLAMA_URL  = "http://localhost:11434/api/generate"
MODEL_PRO   = "qwen3.5:9b"
MODEL_CERT  = "qwen3.5:27b"
DB_PATH     = "/home/ubuntu/cardano-rag"
EMBED_MODEL = "all-MiniLM-L6-v2"
RAG_RESULTS = 5


# ── 1. Filtrer uniquement le code Aiken ────────────────────────
def extract_aiken_code(content):
    """Filtre le code Aiken — supprime commentaires et documentation"""
    lines = content.split("\n")
    code_lines = []
    for line in lines:
        stripped = line.strip()
        # Ignorer les commentaires de documentation
        if stripped.startswith("///"):
            continue
        # Ignorer les commentaires simples
        if stripped.startswith("//"):
            continue
        # Garder le code
        code_lines.append(line)
    return "\n".join(code_lines)


# ── 2. RAG — Contexte Cardano pertinent ───────────────────────
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


# ── 3. Analyse LLM spécialisée sécurité ───────────────────────
def analyze_security(contracts, rag_context, model):
    """Analyse de sécurité pure — code filtré + contexte RAG"""

    # Filtrer uniquement le code
    filtered_code = {}
    for name, content in contracts.items():
        filtered_code[name] = extract_aiken_code(content)

    code_section = ""
    for name, code in filtered_code.items():
        code_section += f"\n\n=== {name} ===\n{code[:3000]}"

    # Prompt spécialisé — analyse sécurité pure
    prompt = f"""You are a specialized Cardano eUTxO security analyzer.

RULES:
- Analyze ONLY the Aiken code provided
- Ignore all comments and documentation
- Focus EXCLUSIVELY on security vulnerabilities
- Look for cross-contract interaction risks
- Think about how multiple validators interact with each other
- Return ONLY valid JSON — no explanations, no markdown

CARDANO SECURITY KNOWLEDGE BASE:
{rag_context if rag_context else "Not available."}

AIKEN CODE TO ANALYZE (comments stripped):
{code_section}

SECURITY FOCUS — detect these eUTxO-specific patterns:
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

Respond ONLY with this JSON structure:
{{
  "score": 0-100,
  "mainnet_ready": true or false,
  "overall_assessment": "2-3 sentences max",
  "multi_contract_risks": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "short title",
      "description": "precise technical description",
      "affected_contracts": ["contract.ak"],
      "recommendation": "exact fix",
      "reference": "CIP or source"
    }}
  ]
}}"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model":  model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.05,
                    "num_predict": 1500
                }
            },
            timeout=1200
        )
        raw = response.json().get("response", "")

        # Extraire le JSON — ignorer le texte de raisonnement
        # Qwen3.5 utilise des balises <think>...</think>
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)

        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(raw[start:end])
        else:
            return {
                "score": 0,
                "mainnet_ready": False,
                "overall_assessment": raw[:300],
                "multi_contract_risks": []
            }
    except Exception as e:
        print(f"  LLM error: {e}")
        return {
            "score": 0,
            "mainnet_ready": False,
            "overall_assessment": f"Analysis failed: {e}",
            "multi_contract_risks": []
        }


# ── 4. Pipeline principale ────────────────────────────────────
def run_llm_analysis(contracts_dir, output_path, model=MODEL_PRO):
    print(f"\nAikenGuard v0.5 — Couche 2 LLM + RAG")
    print(f"  Modele    : {model}")
    print("=" * 45)

    # Charger les contrats
    contracts = {}
    for ak_file in Path(contracts_dir).glob("*.ak"):
        contracts[ak_file.name] = ak_file.read_text(encoding="utf-8", errors="ignore")

    if not contracts:
        print("  Aucun fichier .ak trouve")
        return {}

    print(f"  Contrats  : {list(contracts.keys())}")

    # Charger le rapport Couche 1
    layer1_path = output_path.replace(".json", "_layer1.json")
    layer1 = {}
    try:
        layer1 = json.loads(Path(layer1_path).read_text())
        print(f"  Couche 1  : {len(layer1.get('findings', []))} findings")
    except:
        print("  Couche 1  : rapport non disponible")

    # Contexte RAG
    rag_query = f"Cardano Aiken eUTxO security vulnerability {' '.join(contracts.keys())}"
    rag = get_rag_context(rag_query)
    print(f"  RAG       : {'OK' if rag else 'non disponible'}")

    # Analyse LLM spécialisée sécurité
    print(f"  Analyse   : en cours...")
    llm_result = analyze_security(contracts, rag, model)

    # Rapport final
    findings = layer1.get("findings", [])
    report = {
        "files_scanned": len(contracts),
        "model": model,
        "score": llm_result.get("score", layer1.get("score", 0)),
        "mainnet_ready": llm_result.get("mainnet_ready", False),
        "overall_assessment": llm_result.get("overall_assessment", ""),
        "layer1_findings": findings,
        "multi_contract_risks": llm_result.get("multi_contract_risks", []),
        "summary": {
            "critical": len([f for f in findings if f.get("severity") == "CRITICAL"]),
            "high":     len([f for f in findings if f.get("severity") == "HIGH"]),
            "medium":   len([f for f in findings if f.get("severity") == "MEDIUM"]),
            "low":      len([f for f in findings if f.get("severity") == "LOW"]),
            "total":    len(findings),
            "multi_contract_risks": len(llm_result.get("multi_contract_risks", [])),
        },
        "rag_enabled": bool(rag),
    }

    Path(output_path).write_text(json.dumps(report, indent=2))
    print(f"  Score     : {report['score']}/100")
    print(f"  Mainnet   : {report['mainnet_ready']}")
    print(f"  Risques   : {report['summary']['multi_contract_risks']}")
    print(f"  Rapport   : {output_path}")
    return report


# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 aikenguard_llm.py <dossier> <output.json> [model]")
        print(f"  Models disponibles: {MODEL_PRO} (Pro) | {MODEL_CERT} (Certified)")
        sys.exit(1)

    contracts_dir = sys.argv[1]
    output_path   = sys.argv[2]
    model         = sys.argv[3] if len(sys.argv) > 3 else MODEL_PRO

    run_llm_analysis(contracts_dir, output_path, model)
