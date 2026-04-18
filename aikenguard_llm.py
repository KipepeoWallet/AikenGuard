#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AikenGuard v0.4 — Couche 2 Multi-fichiers"""
import sys, json, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma3:27b"

SYSTEM_PROMPT = """Tu es un auditeur expert en smart contracts Aiken sur Cardano.
Analyse TOUS les fichiers d'un projet ENSEMBLE.
Cherche les vulnérabilités dans les INTERACTIONS entre contrats.
Réponds UNIQUEMENT en JSON :
{
  "architecture": "2-3 phrases sur les interactions",
  "summary": "résumé findings",
  "score": 0-100,
  "real_findings": [{"severity":"CRITICAL|HIGH|MEDIUM|LOW","title":"","location":"","description":"","fix":""}],
  "false_positives_from_layer1": [],
  "positive_patterns": [],
  "multi_contract_risks": []
}"""

def ask_gemma(code_dict, name):
    files = "".join(f"\n\n=== {k} ===\n```aiken\n{v}\n```" for k,v in code_dict.items())
    prompt = f"Analyse ce projet Aiken complet — {name}.\n{files}\nRéponds en JSON uniquement."
    payload = json.dumps({"model":OLLAMA_MODEL,"prompt":prompt,"system":SYSTEM_PROMPT,"stream":False,"options":{"temperature":0.1,"num_predict":3000}}).encode()
    req = urllib.request.Request(OLLAMA_URL,data=payload,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=180) as r:
            txt = json.loads(r.read())["response"].strip()
            for tag in ["```json","```"]:
                if txt.startswith(tag): txt = txt[len(tag):]
            if txt.endswith("```"): txt = txt[:-3]
            return json.loads(txt.strip())
    except Exception as e:
        return {"error":str(e)}

def check_ollama():
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags",timeout=5) as r:
            models = [m["name"] for m in json.loads(r.read()).get("models",[])]
            if not any("gemma3" in m for m in models):
                print(f"  Modèles dispo: {', '.join(models)}"); return False
            return True
    except: print("  Ollama non accessible"); return False

COLORS = {"CRITICAL":"\033[91m","HIGH":"\033[93m","MEDIUM":"\033[94m","LOW":"\033[96m"}
B="\033[1m"; R="\033[0m"; G="\033[92m"

def print_report(name, a, n):
    print(f"\n{B}{'='*60}{R}")
    print(f"{B}  AikenGuard v0.4 Couche 2 — {name}{R}")
    print(f"  Fichiers analysés ensemble : {n}")
    print(f"{'='*60}")
    if "error" in a: print(f"  Erreur: {a['error']}"); return
    print(f"\n  Architecture: {a.get('architecture','')}")
    score = a.get('score','?')
    c = G if isinstance(score,int) and score>=80 else COLORS.get('HIGH','') if isinstance(score,int) and score>=60 else COLORS.get('CRITICAL','')
    print(f"\n  Score: {c}{B}{score}/100{R}")
    print(f"  Résumé: {a.get('summary','')}")
    findings = a.get("real_findings",[])
    if not findings: print(f"\n  {G}✅ Aucune vulnérabilité{R}")
    else:
        print(f"\n  {B}Findings ({len(findings)}):{R}")
        for f in findings:
            col = COLORS.get(f.get("severity","LOW"),"")
            print(f"\n  {col}{B}[{f.get('severity')}]{R} {f.get('title')}")
            print(f"  📍 {f.get('location')}")
            print(f"  {f.get('description')}")
            if f.get("fix"): print(f"  {G}→ Fix:{R} {f.get('fix')}")
    multi = a.get("multi_contract_risks",[])
    if multi:
        print(f"\n  Risques multi-contrats:")
        for m in multi: print(f"  ⚠ {m}")
    print(f"\n{'='*60}")

def scan(path):
    target = Path(path)
    files = [f for f in (target.rglob("*.ak") if target.is_dir() else [target]) if "build" not in str(f)]
    if not files: print(f"  Aucun .ak trouvé"); return
    print(f"\n  🦋 AikenGuard v0.4 Couche 2 — {target.name}")
    print(f"  {len(files)} fichier(s): {', '.join(f.name for f in files)}")
    if not check_ollama(): sys.exit(1)
    code = {}
    for f in files:
        try:
            c = f.read_text(encoding="utf-8")
            code[f.name] = c[:6000] + "\n// [tronqué]" if len(c)>6000 else c
        except Exception as e: print(f"  Erreur {f}: {e}")
    print(f"\n  ⏳ Analyse en cours (~{len(files)*30}s)...")
    analysis = ask_gemma(code, target.name)
    print_report(target.name, analysis, len(files))
    out = f"aikenguard-llm-{datetime.now().strftime('%Y%m%d-%H%M')}.json"
    Path(out).write_text(json.dumps({"version":"0.4","project":target.name,"files":list(code.keys()),"analysis":analysis},indent=2,ensure_ascii=False),encoding="utf-8")
    print(f"\n  📁 Rapport: {out}")
    findings = analysis.get("real_findings",[])
    sys.exit(1 if any(f.get("severity")=="CRITICAL" for f in findings) else 0)

if __name__ == "__main__":
    if len(sys.argv)<2: print("Usage: python3 aikenguard_llm.py <projet/>"); sys.exit(1)
    scan(sys.argv[1])
