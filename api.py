#!/usr/bin/env python3
"""AikenGuard v0.4 — API FastAPI"""

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import subprocess, json, tempfile
from pathlib import Path

app = FastAPI(title="AikenGuard API", version="0.4")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

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

@app.post("/audit")
async def audit(files: list[UploadFile] = File(...)):
    with tempfile.TemporaryDirectory() as tmp:
        # Sauvegarder les fichiers uploadés
        for f in files:
            content = await f.read()
            Path(f"{tmp}/{f.filename}").write_bytes(content)

        # Lancer AikenGuard Couche 1
        report_path = f"{tmp}/report.json"
        subprocess.run(
            ["python3", "/home/ubuntu/AikenGuard/Aikenguard.py", tmp, report_path],
            capture_output=True, text=True
        )

        # Lire le rapport
        try:
            report = json.loads(Path(report_path).read_text())
        except Exception as e:
            report = {"error": str(e)}

        return report
