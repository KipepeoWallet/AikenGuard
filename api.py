#!/usr/bin/env python3
"""AikenGuard v0.4 — API FastAPI"""

from fastapi import FastAPI, UploadFile, File, Request
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

WALLET = "addr1qx3xa7e02hntguhplrl97ynp6l79pvkqkdcd2q4uwe3w2yn6z7pp6gdm3am8252g5rk2lp4a3ew9eryqss8te68n2x8qgmtg8l"

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
        for f in files:
            content = await f.read()
            Path(f"{tmp}/{f.filename}").write_bytes(content)
        report_path = f"{tmp}/report.json"
        subprocess.run(
            ["python3", "/home/ubuntu/AikenGuard/Aikenguard.py", tmp, report_path],
            capture_output=True, text=True
        )
        try:
            report = json.loads(Path(report_path).read_text())
        except Exception as e:
            report = {"error": str(e)}
        return report

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
