
def check_ak016(content, filename):
    findings = []
    lines = content.split("\n")
    has_datum_owner_check = False
    has_external_verification = False
    datum_owner_line = 0
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if "datum.owner" in s and ("list.has" in s or "extra_signatories" in s or "==" in s):
            has_datum_owner_check = True
            datum_owner_line = i
        if "policy_id" in s or "reference_input" in s:
            has_external_verification = True
    if has_datum_owner_check and not has_external_verification:
        findings.append({
            "severity": "HIGH",
            "rule_id": "AK-016",
            "title": "Datum Owner Not Verified Against External Source",
            "description": "datum.owner used for authorization without external verification.",
            "file": filename,
            "line": datum_owner_line,
            "recommendation": "Verify owner against minting policy or reference input."
        })
    return findings

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AikenGuard v0.4 — Outil d'audit automatisé pour smart contracts Aiken
Couche 1 : Analyse statique

Nouveautés v0.4 :
- AK-014 : upper_bound pour vérification temporelle — contournable
- AK-015 : Absence de vérification du bénéficiaire dans vesting
- AK-001 : Pattern amélioré — moins de faux positifs
- Score : calibré selon taux de faux positifs connus

Usage:
    python3 aikenguard.py contracts/
    python3 aikenguard.py contrat.ak
"""

import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List
from datetime import datetime


@dataclass
class Finding:
    severity: str
    rule_id: str
    title: str
    description: str
    file: str
    line: int
    code_snippet: str
    recommendation: str

@dataclass
class AuditReport:
    project: str
    timestamp: str
    files_scanned: int
    findings: List[Finding] = field(default_factory=list)

    @property
    def critical(self): return [f for f in self.findings if f.severity == "CRITICAL"]
    @property
    def high(self):     return [f for f in self.findings if f.severity == "HIGH"]
    @property
    def medium(self):   return [f for f in self.findings if f.severity == "MEDIUM"]
    @property
    def low(self):      return [f for f in self.findings if f.severity == "LOW"]


RULES = [
    {
        "id": "AK-001",
        "severity": "CRITICAL",
        "title": "Multiple satisfaction — unicité UTxO non vérifiée",
        "pattern": r"list\.(any|find|filter)\s*\([^,]+,\s*fn\s*\([^)]+\)\s*\{[^}]*input\b",
        "description": (
            "Sur Cardano eUTxO, un attaquant peut satisfaire le même validator "
            "plusieurs fois dans la même transaction si l'unicité des inputs "
            "n'est pas vérifiée. Vulnérabilité la plus fréquente sur Cardano."
        ),
        "recommendation": (
            "Vérifier que chaque UTxO input est unique. "
            "Utiliser list.unique() ou un vérificateur d'index explicite."
        ),
    },
    {
        "id": "AK-002",
        "severity": "CRITICAL",
        "title": "Datum non vérifié — type générique Data",
        "pattern": r"expect\s+\w+:\s*Data\b",
        "description": (
            "Un datum typé comme Data sans cast explicite "
            "permet d'injecter n'importe quelle valeur."
        ),
        "recommendation": "Toujours utiliser un type concret pour les datums.",
    },
    {
        "id": "AK-006",
        "severity": "MEDIUM",
        "title": "trace() présent — retirer en production",
        "pattern": r"\btrace\s*\(",
        "description": "Les appels trace() augmentent les coûts d'exécution on-chain.",
        "recommendation": "Supprimer tous les trace() avant le déploiement mainnet.",
    },
    {
        "id": "AK-007",
        "severity": "MEDIUM",
        "title": "todo() ou fail() potentiellement atteignable",
        "pattern": r"\b(todo|fail)\s*\(",
        "description": "Un todo() ou fail() atteignable peut bloquer des fonds.",
        "recommendation": "Remplacer tous les todo(). Les fail() doivent être inaccessibles.",
    },
    {
        "id": "AK-008",
        "severity": "MEDIUM",
        "title": "Contrainte temporelle sans valid_range",
        "pattern": r"valid_range",
        "inverse": True,
        "inverse_trigger": r"\b(deadline|expiry|day_start)\b",
        "inverse_check": r"valid_range|validity_range",
        "description": (
            "Le contrat utilise une logique temporelle "
            "mais n'enforce pas valid_range on-chain."
        ),
        "recommendation": (
            "Utiliser interval.contains() avec ctx.transaction.validity_range."
        ),
    },
    {
        "id": "AK-009",
        "severity": "LOW",
        "title": "Paramètre de fonction ignoré",
        "pattern": r"fn\s+\w+\s*\([^)]*\b_\w+\s*:[^)]*\)",
        "description": (
            "Un paramètre préfixé _ dans une fonction est ignoré. "
            "Vérifier que ce n'est pas une omission critique."
        ),
        "recommendation": "Confirmer que le paramètre ignoré est intentionnel.",
    },
    {
        "id": "AK-010",
        "severity": "LOW",
        "title": "Validator sans documentation",
        "pattern": r"^validator\s+\w+",
        "inverse": True,
        "inverse_trigger": r"^validator\s+\w+",
        "inverse_check": r"///",
        "description": (
            "Un validator sans commentaire /// rend l'audit manuel plus difficile."
        ),
        "recommendation": (
            "Ajouter /// avant chaque validator décrivant les invariants attendus."
        ),
    },
    {
        "id": "AK-011",
        "severity": "CRITICAL",
        "title": "Double satisfaction — list.find sans unicité",
        "pattern": r"list\.find\s*\([^,]+,\s*fn\s*\([^)]+\)\s*\{[^}]*\.address",
        "description": (
            "list.find() retourne le PREMIER élément satisfaisant. "
            "Dans une transaction avec plusieurs UTxOs du même validator, "
            "un attaquant peut satisfaire plusieurs validators avec un seul paiement. "
            "Vulnérabilité #1 sur Cardano — documentée dans AADA, FluidTokens, lending."
        ),
        "recommendation": (
            "Utiliser expect [unique_output] = find_script_outputs(...) pour forcer l'unicité. "
            "Ou list.filter() + vérifier length == 1. "
            "Référence : Vacuumlabs Double Satisfaction blog series."
        ),
    },
    {
        "id": "AK-012",
        "severity": "HIGH",
        "title": "Datum non persisté — compteur non mis à jour on-chain",
        "pattern": r"\bspent_today\b",
        "inverse": True,
        "inverse_trigger": r"\bspent_today\b",
        "inverse_check": r"wallet_continues|InlineDatum\s*\(",
        "description": (
            "Le contrat utilise spent_today mais ne vérifie pas "
            "qu'un output retourne le datum mis à jour. "
            "Permet de contourner la limite journalière avec des transactions parallèles."
        ),
        "recommendation": (
            "Vérifier qu'un output retourne vers le validator "
            "avec le datum mis à jour via wallet_continues() ou InlineDatum."
        ),
    },
    {
        "id": "AK-013",
        "severity": "HIGH",
        "title": "Revoke sans vérification de signatures réelles",
        "pattern": r"Revoke\s*->\s*\{(?:(?!has_signed\s*\(\s*ctx|extra_signatories).){0,200}\}",
        "description": (
            "Une action Revoke qui n'utilise pas ctx.extra_signatories "
            "peut être déclenchée sans autorisation réelle. "
            "Bug classique : count_valid_guardians(d.guardians, d.guardians)."
        ),
        "recommendation": (
            "Utiliser has_signed(ctx, owner) ou "
            "count_valid_guardians(ctx.extra_signatories, d.guardians)."
        ),
    },
    # ── NOUVELLES RÈGLES v0.4 ──────────────────────────────────────
    {
        "id": "AK-014",
        "severity": "HIGH",
        "title": "Vérification temporelle sur upper_bound — contournable",
        "pattern": r"upper_bound\.bound_type",
        "description": (
            "Utiliser upper_bound pour vérifier qu'un délai est ÉCOULÉ est dangereux. "
            "Un attaquant peut soumettre une tx avec un upper_bound très loin dans le futur, "
            "contournant la contrainte temporelle. "
            "upper_bound = temps MAX de la tx — pas le temps actuel garanti. "
            "Exemple : vesting CTF Vacuumlabs — fonds débloquables avant la fin du vesting."
        ),
        "recommendation": (
            "Pour vérifier qu'un temps est ÉCOULÉ : utiliser lower_bound >= deadline. "
            "lower_bound = temps minimum garanti de la transaction. "
            "upper_bound est réservé pour vérifier qu'un temps N'EST PAS encore atteint."
        ),
    },
    {
        "id": "AK-015",
        "severity": "HIGH",
        "title": "Vesting sans vérification du bénéficiaire",
        "pattern": r"lock_until|vesting|vest",
        "inverse": True,
        "inverse_trigger": r"\b(lock_until|vesting_date|vest_at)\b",
        "inverse_check": r"beneficiary|signed_by|has_signed|extra_signatories",
        "description": (
            "Un contrat de vesting qui vérifie seulement le temps "
            "sans vérifier que c'est bien le bénéficiaire qui dépense "
            "permet à n'importe qui de débloquer les fonds après le délai."
        ),
        "recommendation": (
            "Toujours vérifier les deux conditions : "
            "1) Le temps est écoulé (lower_bound >= deadline) "
            "2) La signature du bénéficiaire est présente (has_signed ou extra_signatories)"
        ),
    },
]


class AikenGuardScanner:

    def __init__(self, path: str):
        self.path = Path(path)
        self.report = AuditReport(
            project=self.path.name,
            timestamp=datetime.now().isoformat(),
            files_scanned=0,
        )

    def scan(self) -> AuditReport:
        ak_files = (
            list(self.path.rglob("*.ak"))
            if self.path.is_dir()
            else [self.path]
        )
        ak_files = [f for f in ak_files if "build" not in str(f)]
        self.report.files_scanned = len(ak_files)

        for ak_file in ak_files:
            self._scan_file(ak_file)

        # Dédupliquer
        seen = set()
        unique = []
        for f in self.report.findings:
            key = (f.rule_id, f.file, f.line)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.report.findings = unique
        return self.report

    def _scan_file(self, file_path: Path):
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"  ⚠ Impossible de lire {file_path}: {e}")
            return

        lines = content.splitlines()

        for rule in RULES:
            pattern = rule["pattern"]
            inverse = rule.get("inverse", False)

            if inverse:
                trigger = rule.get("inverse_trigger", pattern)
                if re.search(trigger, content, re.MULTILINE):
                    check = rule.get("inverse_check", pattern)
                    if not re.search(check, content, re.MULTILINE):
                        self.report.findings.append(Finding(
                            severity=rule["severity"],
                            rule_id=rule["id"],
                            title=rule["title"],
                            description=rule["description"],
                            file=str(file_path),
                            line=1,
                            code_snippet="[Pattern absent du fichier]",
                            recommendation=rule["recommendation"],
                        ))
                continue

            for match in re.finditer(
                pattern, content, re.DOTALL | re.MULTILINE
            ):
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[max(0, line_num - 2) : line_num + 1]
                snippet_str = "\n".join(
                    f"  {max(1, line_num - 1) + i}: {l}"
                    for i, l in enumerate(snippet)
                )
                self.report.findings.append(
                    Finding(
                        severity=rule["severity"],
                        rule_id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        file=str(file_path),
                        line=line_num,
                        code_snippet=snippet_str,
                        recommendation=rule["recommendation"],
                    )
                )



        # AK-016
        ak016_results = check_ak016(content, str(file_path))
        for r in ak016_results:
            self.report.findings.append(Finding(
                severity=r["severity"],
                rule_id=r["rule_id"],
                title=r["title"],
                description=r["description"],
                file=r["file"],
                line=r["line"],
                code_snippet="",
                recommendation=r["recommendation"],
            ))

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[92m"


def print_report(report: AuditReport):
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  🛡️  AikenGuard v0.4 — Rapport d'audit{RESET}")
    print(f"{'═'*60}")
    print(f"  Projet   : {report.project}")
    print(f"  Date     : {report.timestamp[:19]}")
    print(f"  Fichiers : {report.files_scanned} contrats analysés")
    print(f"{'─'*60}")

    total = len(report.findings)
    if total == 0:
        print(f"\n  {GREEN}{BOLD}✅ Aucune vulnérabilité détectée{RESET}")
    else:
        c = len(report.critical)
        h = len(report.high)
        m = len(report.medium)
        l = len(report.low)
        print(f"\n  {BOLD}Résumé :{RESET}")
        print(f"  {'CRITICAL':<12} {SEVERITY_COLORS['CRITICAL']}{c}{RESET}")
        print(f"  {'HIGH':<12} {SEVERITY_COLORS['HIGH']}{h}{RESET}")
        print(f"  {'MEDIUM':<12} {SEVERITY_COLORS['MEDIUM']}{m}{RESET}")
        print(f"  {'LOW':<12} {SEVERITY_COLORS['LOW']}{l}{RESET}")
        print(f"  {'─'*30}")
        print(f"  {'TOTAL':<12} {total}\n")

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for f in sorted(
            report.findings, key=lambda x: order.index(x.severity)
        ):
            color = SEVERITY_COLORS.get(f.severity, "")
            print(
                f"  {color}{BOLD}[{f.severity}]{RESET} "
                f"{BOLD}{f.rule_id}{RESET} — {f.title}"
            )
            print(f"  📄 {f.file}:{f.line}")
            print(f"\n  {f.description}")
            if f.code_snippet != "[Pattern absent du fichier]":
                print(f"\n  Code :\n{f.code_snippet}")
            print(f"\n  {GREEN}→{RESET} {f.recommendation}")
            print(f"  {'─'*58}\n")

    score = max(
        0,
        100
        - len(report.critical) * 25
        - len(report.high) * 10
        - len(report.medium) * 5
        - len(report.low) * 1,
    )
    bar = "█" * (score // 10) + "░" * (10 - score // 10)
    color = (
        GREEN
        if score >= 80
        else SEVERITY_COLORS["HIGH"]
        if score >= 50
        else SEVERITY_COLORS["CRITICAL"]
    )
    print(f"  {BOLD}Score : {color}{score}/100{RESET}  [{bar}]")
    print(f"  Standard : CIP-0052 Cardano Audit Guidelines")
    print(f"{'═'*60}\n")


def save_json(report: AuditReport, output_path: str):
    score = max(
        0,
        100
        - len(report.critical) * 25
        - len(report.high) * 10
        - len(report.medium) * 5
        - len(report.low) * 1,
    )
    data = {
        "aikenguard_version": "0.4",
        "project": report.project,
        "timestamp": report.timestamp,
        "files_scanned": report.files_scanned,
        "score": score,
        "summary": {
            "critical": len(report.critical),
            "high":     len(report.high),
            "medium":   len(report.medium),
            "low":      len(report.low),
            "total":    len(report.findings),
        },
        "findings": [
            {
                "severity":       f.severity,
                "rule_id":        f.rule_id,
                "title":          f.title,
                "file":           f.file,
                "line":           f.line,
                "description":    f.description,
                "recommendation": f.recommendation,
            }
            for f in report.findings
        ],
    }
    Path(output_path).write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"  📁 Rapport JSON : {output_path}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 aikenguard.py <contracts/>")
        print("       python3 aikenguard.py <contrat.ak>")
        sys.exit(1)

    target = sys.argv[1]
    output_json = (
        sys.argv[2]
        if len(sys.argv) > 2
        else f"aikenguard-{datetime.now().strftime('%Y%m%d-%H%M')}.json"
    )

    print(f"\n  🦋 AikenGuard v0.4 — analyse : {target}")

    scanner = AikenGuardScanner(target)
    report = scanner.scan()

    print_report(report)
    save_json(report, output_json)

    sys.exit(1 if report.critical else 0)


if __name__ == "__main__":
    main()

