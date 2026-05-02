#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AikenGuard v0.5 — Outil d'audit automatisé pour smart contracts Aiken
Couche 1 : Analyse statique multilingue (EN / FR / ES)

Positionnement : pré-audit automatisé.
AikenGuard détecte des patterns connus de vulnérabilités, mais ne remplace
pas un audit humain professionnel. Les findings sont des points d'attention
à valider par un développeur ou auditeur.

Règles actives : 16
- AK-001 à AK-002, AK-006 à AK-009 : sécurité core eUTxO
- AK-011 à AK-016 : sécurité avancée (incluant AK-016 chargée séparément)
- AK-017 à AK-021 : qualité et documentation
- AK-022a à AK-022e : estimateur coûts CPU/Memory (chargé via ak022_patch)

Usage:
    python3 Aikenguard.py contracts/ [output.json] [lang]
    python3 Aikenguard.py contrat.ak [output.json] [lang]
    lang : en (default) | fr | es
"""

import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List
from datetime import datetime


# ── Langues supportées ─────────────────────────────────────────
SUPPORTED_LANGS = {"en", "fr", "es"}


def normalize_lang(lang):
    """Valide et normalise la langue. Retombe sur 'en' si invalide."""
    lang = (lang or "en").lower().strip()
    if lang not in SUPPORTED_LANGS:
        return "en"
    return lang


def t(field, lang):
    """Récupère un champ traduit. Fallback en anglais si manquant."""
    if isinstance(field, dict):
        return field.get(lang, field.get("en", ""))
    return field


# ── Modèles de données ─────────────────────────────────────────
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
    language: str = "en"
    findings: List[Finding] = field(default_factory=list)

    @property
    def critical(self): return [f for f in self.findings if f.severity == "CRITICAL"]
    @property
    def high(self):     return [f for f in self.findings if f.severity == "HIGH"]
    @property
    def medium(self):   return [f for f in self.findings if f.severity == "MEDIUM"]
    @property
    def low(self):      return [f for f in self.findings if f.severity == "LOW"]


# ── Définition des règles (multilingue) ────────────────────────
# Chaque règle a:
#   - id, severity : techniques (pas à traduire)
#   - pattern, inverse, etc. : techniques (pas à traduire)
#   - title, description, recommendation : dictionnaires {en, fr, es}
RULES = [
    # ── AK-001 — Multiple satisfaction ─────────────────────────
    {
        "id": "AK-001",
        "severity": "CRITICAL",
        "pattern": r"list\.(any|find|filter)\s*\([^,]+,\s*fn\s*\([^)]+\)\s*\{[^}]*input\b",
        "title": {
            "en": "Multiple satisfaction — UTxO uniqueness not verified",
            "fr": "Multiple satisfaction — unicité UTxO non vérifiée",
            "es": "Multiple satisfaction — unicidad UTxO no verificada",
        },
        "description": {
            "en": (
                "On Cardano eUTxO, an attacker can satisfy the same validator "
                "multiple times in a single transaction if input uniqueness "
                "is not enforced. Most common Cardano vulnerability."
            ),
            "fr": (
                "Sur Cardano eUTxO, un attaquant peut satisfaire le même validator "
                "plusieurs fois dans la même transaction si l'unicité des inputs "
                "n'est pas vérifiée. Vulnérabilité la plus fréquente sur Cardano."
            ),
            "es": (
                "En Cardano eUTxO, un atacante puede satisfacer el mismo validador "
                "varias veces en la misma transacción si no se verifica la unicidad "
                "de los inputs. Vulnerabilidad más frecuente en Cardano."
            ),
        },
        "recommendation": {
            "en": (
                "Verify each input UTxO is unique. "
                "Use list.unique() or an explicit index checker."
            ),
            "fr": (
                "Vérifier que chaque UTxO input est unique. "
                "Utiliser list.unique() ou un vérificateur d'index explicite."
            ),
            "es": (
                "Verificar que cada UTxO input sea único. "
                "Usar list.unique() o un verificador de índice explícito."
            ),
        },
    },

    # ── AK-002 — Datum non typé ────────────────────────────────
    {
        "id": "AK-002",
        "severity": "CRITICAL",
        "pattern": r"expect\s+\w+:\s*Data\b",
        "title": {
            "en": "Untyped datum — generic Data type",
            "fr": "Datum non vérifié — type générique Data",
            "es": "Datum sin tipar — tipo Data genérico",
        },
        "description": {
            "en": (
                "A datum typed as Data without explicit cast "
                "allows injection of any value."
            ),
            "fr": (
                "Un datum typé comme Data sans cast explicite "
                "permet d'injecter n'importe quelle valeur."
            ),
            "es": (
                "Un datum tipado como Data sin cast explícito "
                "permite inyectar cualquier valor."
            ),
        },
        "recommendation": {
            "en": "Always use a concrete type for datums.",
            "fr": "Toujours utiliser un type concret pour les datums.",
            "es": "Siempre usar un tipo concreto para los datums.",
        },
    },

    # ── AK-006 — trace() en production ─────────────────────────
    {
        "id": "AK-006",
        "severity": "MEDIUM",
        "pattern": r"\btrace\s*\(",
        "title": {
            "en": "trace() present — remove in production",
            "fr": "trace() présent — retirer en production",
            "es": "trace() presente — eliminar en producción",
        },
        "description": {
            "en": "trace() calls increase on-chain execution costs.",
            "fr": "Les appels trace() augmentent les coûts d'exécution on-chain.",
            "es": "Las llamadas trace() aumentan los costos de ejecución on-chain.",
        },
        "recommendation": {
            "en": "Remove all trace() calls before mainnet deployment.",
            "fr": "Supprimer tous les trace() avant le déploiement mainnet.",
            "es": "Eliminar todas las llamadas trace() antes del despliegue en mainnet.",
        },
    },

    # ── AK-007 — todo() / fail() atteignable ───────────────────
    {
        "id": "AK-007",
        "severity": "MEDIUM",
        "pattern": r"\b(todo|fail)\s*\(",
        "title": {
            "en": "Reachable todo() or fail()",
            "fr": "todo() ou fail() potentiellement atteignable",
            "es": "todo() o fail() potencialmente alcanzable",
        },
        "description": {
            "en": "A reachable todo() or fail() can lock funds.",
            "fr": "Un todo() ou fail() atteignable peut bloquer des fonds.",
            "es": "Un todo() o fail() alcanzable puede bloquear fondos.",
        },
        "recommendation": {
            "en": "Replace all todo(). fail() must be unreachable.",
            "fr": "Remplacer tous les todo(). Les fail() doivent être inaccessibles.",
            "es": "Reemplazar todos los todo(). Los fail() deben ser inalcanzables.",
        },
    },

    # ── AK-008 — Contrainte temporelle sans valid_range ────────
    {
        "id": "AK-008",
        "severity": "MEDIUM",
        "pattern": r"valid_range",
        "inverse": True,
        "inverse_trigger": r"\b(deadline|expiry|day_start)\b",
        "inverse_check": r"valid_range|validity_range",
        "title": {
            "en": "Time constraint without valid_range",
            "fr": "Contrainte temporelle sans valid_range",
            "es": "Restricción temporal sin valid_range",
        },
        "description": {
            "en": (
                "The contract uses time-based logic "
                "but does not enforce valid_range on-chain."
            ),
            "fr": (
                "Le contrat utilise une logique temporelle "
                "mais n'enforce pas valid_range on-chain."
            ),
            "es": (
                "El contrato usa lógica temporal "
                "pero no aplica valid_range on-chain."
            ),
        },
        "recommendation": {
            "en": "Use interval.contains() with ctx.transaction.validity_range.",
            "fr": "Utiliser interval.contains() avec ctx.transaction.validity_range.",
            "es": "Usar interval.contains() con ctx.transaction.validity_range.",
        },
    },

    # ── AK-009 — Paramètre ignoré ──────────────────────────────
    {
        "id": "AK-009",
        "severity": "LOW",
        "pattern": r"fn\s+\w+\s*\([^)]*\b_\w+\s*:[^)]*\)",
        "title": {
            "en": "Ignored function parameter",
            "fr": "Paramètre de fonction ignoré",
            "es": "Parámetro de función ignorado",
        },
        "description": {
            "en": (
                "A parameter prefixed with _ in a function is ignored. "
                "Verify it's not a critical omission."
            ),
            "fr": (
                "Un paramètre préfixé _ dans une fonction est ignoré. "
                "Vérifier que ce n'est pas une omission critique."
            ),
            "es": (
                "Un parámetro prefijado con _ en una función es ignorado. "
                "Verificar que no sea una omisión crítica."
            ),
        },
        "recommendation": {
            "en": "Confirm the ignored parameter is intentional.",
            "fr": "Confirmer que le paramètre ignoré est intentionnel.",
            "es": "Confirmar que el parámetro ignorado es intencional.",
        },
    },

    # ── AK-011 — Double satisfaction via list.find ─────────────
    {
        "id": "AK-011",
        "severity": "CRITICAL",
        "pattern": r"list\.find\s*\([^,]+,\s*fn\s*\([^)]+\)\s*\{[^}]*\.address",
        "title": {
            "en": "Double satisfaction — list.find without uniqueness",
            "fr": "Double satisfaction — list.find sans unicité",
            "es": "Double satisfaction — list.find sin unicidad",
        },
        "description": {
            "en": (
                "list.find() returns the FIRST satisfying element. "
                "In a transaction with multiple UTxOs from the same validator, "
                "an attacker can satisfy multiple validators with a single payment. "
                "Top Cardano vulnerability — documented in AADA, FluidTokens, lending protocols."
            ),
            "fr": (
                "list.find() retourne le PREMIER élément satisfaisant. "
                "Dans une transaction avec plusieurs UTxOs du même validator, "
                "un attaquant peut satisfaire plusieurs validators avec un seul paiement. "
                "Vulnérabilité #1 sur Cardano — documentée dans AADA, FluidTokens, lending."
            ),
            "es": (
                "list.find() retorna el PRIMER elemento que satisface. "
                "En una transacción con varios UTxOs del mismo validador, "
                "un atacante puede satisfacer varios validadores con un solo pago. "
                "Vulnerabilidad #1 en Cardano — documentada en AADA, FluidTokens, lending."
            ),
        },
        "recommendation": {
            "en": (
                "Use expect [unique_output] = find_script_outputs(...) to enforce uniqueness. "
                "Or list.filter() + verify length == 1. "
                "Reference: Vacuumlabs Double Satisfaction blog series."
            ),
            "fr": (
                "Utiliser expect [unique_output] = find_script_outputs(...) pour forcer l'unicité. "
                "Ou list.filter() + vérifier length == 1. "
                "Référence : Vacuumlabs Double Satisfaction blog series."
            ),
            "es": (
                "Usar expect [unique_output] = find_script_outputs(...) para forzar unicidad. "
                "O list.filter() + verificar length == 1. "
                "Referencia: Vacuumlabs Double Satisfaction blog series."
            ),
        },
    },

    # ── AK-012 — Datum non persisté ────────────────────────────
    {
        "id": "AK-012",
        "severity": "HIGH",
        "pattern": r"\bspent_today\b",
        "inverse": True,
        "inverse_trigger": r"\bspent_today\b",
        "inverse_check": r"wallet_continues|InlineDatum\s*\(",
        "title": {
            "en": "Datum not persisted — counter not updated on-chain",
            "fr": "Datum non persisté — compteur non mis à jour on-chain",
            "es": "Datum no persistido — contador no actualizado on-chain",
        },
        "description": {
            "en": (
                "The contract uses spent_today but does not verify "
                "an output returns the updated datum. "
                "Allows bypassing daily limit via parallel transactions."
            ),
            "fr": (
                "Le contrat utilise spent_today mais ne vérifie pas "
                "qu'un output retourne le datum mis à jour. "
                "Permet de contourner la limite journalière avec des transactions parallèles."
            ),
            "es": (
                "El contrato usa spent_today pero no verifica "
                "que una salida retorne el datum actualizado. "
                "Permite evadir el límite diario con transacciones paralelas."
            ),
        },
        "recommendation": {
            "en": (
                "Verify an output returns to the validator "
                "with the updated datum via wallet_continues() or InlineDatum."
            ),
            "fr": (
                "Vérifier qu'un output retourne vers le validator "
                "avec le datum mis à jour via wallet_continues() ou InlineDatum."
            ),
            "es": (
                "Verificar que una salida retorne al validador "
                "con el datum actualizado vía wallet_continues() o InlineDatum."
            ),
        },
    },

    # ── AK-013 — Revoke sans signatures ────────────────────────
    {
        "id": "AK-013",
        "severity": "HIGH",
        "pattern": r"Revoke\s*->\s*\{(?:(?!has_signed\s*\(\s*ctx|extra_signatories).){0,200}\}",
        "title": {
            "en": "Revoke without real signature verification",
            "fr": "Revoke sans vérification de signatures réelles",
            "es": "Revoke sin verificación de firmas reales",
        },
        "description": {
            "en": (
                "A Revoke action that does not use ctx.extra_signatories "
                "can be triggered without real authorization. "
                "Classic bug: count_valid_guardians(d.guardians, d.guardians)."
            ),
            "fr": (
                "Une action Revoke qui n'utilise pas ctx.extra_signatories "
                "peut être déclenchée sans autorisation réelle. "
                "Bug classique : count_valid_guardians(d.guardians, d.guardians)."
            ),
            "es": (
                "Una acción Revoke que no usa ctx.extra_signatories "
                "puede ser activada sin autorización real. "
                "Bug clásico: count_valid_guardians(d.guardians, d.guardians)."
            ),
        },
        "recommendation": {
            "en": (
                "Use has_signed(ctx, owner) or "
                "count_valid_guardians(ctx.extra_signatories, d.guardians)."
            ),
            "fr": (
                "Utiliser has_signed(ctx, owner) ou "
                "count_valid_guardians(ctx.extra_signatories, d.guardians)."
            ),
            "es": (
                "Usar has_signed(ctx, owner) o "
                "count_valid_guardians(ctx.extra_signatories, d.guardians)."
            ),
        },
    },

    # ── AK-014 — upper_bound contournable ──────────────────────
    {
        "id": "AK-014",
        "severity": "HIGH",
        "pattern": r"upper_bound\.bound_type",
        "title": {
            "en": "Time check on upper_bound — bypassable",
            "fr": "Vérification temporelle sur upper_bound — contournable",
            "es": "Verificación temporal sobre upper_bound — evadible",
        },
        "description": {
            "en": (
                "Using upper_bound to verify a delay has ELAPSED is dangerous. "
                "An attacker can submit a tx with upper_bound far in the future, "
                "bypassing the time constraint. "
                "upper_bound = MAX time of the tx — not the guaranteed current time. "
                "Example: Vacuumlabs vesting CTF — funds unlockable before vesting end."
            ),
            "fr": (
                "Utiliser upper_bound pour vérifier qu'un délai est ÉCOULÉ est dangereux. "
                "Un attaquant peut soumettre une tx avec un upper_bound très loin dans le futur, "
                "contournant la contrainte temporelle. "
                "upper_bound = temps MAX de la tx — pas le temps actuel garanti. "
                "Exemple : vesting CTF Vacuumlabs — fonds débloquables avant la fin du vesting."
            ),
            "es": (
                "Usar upper_bound para verificar que un plazo ha TRANSCURRIDO es peligroso. "
                "Un atacante puede enviar una tx con upper_bound muy en el futuro, "
                "evadiendo la restricción temporal. "
                "upper_bound = tiempo MÁX de la tx — no el tiempo actual garantizado. "
                "Ejemplo: vesting CTF Vacuumlabs — fondos desbloqueables antes del fin del vesting."
            ),
        },
        "recommendation": {
            "en": (
                "To verify time has elapsed: use lower_bound >= deadline. "
                "lower_bound = guaranteed minimum time of the transaction. "
                "upper_bound is reserved for verifying a time has NOT yet been reached."
            ),
            "fr": (
                "Pour vérifier qu'un temps est ÉCOULÉ : utiliser lower_bound >= deadline. "
                "lower_bound = temps minimum garanti de la transaction. "
                "upper_bound est réservé pour vérifier qu'un temps N'EST PAS encore atteint."
            ),
            "es": (
                "Para verificar tiempo transcurrido: usar lower_bound >= deadline. "
                "lower_bound = tiempo mínimo garantizado de la transacción. "
                "upper_bound se reserva para verificar que un tiempo NO se ha alcanzado aún."
            ),
        },
    },

    # ── AK-015 — Vesting sans bénéficiaire ─────────────────────
    {
        "id": "AK-015",
        "severity": "HIGH",
        "pattern": r"lock_until|vesting|vest",
        "inverse": True,
        "inverse_trigger": r"\b(lock_until|vesting_date|vest_at)\b",
        "inverse_check": r"beneficiary|signed_by|has_signed|extra_signatories",
        "title": {
            "en": "Vesting without beneficiary verification",
            "fr": "Vesting sans vérification du bénéficiaire",
            "es": "Vesting sin verificación del beneficiario",
        },
        "description": {
            "en": (
                "A vesting contract that only checks time "
                "without verifying the spender is the beneficiary "
                "lets anyone unlock funds after the delay."
            ),
            "fr": (
                "Un contrat de vesting qui vérifie seulement le temps "
                "sans vérifier que c'est bien le bénéficiaire qui dépense "
                "permet à n'importe qui de débloquer les fonds après le délai."
            ),
            "es": (
                "Un contrato de vesting que solo verifica el tiempo "
                "sin verificar que es el beneficiario quien gasta "
                "permite a cualquiera desbloquear los fondos tras el plazo."
            ),
        },
        "recommendation": {
            "en": (
                "Always verify both conditions: "
                "1) Time has elapsed (lower_bound >= deadline) "
                "2) Beneficiary signature is present (has_signed or extra_signatories)"
            ),
            "fr": (
                "Toujours vérifier les deux conditions : "
                "1) Le temps est écoulé (lower_bound >= deadline) "
                "2) La signature du bénéficiaire est présente (has_signed ou extra_signatories)"
            ),
            "es": (
                "Verificar siempre ambas condiciones: "
                "1) El tiempo ha transcurrido (lower_bound >= deadline) "
                "2) La firma del beneficiario está presente (has_signed o extra_signatories)"
            ),
        },
    },

    # ── AK-017 — Validator sans documentation (remplace AK-010) ──
    {
        "id": "AK-017",
        "severity": "LOW",
        "pattern": r"^validator",
        "inverse": True,
        "inverse_trigger": r"^validator",
        "inverse_check": r"(///|//\s+[A-Z@])",
        "title": {
            "en": "Validator without documentation",
            "fr": "Validator sans documentation",
            "es": "Validador sin documentación",
        },
        "description": {
            "en": (
                "This validator has no documentation comment. "
                "CIP-0052 recommends each validator document its role, "
                "parameters and validation conditions."
            ),
            "fr": (
                "Ce validator ne contient aucun commentaire de documentation. "
                "CIP-0052 recommande que chaque validator documente son rôle, "
                "ses paramètres et ses conditions de validation."
            ),
            "es": (
                "Este validador no tiene comentario de documentación. "
                "CIP-0052 recomienda que cada validador documente su rol, "
                "sus parámetros y sus condiciones de validación."
            ),
        },
        "recommendation": {
            "en": (
                "Add comments before the validator: "
                "/// @title validator name "
                "/// @param datum description "
                "/// @returns validation conditions"
            ),
            "fr": (
                "Ajouter des commentaires avant le validator : "
                "/// @title nom du validator "
                "/// @param datum description "
                "/// @returns conditions de validation"
            ),
            "es": (
                "Agregar comentarios antes del validador: "
                "/// @title nombre del validador "
                "/// @param datum descripción "
                "/// @returns condiciones de validación"
            ),
        },
    },

    # ── AK-018 — expect sans message ───────────────────────────
    {
        "id": "AK-018",
        "severity": "LOW",
        "pattern": r"^\s+expect\s+(?!.*@msg)(?!.*Some\()(?!.*ScriptContext)",
        "title": {
            "en": "expect without explicit error message",
            "fr": "expect sans message d'erreur explicite",
            "es": "expect sin mensaje de error explícito",
        },
        "description": {
            "en": (
                "An expect without error message makes debugging hard. "
                "When the contract fails, impossible to know which condition "
                "caused the on-chain failure."
            ),
            "fr": (
                "Un expect sans message d'erreur rend le debugging difficile. "
                "Quand le contrat échoue, impossible de savoir quelle condition "
                "a causé l'échec on-chain."
            ),
            "es": (
                "Un expect sin mensaje de error dificulta el debugging. "
                "Cuando el contrato falla, imposible saber qué condición "
                "causó el fallo on-chain."
            ),
        },
        "recommendation": {
            "en": (
                "Use expect with a message: "
                'expect condition, @msg "Clear error description"'
            ),
            "fr": (
                "Utiliser expect avec un message : "
                'expect condition, @msg "Description claire de l\'erreur"'
            ),
            "es": (
                "Usar expect con un mensaje: "
                'expect condition, @msg "Descripción clara del error"'
            ),
        },
    },

    # ── AK-019 — Variable nom trop court ───────────────────────
    {
        "id": "AK-019",
        "severity": "LOW",
        "pattern": r"\blet\s+[a-z]\s*=",
        "title": {
            "en": "Variable with too-short name in validator",
            "fr": "Variable à nom trop court dans validator",
            "es": "Variable con nombre muy corto en validador",
        },
        "description": {
            "en": (
                "A variable named with a single character (a, b, x, y) "
                "makes the code hard to read and audit."
            ),
            "fr": (
                "Une variable nommée avec un seul caractère (a, b, x, y) "
                "rend le code difficile à lire et à auditer."
            ),
            "es": (
                "Una variable nombrada con un solo carácter (a, b, x, y) "
                "hace el código difícil de leer y auditar."
            ),
        },
        "recommendation": {
            "en": (
                "Use descriptive names: "
                "Instead of let x = ..., write let input_value = ..."
            ),
            "fr": (
                "Utiliser des noms descriptifs : "
                "Au lieu de let x = ..., écrire let input_value = ..."
            ),
            "es": (
                "Usar nombres descriptivos: "
                "En lugar de let x = ..., escribir let input_value = ..."
            ),
        },
    },

    # ── AK-020 — Logique trop complexe ─────────────────────────
    {
        "id": "AK-020",
        "severity": "MEDIUM",
        "pattern": r"fn\s+\w+\([^)]*ScriptContext[^)]*\)[^{]*\{[^}]{1500,}",
        "title": {
            "en": "Validator logic too complex",
            "fr": "Logique validator trop complexe",
            "es": "Lógica de validador demasiado compleja",
        },
        "description": {
            "en": (
                "This validator contains highly complex logic in a single block. "
                "Complex validators are hard to audit and maintain."
            ),
            "fr": (
                "Ce validator contient une logique très complexe en un seul bloc. "
                "Les validators complexes sont difficiles à auditer et à maintenir."
            ),
            "es": (
                "Este validador contiene lógica muy compleja en un solo bloque. "
                "Los validadores complejos son difíciles de auditar y mantener."
            ),
        },
        "recommendation": {
            "en": (
                "Split into helper functions: "
                "fn check_authorization(...), fn check_value(...), "
                "fn check_datum(...) called from the main validator."
            ),
            "fr": (
                "Décomposer en fonctions auxiliaires : "
                "fn check_authorization(...), fn check_value(...), "
                "fn check_datum(...) appelées depuis le validator principal."
            ),
            "es": (
                "Descomponer en funciones auxiliares: "
                "fn check_authorization(...), fn check_value(...), "
                "fn check_datum(...) llamadas desde el validador principal."
            ),
        },
    },

    # ── AK-021 — Pattern match sans défaut ─────────────────────
    {
        "id": "AK-021",
        "severity": "MEDIUM",
        "pattern": r"when\s+\w+\s+is\s*\{(?:(?!\_ ->)[^}])*\}",
        "title": {
            "en": "Pattern match without default case",
            "fr": "Pattern match sans cas par défaut",
            "es": "Pattern match sin caso por defecto",
        },
        "description": {
            "en": (
                "This pattern match has no default case. "
                "If a new redeemer is added to the enum, "
                "behavior may be unexpected."
            ),
            "fr": (
                "Ce pattern match n'a pas de cas par défaut. "
                "Si un nouveau redeemer est ajouté à l'enum, "
                "le comportement peut être inattendu."
            ),
            "es": (
                "Este pattern match no tiene caso por defecto. "
                "Si se agrega un nuevo redeemer al enum, "
                "el comportamiento puede ser inesperado."
            ),
        },
        "recommendation": {
            "en": (
                "Add an explicit default case: "
                "_ -> False // Reject any unforeseen case"
            ),
            "fr": (
                "Ajouter un cas par défaut explicite : "
                "_ -> False // Rejeter tout cas non prévu"
            ),
            "es": (
                "Agregar un caso por defecto explícito: "
                "_ -> False // Rechazar cualquier caso no previsto"
            ),
        },
    },
]


# ── AK-016 : règle spéciale (logique custom) ───────────────────
AK016_TEXTS = {
    "title": {
        "en": "Datum Owner not verified against external source",
        "fr": "Datum.owner non vérifié contre une source externe",
        "es": "Datum.owner no verificado contra fuente externa",
    },
    "description": {
        "en": "datum.owner used for authorization without external verification.",
        "fr": "datum.owner utilisé pour l'autorisation sans vérification externe.",
        "es": "datum.owner usado para autorización sin verificación externa.",
    },
    "recommendation": {
        "en": "Verify owner against minting policy or reference input.",
        "fr": "Vérifier le owner contre une minting policy ou un reference input.",
        "es": "Verificar el owner contra una minting policy o un reference input.",
    },
}


def check_ak016(content, filename, lang="en"):
    """AK-016 : Datum.owner sans vérification externe (logique custom)."""
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
            "severity":       "HIGH",
            "rule_id":        "AK-016",
            "title":          t(AK016_TEXTS["title"], lang),
            "description":    t(AK016_TEXTS["description"], lang),
            "file":           filename,
            "line":           datum_owner_line,
            "recommendation": t(AK016_TEXTS["recommendation"], lang),
        })
    return findings


# ── Scanner principal ──────────────────────────────────────────
class AikenGuardScanner:

    def __init__(self, path: str, lang: str = "en"):
        self.path = Path(path)
        self.lang = normalize_lang(lang)
        self.report = AuditReport(
            project=self.path.name,
            timestamp=datetime.now().isoformat(),
            files_scanned=0,
            language=self.lang,
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

        # Dédupliquer (même règle, même fichier, même ligne)
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

        # Application des règles RULES (avec traduction)
        for rule in RULES:
            self._apply_rule(rule, content, lines, file_path)

        # AK-022 — Estimateur coûts (chargé dynamiquement)
        self._apply_ak022(content, file_path)

        # AK-016 — Datum owner (logique custom)
        ak016_results = check_ak016(content, str(file_path), self.lang)
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

    def _apply_rule(self, rule, content, lines, file_path):
        """Applique une règle de RULES sur le contenu d'un fichier."""
        pattern = rule["pattern"]
        inverse = rule.get("inverse", False)

        title          = t(rule["title"], self.lang)
        description    = t(rule["description"], self.lang)
        recommendation = t(rule["recommendation"], self.lang)

        if inverse:
            trigger = rule.get("inverse_trigger", pattern)
            if re.search(trigger, content, re.MULTILINE):
                check = rule.get("inverse_check", pattern)
                if not re.search(check, content, re.MULTILINE):
                    snippet_msg = {
                        "en": "[Pattern absent from file]",
                        "fr": "[Pattern absent du fichier]",
                        "es": "[Patrón ausente del archivo]",
                    }[self.lang]
                    self.report.findings.append(Finding(
                        severity=rule["severity"],
                        rule_id=rule["id"],
                        title=title,
                        description=description,
                        file=str(file_path),
                        line=1,
                        code_snippet=snippet_msg,
                        recommendation=recommendation,
                    ))
            return

        for match in re.finditer(pattern, content, re.DOTALL | re.MULTILINE):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[max(0, line_num - 2): line_num + 1]
            snippet_str = "\n".join(
                f"  {max(1, line_num - 1) + i}: {l}"
                for i, l in enumerate(snippet)
            )
            self.report.findings.append(Finding(
                severity=rule["severity"],
                rule_id=rule["id"],
                title=title,
                description=description,
                file=str(file_path),
                line=line_num,
                code_snippet=snippet_str,
                recommendation=recommendation,
            ))

    def _apply_ak022(self, content, file_path):
        """Charge ak022_patch et applique les règles AK-022a-e."""
        try:
            import importlib.machinery
            loader = importlib.machinery.SourceFileLoader(
                'ak022', '/home/ubuntu/AikenGuard/ak022_patch.py'
            )
            ak022_mod = loader.load_module()
            results = ak022_mod.check_ak022(content, str(file_path), self.lang)
            for r in results:
                self.report.findings.append(Finding(
                    severity=r['severity'],
                    rule_id=r['rule_id'],
                    title=r['title'],
                    description=r['description'],
                    file=r['file'],
                    line=r['line'],
                    code_snippet='',
                    recommendation=r['recommendation'],
                ))
        except Exception as e:
            print(f"  ⚠ AK-022 non charge: {e}")


# ── Affichage console ──────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[92m"


CONSOLE_LABELS = {
    "en": {
        "header":   "AikenGuard v0.5 — Audit Report",
        "project":  "Project",
        "date":     "Date",
        "files":    "Files",
        "files_unit": "contracts analyzed",
        "no_vulns": "No vulnerabilities detected",
        "summary":  "Summary",
        "total":    "TOTAL",
        "code":     "Code",
        "score":    "Score",
        "standard": "Standard",
    },
    "fr": {
        "header":   "AikenGuard v0.5 — Rapport d'audit",
        "project":  "Projet",
        "date":     "Date",
        "files":    "Fichiers",
        "files_unit": "contrats analysés",
        "no_vulns": "Aucune vulnérabilité détectée",
        "summary":  "Résumé",
        "total":    "TOTAL",
        "code":     "Code",
        "score":    "Score",
        "standard": "Standard",
    },
    "es": {
        "header":   "AikenGuard v0.5 — Informe de auditoría",
        "project":  "Proyecto",
        "date":     "Fecha",
        "files":    "Archivos",
        "files_unit": "contratos analizados",
        "no_vulns": "No se detectaron vulnerabilidades",
        "summary":  "Resumen",
        "total":    "TOTAL",
        "code":     "Código",
        "score":    "Puntuación",
        "standard": "Estándar",
    },
}


def print_report(report: AuditReport):
    lang = normalize_lang(report.language)
    L = CONSOLE_LABELS[lang]

    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  🛡️  {L['header']}{RESET}")
    print(f"{'═'*60}")
    print(f"  {L['project']:<10}: {report.project}")
    print(f"  {L['date']:<10}: {report.timestamp[:19]}")
    print(f"  {L['files']:<10}: {report.files_scanned} {L['files_unit']}")
    print(f"{'─'*60}")

    total = len(report.findings)
    if total == 0:
        print(f"\n  {GREEN}{BOLD}✅ {L['no_vulns']}{RESET}")
    else:
        c = len(report.critical)
        h = len(report.high)
        m = len(report.medium)
        low = len(report.low)
        print(f"\n  {BOLD}{L['summary']} :{RESET}")
        print(f"  {'CRITICAL':<12} {SEVERITY_COLORS['CRITICAL']}{c}{RESET}")
        print(f"  {'HIGH':<12} {SEVERITY_COLORS['HIGH']}{h}{RESET}")
        print(f"  {'MEDIUM':<12} {SEVERITY_COLORS['MEDIUM']}{m}{RESET}")
        print(f"  {'LOW':<12} {SEVERITY_COLORS['LOW']}{low}{RESET}")
        print(f"  {'─'*30}")
        print(f"  {L['total']:<12} {total}\n")

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for f in sorted(report.findings, key=lambda x: order.index(x.severity)):
            color = SEVERITY_COLORS.get(f.severity, "")
            print(
                f"  {color}{BOLD}[{f.severity}]{RESET} "
                f"{BOLD}{f.rule_id}{RESET} — {f.title}"
            )
            print(f"  📄 {f.file}:{f.line}")
            print(f"\n  {f.description}")
            if f.code_snippet and not f.code_snippet.startswith("["):
                print(f"\n  {L['code']} :\n{f.code_snippet}")
            print(f"\n  {GREEN}→{RESET} {f.recommendation}")
            print(f"  {'─'*58}\n")

    score = compute_score(report)
    bar = "█" * (score // 10) + "░" * (10 - score // 10)
    color = (
        GREEN if score >= 80
        else SEVERITY_COLORS["HIGH"] if score >= 50
        else SEVERITY_COLORS["CRITICAL"]
    )
    print(f"  {BOLD}{L['score']} : {color}{score}/100{RESET}  [{bar}]")
    print(f"  {L['standard']} : CIP-0052 Cardano Audit Guidelines")
    print(f"{'═'*60}\n")


def compute_score(report: AuditReport) -> int:
    """Calcule le score 0-100 basé sur les findings pondérés."""
    return max(
        0,
        100
        - len(report.critical) * 25
        - len(report.high)     * 10
        - len(report.medium)   * 5
        - len(report.low)      * 1,
    )


def save_json(report: AuditReport, output_path: str):
    """Sauvegarde le rapport au format JSON."""
    score = compute_score(report)
    data = {
        "aikenguard_version": "0.5",
        "project":       report.project,
        "timestamp":     report.timestamp,
        "language":      report.language,
        "files_scanned": report.files_scanned,
        "score":         score,
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
    print(f"  📁 JSON : {output_path}\n")


# ── Point d'entrée ─────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 Aikenguard.py <contracts/> [output.json] [lang]")
        print("       python3 Aikenguard.py <contrat.ak>")
        print("  lang : en (default) | fr | es")
        sys.exit(1)

    target      = sys.argv[1]
    output_json = (
        sys.argv[2]
        if len(sys.argv) > 2
        else f"aikenguard-{datetime.now().strftime('%Y%m%d-%H%M')}.json"
    )
    lang = sys.argv[3] if len(sys.argv) > 3 else "en"

    print(f"\n  🦋 AikenGuard v0.5 — analyse : {target} (lang: {lang})")

    scanner = AikenGuardScanner(target, lang=lang)
    report  = scanner.scan()

    print_report(report)
    save_json(report, output_json)

    sys.exit(1 if report.critical else 0)


if __name__ == "__main__":
    main()
