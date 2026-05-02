#!/usr/bin/env python3
"""
AK-022 — Estimateur de coûts d'exécution Cardano
Détecte les patterns coûteux en CPU/Memory avant déploiement
Support multilingue : EN / FR / ES
"""

import re

SUPPORTED_LANGS = {"en", "fr", "es"}


def _t(field, lang):
    """Récupère un champ traduit. Fallback en anglais si manquant."""
    if isinstance(field, dict):
        return field.get(lang, field.get("en", ""))
    return field


AK022_RULES = [
    # ── AK-022a — Listes non bornées ──────────────────────────
    {
        "id": "AK-022a",
        "severity": "HIGH",
        "pattern": r"\blist\.(filter|find|any|all|map|foldl|foldr|flat_map)\s*\(",
        "title": {
            "en": "Unbounded list operation — high CPU cost",
            "fr": "Opération sur liste non bornée — coût CPU élevé",
            "es": "Operación en lista no acotada — alto costo CPU",
        },
        "description": {
            "en": (
                "This operation iterates over an unbounded list. "
                "On Cardano, CPU execution units are proportional to list size. "
                "A list of 100 UTxOs costs ~100x more than a list of 1. "
                "Risk: transaction rejected if Execution Units exceed limits "
                "(CPU max: 10,000,000,000 / Memory max: 14,000,000)."
            ),
            "fr": (
                "Cette opération itère sur une liste non bornée. "
                "Sur Cardano, les unités d'exécution CPU sont proportionnelles à la taille de la liste. "
                "Une liste de 100 UTxOs coûte ~100x plus qu'une liste de 1. "
                "Risque : transaction rejetée si les Execution Units dépassent les limites "
                "(CPU max : 10 000 000 000 / Memory max : 14 000 000)."
            ),
            "es": (
                "Esta operación itera sobre una lista no acotada. "
                "En Cardano, las unidades de ejecución CPU son proporcionales al tamaño de la lista. "
                "Una lista de 100 UTxOs cuesta ~100x más que una lista de 1. "
                "Riesgo: transacción rechazada si las Execution Units exceden los límites "
                "(CPU max: 10.000.000.000 / Memory max: 14.000.000)."
            ),
        },
        "recommendation": {
            "en": (
                "Bound the list size: add a check before the operation. "
                "Example: expect list.length(inputs) <= 10 "
                "@msg 'Too many inputs — execution cost too high'. "
                "Or use list.head() if you only need the first element."
            ),
            "fr": (
                "Borner la taille de la liste : ajouter une vérification avant l'opération. "
                "Exemple : expect list.length(inputs) <= 10 "
                "@msg 'Trop d'inputs — coût d'exécution trop élevé'. "
                "Ou utiliser list.head() si seul le premier élément est nécessaire."
            ),
            "es": (
                "Acotar el tamaño de la lista: agregar una verificación antes de la operación. "
                "Ejemplo: expect list.length(inputs) <= 10 "
                "@msg 'Demasiados inputs — costo de ejecución muy alto'. "
                "O usar list.head() si solo se necesita el primer elemento."
            ),
        },
        "cost_impact": "HIGH — O(n) CPU cost",
    },

    # ── AK-022b — ByteArray operations répétées ───────────────
    {
        "id": "AK-022b",
        "severity": "MEDIUM",
        "pattern": r"\b(bytearray\.concat|string\.concat|builtin\.append_byte_string)\s*\(",
        "title": {
            "en": "Repeated ByteArray operations — high Memory cost",
            "fr": "Opérations ByteArray répétées — coût Memory élevé",
            "es": "Operaciones ByteArray repetidas — alto costo Memory",
        },
        "description": {
            "en": (
                "Repeated ByteArray concatenation is expensive in Memory units. "
                "Each concat creates a new ByteArray in memory. "
                "In a loop or recursive function, this can exhaust Memory limits quickly."
            ),
            "fr": (
                "La concaténation répétée de ByteArray est coûteuse en unités Memory. "
                "Chaque concat crée un nouveau ByteArray en mémoire. "
                "Dans une boucle ou fonction récursive, cela peut épuiser les limites Memory rapidement."
            ),
            "es": (
                "La concatenación repetida de ByteArray es costosa en unidades Memory. "
                "Cada concat crea un nuevo ByteArray en memoria. "
                "En un bucle o función recursiva, esto puede agotar los límites de Memory rápidamente."
            ),
        },
        "recommendation": {
            "en": (
                "Minimize ByteArray concatenations. "
                "Pre-compute fixed strings outside validators. "
                "Use blake2b_256 hashing instead of building long ByteArrays."
            ),
            "fr": (
                "Minimiser les concaténations de ByteArray. "
                "Pré-calculer les chaînes fixes en dehors des validators. "
                "Utiliser le hashing blake2b_256 au lieu de construire de longs ByteArrays."
            ),
            "es": (
                "Minimizar las concatenaciones de ByteArray. "
                "Pre-calcular strings fijos fuera de los validadores. "
                "Usar hashing blake2b_256 en lugar de construir ByteArrays largos."
            ),
        },
        "cost_impact": "MEDIUM — O(n) Memory cost",
    },

    # ── AK-022c — Multiples validators ─────────────────────────
    {
        "id": "AK-022c",
        "severity": "HIGH",
        "pattern": r"\bscript_hash\b|\bvalidator_hash\b|\binvoke\b",
        "title": {
            "en": "Multiple validator executions in same transaction",
            "fr": "Plusieurs exécutions de validators dans la même transaction",
            "es": "Múltiples ejecuciones de validadores en la misma transacción",
        },
        "description": {
            "en": (
                "Multiple validators executing in the same transaction multiply "
                "the total Execution Units cost. "
                "If each validator uses 2B CPU units and you have 5 validators, "
                "total cost = 10B CPU units — near the 10B limit."
            ),
            "fr": (
                "Plusieurs validators s'exécutant dans la même transaction multiplient "
                "le coût total en Execution Units. "
                "Si chaque validator utilise 2 milliards d'unités CPU et que vous avez 5 validators, "
                "coût total = 10 milliards d'unités CPU — proche de la limite de 10 milliards."
            ),
            "es": (
                "Múltiples validadores ejecutándose en la misma transacción multiplican "
                "el costo total en Execution Units. "
                "Si cada validador usa 2 mil millones de unidades CPU y tienes 5 validadores, "
                "costo total = 10 mil millones de unidades CPU — cerca del límite de 10 mil millones."
            ),
        },
        "recommendation": {
            "en": (
                "Profile each validator independently. "
                "Consider merging validators if possible. "
                "Or use reference scripts to reduce execution overhead."
            ),
            "fr": (
                "Profiler chaque validator indépendamment. "
                "Envisager de fusionner les validators si possible. "
                "Ou utiliser des reference scripts pour réduire l'overhead d'exécution."
            ),
            "es": (
                "Perfilar cada validador independientemente. "
                "Considerar fusionar validadores si es posible. "
                "O usar reference scripts para reducir el overhead de ejecución."
            ),
        },
        "cost_impact": "HIGH — multiplicative cost",
    },

    # ── AK-022d — Décodage Data coûteux ───────────────────────
    {
        "id": "AK-022d",
        "severity": "MEDIUM",
        "pattern": r"\bexpect\s+\w+:\s*Data\b|\bwhen\s+\w+\s+is\s*\{[^}]{200,}",
        "title": {
            "en": "Complex Data decoding — Memory intensive",
            "fr": "Décodage Data complexe — intensif en Memory",
            "es": "Decodificación Data compleja — intensiva en Memory",
        },
        "description": {
            "en": (
                "Decoding complex Data types or deeply nested pattern matches "
                "consumes significant Memory units on Cardano. "
                "Large datum types with many fields are particularly expensive."
            ),
            "fr": (
                "Le décodage de types Data complexes ou de pattern matches profondément imbriqués "
                "consomme des unités Memory significatives sur Cardano. "
                "Les datums volumineux avec beaucoup de champs sont particulièrement coûteux."
            ),
            "es": (
                "Decodificar tipos Data complejos o pattern matches profundamente anidados "
                "consume unidades Memory significativas en Cardano. "
                "Los datums grandes con muchos campos son particularmente costosos."
            ),
        },
        "recommendation": {
            "en": (
                "Use typed datum/redeemer instead of generic Data. "
                "Split large datums into smaller focused structs. "
                "Avoid deeply nested when/is pattern matches."
            ),
            "fr": (
                "Utiliser des datum/redeemer typés au lieu de Data générique. "
                "Diviser les gros datums en structs plus petits et focalisés. "
                "Éviter les pattern matches when/is profondément imbriqués."
            ),
            "es": (
                "Usar datum/redeemer tipados en lugar de Data genérico. "
                "Dividir datums grandes en structs más pequeños y enfocados. "
                "Evitar pattern matches when/is profundamente anidados."
            ),
        },
        "cost_impact": "MEDIUM — Memory decoding cost",
    },

    # ── AK-022e — Reference inputs non utilisés ───────────────
    {
        "id": "AK-022e",
        "severity": "LOW",
        "pattern": r"\breference_inputs\b",
        "title": {
            "en": "Large reference_inputs list — unnecessary CPU cost",
            "fr": "Liste reference_inputs grande — coût CPU inutile",
            "es": "Lista reference_inputs grande — costo CPU innecesario",
        },
        "description": {
            "en": (
                "Accessing reference_inputs iterates over all reference UTxOs "
                "in the transaction. Each additional reference input adds CPU cost. "
                "Unnecessary reference inputs waste execution budget."
            ),
            "fr": (
                "Accéder à reference_inputs itère sur tous les UTxOs de référence "
                "dans la transaction. Chaque reference input supplémentaire ajoute du coût CPU. "
                "Les reference inputs inutiles gaspillent le budget d'exécution."
            ),
            "es": (
                "Acceder a reference_inputs itera sobre todos los UTxOs de referencia "
                "en la transacción. Cada reference input adicional agrega costo CPU. "
                "Los reference inputs innecesarios desperdician el presupuesto de ejecución."
            ),
        },
        "recommendation": {
            "en": (
                "Only include reference inputs that are actually needed. "
                "Filter reference inputs by script hash or asset to reduce iteration cost."
            ),
            "fr": (
                "N'inclure que les reference inputs réellement nécessaires. "
                "Filtrer les reference inputs par script hash ou asset pour réduire le coût d'itération."
            ),
            "es": (
                "Incluir solo los reference inputs realmente necesarios. "
                "Filtrar reference inputs por script hash o asset para reducir el costo de iteración."
            ),
        },
        "cost_impact": "LOW — O(n) CPU cost per lookup",
    },
]


def check_ak022(content, filename, lang="en"):
    """Détecte les patterns coûteux en exécution sur Cardano.

    Args:
        content:  contenu du fichier .ak
        filename: nom/chemin du fichier (pour le rapport)
        lang:     'en' | 'fr' | 'es' — langue des findings

    Returns:
        list[dict] : findings traduits dans la langue demandée
    """
    lang = (lang or "en").lower()
    if lang not in SUPPORTED_LANGS:
        lang = "en"

    findings = []
    lines = content.split("\n")

    for rule in AK022_RULES:
        pattern = re.compile(rule["pattern"])
        matched_lines = []

        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                matched_lines.append(i)

        if matched_lines:
            # Un seul finding par règle par fichier (déduplication)
            findings.append({
                "severity":       rule["severity"],
                "rule_id":        rule["id"],
                "title":          _t(rule["title"], lang),
                "description":    _t(rule["description"], lang),
                "file":           filename,
                "line":           matched_lines[0],
                "recommendation": _t(rule["recommendation"], lang),
                "cost_impact":    rule["cost_impact"],
                "occurrences":    len(matched_lines),
                "all_lines":      matched_lines[:5],
            })

    return findings


# ── Mode standalone (pour debug/test) ─────────────────────────
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python3 ak022_patch.py <fichier.ak> [lang]")
        print("  lang : en (default) | fr | es")
        sys.exit(1)

    file_arg = sys.argv[1]
    lang_arg = sys.argv[2] if len(sys.argv) > 2 else "en"

    content = open(file_arg).read()
    findings = check_ak022(content, file_arg, lang_arg)

    print(f"\n AK-022 — Execution Cost Estimator ({lang_arg})")
    print(f" Fichier : {file_arg}")
    print(f" Findings: {len(findings)}")
    print("=" * 50)

    for f in findings:
        print(f"\n [{f['severity']}] {f['rule_id']} — {f['title']}")
        print(f" Lignes  : {f['all_lines']}")
        print(f" Impact  : {f['cost_impact']}")
        print(f" Fix     : {f['recommendation'][:80]}")
