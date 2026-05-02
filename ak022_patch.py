#!/usr/bin/env python3
"""
AK-022 — Estimateur de couts d execution Cardano
Detecte les patterns couteux en CPU/Memory avant deploiement
"""

AK022_RULES = [
    # ── AK-022a — Listes non bornees ──────────────────────────
    {
        "id": "AK-022a",
        "severity": "HIGH",
        "title": "Unbounded list operation — high CPU cost",
        "pattern": r"\blist\.(filter|find|any|all|map|foldl|foldr|flat_map)\s*\(",
        "description": (
            "This operation iterates over an unbounded list. "
            "On Cardano, CPU execution units are proportional to list size. "
            "A list of 100 UTxOs costs ~100x more than a list of 1. "
            "Risk: transaction rejected if Execution Units exceed limits "
            "(CPU max: 10,000,000,000 / Memory max: 14,000,000)."
        ),
        "recommendation": (
            "Bound the list size: add a check before the operation. "
            "Example: expect list.length(inputs) <= 10 "
            "@msg 'Too many inputs — execution cost too high'. "
            "Or use list.head() if you only need the first element."
        ),
        "cost_impact": "HIGH — O(n) CPU cost",
    },

    # ── AK-022b — ByteArray operations repetees ───────────────
    {
        "id": "AK-022b",
        "severity": "MEDIUM",
        "title": "Repeated ByteArray operations — high Memory cost",
        "pattern": r"\b(bytearray\.concat|string\.concat|builtin\.append_byte_string)\s*\(",
        "description": (
            "Repeated ByteArray concatenation is expensive in Memory units. "
            "Each concat creates a new ByteArray in memory. "
            "In a loop or recursive function, this can exhaust Memory limits quickly."
        ),
        "recommendation": (
            "Minimize ByteArray concatenations. "
            "Pre-compute fixed strings outside validators. "
            "Use blake2b_256 hashing instead of building long ByteArrays."
        ),
        "cost_impact": "MEDIUM — O(n) Memory cost",
    },

    # ── AK-022c — Nested validators ───────────────────────────
    {
        "id": "AK-022c",
        "severity": "HIGH",
        "title": "Multiple validator executions in same transaction",
        "pattern": r"\bscript_hash\b|\bvalidator_hash\b|\binvoke\b",
        "description": (
            "Multiple validators executing in the same transaction multiply "
            "the total Execution Units cost. "
            "If each validator uses 2B CPU units and you have 5 validators, "
            "total cost = 10B CPU units — near the 10B limit."
        ),
        "recommendation": (
            "Profile each validator independently. "
            "Consider merging validators if possible. "
            "Or use reference scripts to reduce execution overhead."
        ),
        "cost_impact": "HIGH — multiplicative cost",
    },

    # ── AK-022d — Data decoding couteux ───────────────────────
    {
        "id": "AK-022d",
        "severity": "MEDIUM",
        "title": "Complex Data decoding — Memory intensive",
        "pattern": r"\bexpect\s+\w+:\s*Data\b|\bwhen\s+\w+\s+is\s*\{[^}]{200,}",
        "description": (
            "Decoding complex Data types or deeply nested pattern matches "
            "consumes significant Memory units on Cardano. "
            "Large datum types with many fields are particularly expensive."
        ),
        "recommendation": (
            "Use typed datum/redeemer instead of generic Data. "
            "Split large datums into smaller focused structs. "
            "Avoid deeply nested when/is pattern matches."
        ),
        "cost_impact": "MEDIUM — Memory decoding cost",
    },

    # ── AK-022e — Reference inputs non utilises ───────────────
    {
        "id": "AK-022e",
        "severity": "LOW",
        "title": "Large reference_inputs list — unnecessary CPU cost",
        "pattern": r"\breference_inputs\b",
        "description": (
            "Accessing reference_inputs iterates over all reference UTxOs "
            "in the transaction. Each additional reference input adds CPU cost. "
            "Unnecessary reference inputs waste execution budget."
        ),
        "recommendation": (
            "Only include reference inputs that are actually needed. "
            "Filter reference inputs by script hash or asset to reduce iteration cost."
        ),
        "cost_impact": "LOW — O(n) CPU cost per lookup",
    },
]


def check_ak022(content, filename):
    """Detecte les patterns couteux en execution sur Cardano"""
    import re
    findings = []
    lines = content.split("\n")

    for rule in AK022_RULES:
        pattern = re.compile(rule["pattern"])
        matched_lines = []

        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                matched_lines.append(i)

        if matched_lines:
            # Dedupliquer — un seul finding par regle par fichier
            findings.append({
                "severity":       rule["severity"],
                "rule_id":        rule["id"],
                "title":          rule["title"],
                "description":    rule["description"],
                "file":           filename,
                "line":           matched_lines[0],
                "recommendation": rule["recommendation"],
                "cost_impact":    rule["cost_impact"],
                "occurrences":    len(matched_lines),
                "all_lines":      matched_lines[:5],
            })

    return findings


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python3 ak022_patch.py <fichier.ak>")
        sys.exit(1)

    content = open(sys.argv[1]).read()
    findings = check_ak022(content, sys.argv[1])

    print(f"\n AK-022 — Execution Cost Estimator")
    print(f" Fichier : {sys.argv[1]}")
    print(f" Findings: {len(findings)}")
    print("=" * 50)

    for f in findings:
        print(f"\n [{f['severity']}] {f['rule_id']} — {f['title']}")
        print(f" Lignes  : {f['all_lines']}")
        print(f" Impact  : {f['cost_impact']}")
        print(f" Fix     : {f['recommendation'][:80]}")

    print(json.dumps(findings, indent=2))
