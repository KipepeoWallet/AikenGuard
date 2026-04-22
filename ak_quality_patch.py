#!/usr/bin/env python3
"""
Script à exécuter sur OVH pour ajouter les règles AK-017 à AK-021
dans Aikenguard.py

Usage: python3 ak_quality_patch.py
"""

import re

PATH = "/home/ubuntu/AikenGuard/Aikenguard.py"

# Les 5 nouvelles règles qualité
NEW_RULES = r"""
    # ── AK-017 — Validator sans documentation ──────────────────
    {
        "id": "AK-017",
        "severity": "LOW",
        "title": "Validator sans documentation",
        "pattern": r"^validator",
        "inverse": True,
        "inverse_trigger": r"^validator",
        "inverse_check": r"(///|//\s+[A-Z@])",
        "description": (
            "Ce validator ne contient aucun commentaire de documentation. "
            "CIP-0052 recommande que chaque validator documente son role, "
            "ses parametres et ses conditions de validation."
        ),
        "recommendation": (
            "Ajouter des commentaires avant le validator : "
            "/// @title nom du validator "
            "/// @param datum description "
            "/// @returns conditions de validation"
        ),
    },
    # ── AK-018 — expect sans message d erreur ──────────────────
    {
        "id": "AK-018",
        "severity": "LOW",
        "title": "expect sans message d erreur explicite",
        "pattern": r"^\s+expect\s+(?!.*@msg)(?!.*Some\()(?!.*ScriptContext)",
        "description": (
            "Un expect sans message d erreur rend le debugging difficile. "
            "Quand le contrat echoue, impossible de savoir quelle condition "
            "a cause l echec on-chain."
        ),
        "recommendation": (
            "Utiliser expect avec un message : "
            'expect condition, @msg "Description claire de l erreur"'
        ),
    },
    # ── AK-019 — Variable a nom trop court ─────────────────────
    {
        "id": "AK-019",
        "severity": "LOW",
        "title": "Variable a nom trop court dans validator",
        "pattern": r"\blet\s+[a-z]\s*=",
        "description": (
            "Une variable nommee avec un seul caractere (a, b, x, y) "
            "rend le code difficile a lire et a auditer."
        ),
        "recommendation": (
            "Utiliser des noms descriptifs : "
            "Au lieu de let x = ..., ecrire let input_value = ..."
        ),
    },
    # ── AK-020 — Logique validator trop complexe ───────────────
    {
        "id": "AK-020",
        "severity": "MEDIUM",
        "title": "Logique validator trop complexe",
        "pattern": r"fn\s+\w+\([^)]*ScriptContext[^)]*\)[^{]*\{[^}]{1500,}",
        "description": (
            "Ce validator contient une logique tres complexe en un seul bloc. "
            "Les validators complexes sont difficiles a auditer et a maintenir."
        ),
        "recommendation": (
            "Decomposer en fonctions auxiliaires : "
            "fn check_authorization(...), fn check_value(...), "
            "fn check_datum(...) appellees depuis le validator principal."
        ),
    },
    # ── AK-021 — Pattern match sans cas par defaut ─────────────
    {
        "id": "AK-021",
        "severity": "MEDIUM",
        "title": "Pattern match sans cas par defaut",
        "pattern": r"when\s+\w+\s+is\s*\{(?:(?!\_ ->)[^}])*\}",
        "description": (
            "Ce pattern match n a pas de cas par defaut. "
            "Si un nouveau redeemer est ajoute a l enum, "
            "le comportement peut etre inattendu."
        ),
        "recommendation": (
            "Ajouter un cas par defaut explicite : "
            "_ -> False // Rejeter tout cas non prevu"
        ),
    },
"""

def main():
    with open(PATH) as f:
        content = f.read()

    # Trouver la fin de la liste RULES — avant le ]
    # On cherche la dernière règle AK-015 ou AK-016
    last_rule = content.rfind('"id": "AK-0')
    if last_rule < 0:
        print("Erreur: impossible de trouver les règles existantes")
        return

    # Trouver la fermeture de bloc après la dernière règle
    end_of_last = content.find('},\n', last_rule)
    if end_of_last < 0:
        end_of_last = content.find('},', last_rule)

    insert_pos = end_of_last + 3  # après },\n

    # Vérifier qu'on n'a pas déjà AK-017
    if '"id": "AK-017"' in content:
        print("AK-017 existe déjà dans le fichier!")
        return

    # Insérer les nouvelles règles
    new_content = content[:insert_pos] + NEW_RULES + content[insert_pos:]

    with open(PATH, 'w') as f:
        f.write(new_content)

    print("AK-017 a AK-021 integres dans Aikenguard.py")

    # Compter les règles
    count = new_content.count('"id": "AK-0')
    print(f"Total regles: {count}")

if __name__ == "__main__":
    main()
