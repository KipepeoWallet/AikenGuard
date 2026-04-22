# AikenGuard Quality Standards
## Guide de qualité pour smart contracts Aiken sur Cardano

> Ce guide applique les standards officiels de l'équipe Aiken-lang et CIP-0052.
> AikenGuard ne les invente pas — il les vérifie automatiquement.

---

## Pourquoi la qualité du code est critique en smart contracts

Un smart contract déployé sur Cardano est **immutable**. Tu ne peux pas corriger un bug après déploiement. La qualité du code n'est pas optionnelle — c'est une nécessité absolue.

Un code de mauvaise qualité :
- Est difficile à auditer → les auditeurs humains facturent plus cher
- Cache des bugs logiques → exploitables par des attaquants
- Est impossible à maintenir → problèmes lors des mises à jour

---

## Les 5 règles de qualité AikenGuard

### AK-017 — Documentation obligatoire

**Pourquoi :** CIP-0052 stipule que chaque validator doit être documenté. Un auditeur humain ne peut pas valider ce qu'il ne comprend pas.

**Mauvais :**
```aiken
validator {
  fn spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {
    // ...
  }
}
```

**Bon :**
```aiken
/// Validator de paiement escrow
/// @param datum : contient l'adresse du bénéficiaire et le montant
/// @param redeemer : Release (libérer) ou Refund (rembourser)
/// @returns : True si la transaction est autorisée
validator {
  fn spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {
    // ...
  }
}
```

---

### AK-018 — Messages d'erreur explicites

**Pourquoi :** Sans messages d'erreur, le debugging d'un contrat Aiken est un cauchemar. Les traces sont la seule fenêtre sur l'exécution on-chain.

**Mauvais :**
```aiken
expect list.length(inputs) == 1
expect Some(datum) = find_datum(...)
```

**Bon :**
```aiken
expect list.length(inputs) == 1, @msg "Un seul input script attendu"
expect Some(datum) = find_datum(...), @msg "Datum introuvable pour cet output"
```

---

### AK-019 — Noms de variables descriptifs

**Pourquoi :** Les smart contracts sont audités par des humains. Un code lisible réduit le temps d'audit et donc son coût.

**Mauvais :**
```aiken
let a = ctx.transaction.inputs
let b = list.filter(a, fn(x) { ... })
let c = list.length(b)
```

**Bon :**
```aiken
let tx_inputs = ctx.transaction.inputs
let script_inputs = list.filter(tx_inputs, fn(input) { ... })
let script_input_count = list.length(script_inputs)
```

---

### AK-020 — Validators décomposés

**Pourquoi :** Un validator avec 50+ lignes de logique mélangée est un red flag pour tout auditeur. La complexité cache les bugs.

**Mauvais :**
```aiken
validator {
  fn spend(datum, redeemer, ctx) -> Bool {
    // 60 lignes de logique mélangée
    // vérification auth + valeur + datum + time
    // impossible à auditer proprement
  }
}
```

**Bon :**
```aiken
validator {
  fn spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {
    and {
      check_authorization(datum, ctx)?,
      check_value(datum, ctx)?,
      check_datum_continuity(datum, ctx)?,
      check_time_bounds(datum, ctx)?,
    }
  }
}

fn check_authorization(datum: Datum, ctx: ScriptContext) -> Bool {
  // Uniquement la logique d'autorisation
}
```

---

### AK-021 — Pattern match complet

**Pourquoi :** Un pattern match sans cas par défaut peut accepter des redeemers non prévus si l'enum évolue.

**Mauvais :**
```aiken
when redeemer is {
  Claim -> check_claim(datum, ctx)
  AddTip -> check_tip(datum, ctx)
  // Que se passe-t-il si un nouveau variant est ajouté ?
}
```

**Bon :**
```aiken
when redeemer is {
  Claim -> check_claim(datum, ctx)
  AddTip -> check_tip(datum, ctx)
  _ -> False // Rejeter explicitement tout cas non prévu
}
```

---

## Score de qualité AikenGuard

| Règle  | Impact score | Catégorie |
|--------|-------------|-----------|
| AK-017 | -5 points   | Qualité   |
| AK-018 | -3 points   | Qualité   |
| AK-019 | -2 points   | Qualité   |
| AK-020 | -5 points   | Qualité   |
| AK-021 | -5 points   | Qualité   |

Un contrat avec **100/100** a passé les 16 règles de sécurité ET les 5 règles de qualité.

---

## Sources et références

Ces standards sont basés sur :
- [CIP-0052](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0052) — Cardano Audit Best Practices
- [Aiken Language Guide](https://aiken-lang.org/language-tour) — Documentation officielle
- [Vacuumlabs CTF](https://github.com/vacuumlabs/cardano-ctf) — 26 vulnérabilités documentées
- [Aikido Security](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform) — 75 détecteurs

---

*Guide maintenu par AikenGuard — aikenguard.io*
*Appliquant les standards de la communauté Cardano, pas les inventant.*
