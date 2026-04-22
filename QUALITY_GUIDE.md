# AikenGuard Quality Standards
## Quality guide for Aiken smart contracts on Cardano

> This guide applies the official standards from the Aiken-lang team and CIP-0052.
> AikenGuard does not invent them — it verifies them automatically.

---

## Why code quality is critical in smart contracts

A smart contract deployed on Cardano is **immutable**. You cannot fix a bug after deployment. Code quality is not optional — it is an absolute necessity.

Poor quality code:
- Is difficult to audit → human auditors charge more
- Hides logical bugs → exploitable by attackers
- Is impossible to maintain → problems during updates

---

## The 5 AikenGuard quality rules

### AK-017 — Mandatory documentation

**Why:** CIP-0052 states that every validator must be documented. A human auditor cannot validate what they do not understand.

**Bad:**
```aiken
validator {
  fn spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {
    // ...
  }
}
```

**Good:**
```aiken
/// Escrow payment validator
/// @param datum : contains the beneficiary address and amount
/// @param redeemer : Release or Refund
/// @returns : True if the transaction is authorized
validator {
  fn spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {
    // ...
  }
}
```

---

### AK-018 — Explicit error messages

**Why:** Without error messages, debugging an Aiken contract is a nightmare. Traces are the only window into on-chain execution.

**Bad:**
```aiken
expect list.length(inputs) == 1
expect Some(datum) = find_datum(...)
```

**Good:**
```aiken
expect list.length(inputs) == 1, @msg "Only one script input expected"
expect Some(datum) = find_datum(...), @msg "Datum not found for this output"
```

---

### AK-019 — Descriptive variable names

**Why:** Smart contracts are audited by humans. Readable code reduces audit time and therefore its cost.

**Bad:**
```aiken
let a = ctx.transaction.inputs
let b = list.filter(a, fn(x) { ... })
let c = list.length(b)
```

**Good:**
```aiken
let tx_inputs = ctx.transaction.inputs
let script_inputs = list.filter(tx_inputs, fn(input) { ... })
let script_input_count = list.length(script_inputs)
```

---

### AK-020 — Decomposed validators

**Why:** A validator with 50+ lines of mixed logic is a red flag for any auditor. Complexity hides bugs.

**Bad:**
```aiken
validator {
  fn spend(datum, redeemer, ctx) -> Bool {
    // 60 lines of mixed logic
    // auth + value + datum + time all together
    // impossible to audit properly
  }
}
```

**Good:**
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
  // Authorization logic only
}
```

---

### AK-021 — Complete pattern matching

**Why:** A pattern match without a default case may accept unexpected redeemers if the enum evolves.

**Bad:**
```aiken
when redeemer is {
  Claim -> check_claim(datum, ctx)
  AddTip -> check_tip(datum, ctx)
  // What happens if a new variant is added?
}
```

**Good:**
```aiken
when redeemer is {
  Claim -> check_claim(datum, ctx)
  AddTip -> check_tip(datum, ctx)
  _ -> False // Explicitly reject any unplanned case
}
```

---

## AikenGuard quality score

| Rule   | Score impact | Category |
|--------|-------------|----------|
| AK-017 | -5 points   | Quality  |
| AK-018 | -3 points   | Quality  |
| AK-019 | -2 points   | Quality  |
| AK-020 | -5 points   | Quality  |
| AK-021 | -5 points   | Quality  |

A contract with **100/100** has passed all 16 security rules AND all 5 quality rules.

---

## Checklist before submitting your audit

```
Security (AK-001 to AK-016):
☐ No multiple satisfaction
☐ Explicitly typed datums
☐ Beneficiary verification
☐ Correct time constraints
☐ No trace() in production

Quality (AK-017 to AK-021):
☐ Validator documented with ///
☐ expect with error messages
☐ Variables with descriptive names
☐ Logic decomposed into functions
☐ Pattern match with default case
```

---

## Sources and references

These standards are based on:
- [CIP-0052](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0052) — Cardano Audit Best Practices
- [Aiken Language Guide](https://aiken-lang.org/language-tour) — Official documentation
- [Vacuumlabs CTF](https://github.com/vacuumlabs/cardano-ctf) — 26 documented vulnerabilities
- [Aikido Security](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform) — 75 detectors

---

*Guide maintained by AikenGuard — aikenguard.io*
*Applying Cardano community standards, not inventing them.*
