# AikenGuard Quality Standards
## Guía de calidad para smart contracts Aiken en Cardano

> Esta guía aplica los estándares oficiales del equipo Aiken-lang y CIP-0052.
> AikenGuard no los inventa — los verifica automáticamente.

---

## Por qué la calidad del código es crítica en smart contracts

Un smart contract desplegado en Cardano es **inmutable**. No puedes corregir un bug después del despliegue. La calidad del código no es opcional — es una necesidad absoluta.

Un código de mala calidad:
- Es difícil de auditar → los auditores humanos cobran más
- Esconde bugs lógicos → explotables por atacantes
- Es imposible de mantener → problemas durante las actualizaciones

---

## Las 5 reglas de calidad de AikenGuard

### AK-017 — Documentación obligatoria

**Por qué:** CIP-0052 establece que cada validator debe estar documentado. Un auditor humano no puede validar lo que no entiende.

**Malo:**
```aiken
validator {
  fn spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {
    // ...
  }
}
```

**Bueno:**
```aiken
/// Validator de pago escrow
/// @param datum : contiene la dirección del beneficiario y el monto
/// @param redeemer : Release (liberar) o Refund (reembolsar)
/// @returns : True si la transacción está autorizada
validator {
  fn spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {
    // ...
  }
}
```

---

### AK-018 — Mensajes de error explícitos

**Por qué:** Sin mensajes de error, depurar un contrato Aiken es una pesadilla. Los traces son la única ventana a la ejecución on-chain.

**Malo:**
```aiken
expect list.length(inputs) == 1
expect Some(datum) = find_datum(...)
```

**Bueno:**
```aiken
expect list.length(inputs) == 1, @msg "Solo se espera un input de script"
expect Some(datum) = find_datum(...), @msg "Datum no encontrado para este output"
```

---

### AK-019 — Nombres de variables descriptivos

**Por qué:** Los smart contracts son auditados por humanos. Un código legible reduce el tiempo de auditoría y por lo tanto su costo.

**Malo:**
```aiken
let a = ctx.transaction.inputs
let b = list.filter(a, fn(x) { ... })
let c = list.length(b)
```

**Bueno:**
```aiken
let tx_inputs = ctx.transaction.inputs
let script_inputs = list.filter(tx_inputs, fn(input) { ... })
let script_input_count = list.length(script_inputs)
```

---

### AK-020 — Validators descompuestos

**Por qué:** Un validator con 50+ líneas de lógica mezclada es una señal de alerta para cualquier auditor. La complejidad esconde bugs.

**Malo:**
```aiken
validator {
  fn spend(datum, redeemer, ctx) -> Bool {
    // 60 líneas de lógica mezclada
    // verificación auth + valor + datum + tiempo
    // imposible de auditar correctamente
  }
}
```

**Bueno:**
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
  // Solo la lógica de autorización
}
```

---

### AK-021 — Pattern match completo

**Por qué:** Un pattern match sin caso por defecto puede aceptar redeemers no previstos si el enum evoluciona.

**Malo:**
```aiken
when redeemer is {
  Claim -> check_claim(datum, ctx)
  AddTip -> check_tip(datum, ctx)
  // ¿Qué pasa si se agrega una nueva variante?
}
```

**Bueno:**
```aiken
when redeemer is {
  Claim -> check_claim(datum, ctx)
  AddTip -> check_tip(datum, ctx)
  _ -> False // Rechazar explícitamente cualquier caso no previsto
}
```

---

## Puntuación de calidad AikenGuard

| Regla  | Impacto    | Categoría |
|--------|------------|-----------|
| AK-017 | -5 puntos  | Calidad   |
| AK-018 | -3 puntos  | Calidad   |
| AK-019 | -2 puntos  | Calidad   |
| AK-020 | -5 puntos  | Calidad   |
| AK-021 | -5 puntos  | Calidad   |

Un contrato con **100/100** ha pasado las 16 reglas de seguridad Y las 5 reglas de calidad.

---

## Fuentes y referencias

Estos estándares están basados en:
- [CIP-0052](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0052) — Cardano Audit Best Practices
- [Aiken Language Guide](https://aiken-lang.org/language-tour) — Documentación oficial
- [Vacuumlabs CTF](https://github.com/vacuumlabs/cardano-ctf) — 26 vulnerabilidades documentadas
- [Aikido Security](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform) — 75 detectores

---

*Guía mantenida por AikenGuard — aikenguard.io*
*Aplicando los estándares de la comunidad Cardano, no inventándolos.*
