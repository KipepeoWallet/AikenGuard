# 🛡️ AikenGuard

> Security analysis platform for Aiken smart contracts on Cardano

[![Version](https://img.shields.io/badge/version-0.4-2EFFB5)](https://github.com/KipepeoWallet/AikenGuard)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Cardano](https://img.shields.io/badge/Cardano-eUTxO-0033AD)](https://cardano.org)
[![CTF Score](https://img.shields.io/badge/CTF_Vacuumlabs-63%25-brightgreen)](https://github.com/vacuumlabs/cardano-ctf)
[![CIP-0052](https://img.shields.io/badge/CIP--0052-compliant-2EFFB5)](https://cips.cardano.org)

---

AikenGuard finds vulnerabilities in Aiken smart contracts before they reach mainnet.  
**Two analysis layers** — static detectors + local LLM — cross-validate findings and produce CIP-0052 compliant audit reports.

---

## Why AikenGuard

Cardano smart contracts are immutable once deployed. A single vulnerability can lock funds forever or drain a protocol. Manual audits cost $15,000–$50,000 and take weeks. AikenGuard catches the most critical Cardano-specific bugs automatically, in minutes.

- **eUTxO-native** — detectors built specifically for Cardano's extended UTxO model
- **Multi-layer analysis** — static rules + Gemma 3 27B LLM working together
- **Multi-contract aware** — detects vulnerabilities in interactions between validators
- **Validated against CTF** — 63% detection rate on Vacuumlabs Cardano CTF (15/24 bugs)
- **CIP-0052 reports** — audit reports following the Cardano audit standard

---

## Quick Start

```bash
# Layer 1 — Static analysis (instant)
python3 Aikenguard.py validators/

# Layer 2 — LLM multi-file analysis (requires Ollama + Gemma 3 27B)
python3 aikenguard_llm.py validators/
```

### Requirements

```bash
# Layer 1
python3 --version  # Python 3.9+

# Layer 2
ollama pull gemma3:27b
```

---

## Detectors — 15 Rules (AK-001 to AK-015)

| Rule | Severity | Description |
|------|----------|-------------|
| AK-001 | 🔴 CRITICAL | Multiple satisfaction — UTxO uniqueness not verified |
| AK-002 | 🔴 CRITICAL | Untyped datum — generic Data type |
| AK-006 | 🟡 MEDIUM | trace() present in production code |
| AK-007 | 🟡 MEDIUM | Reachable todo() or fail() |
| AK-008 | 🟡 MEDIUM | Time constraint without valid_range |
| AK-009 | 🔵 LOW | Ignored function parameter |
| AK-010 | 🔵 LOW | Validator without documentation |
| AK-011 | 🔴 CRITICAL | Double satisfaction — list.find without uniqueness |
| AK-012 | 🟠 HIGH | Datum not persisted — counter not updated on-chain |
| AK-013 | 🟠 HIGH | Revoke without real signature verification |
| AK-014 | 🟠 HIGH | Temporal check on upper_bound — bypassable |
| AK-015 | 🟠 HIGH | Vesting without beneficiary verification |

---

## Output Formats

```bash
# Terminal (colored)
python3 Aikenguard.py validators/

# JSON report
python3 Aikenguard.py validators/ report.json
```

Example output:
```
══════════════════════════════════════════════════════════
  🛡️  AikenGuard v0.4 — Audit Report
══════════════════════════════════════════════════════════
  Project   : my_contract
  Files     : 3 contracts analyzed
──────────────────────────────────────────────────────────
  CRITICAL  2
  HIGH      1
  MEDIUM    0
  LOW       1
  Score : 40/100  [████░░░░░░]
  Standard : CIP-0052 Cardano Audit Guidelines
══════════════════════════════════════════════════════════
```

---

## Architecture

```
Layer 1 — AikenGuard Static (Python)
  → 15 regex + AST detectors
  → Instant results
  → eUTxO-specific patterns

Layer 2 — AikenGuard LLM (Gemma 3 27B via Ollama)
  → Analyzes ALL project files together
  → Detects multi-contract interaction vulnerabilities
  → Contextual understanding of business logic
  → multi_contract_risks section in report
```

---

## CTF Validation — Vacuumlabs Cardano CTF

AikenGuard was benchmarked against the [Vacuumlabs Cardano CTF](https://github.com/vacuumlabs/cardano-ctf) — a suite of intentionally vulnerable Aiken contracts used in professional security training.

| Series | Bugs Detected | Coverage |
|--------|--------------|----------|
| 00-09 Simple contracts | 9/10 | 90% |
| Bank series (multi-contract) | 6/14 | 43% |
| **Total** | **15/24** | **63%** |

Layer 2 (LLM) significantly improves detection on multi-contract vulnerabilities.

---

## Vulnerability Coverage

Detectors derived from real vulnerabilities documented in:

| Source | Patterns Covered |
|--------|-----------------|
| Vacuumlabs audit reports | Double satisfaction, missing signature checks |
| MLabs audit reports | Datum tampering, unsafe datum handling |
| Plutonomicon | eUTxO-specific attack patterns |
| Vacuumlabs CTF | 24 intentional vulnerabilities |

---

## Roadmap

- [ ] **v0.5** — Aikido CLI integration (75 additional Rust detectors)
- [ ] **v0.6** — On-chain NFT certification (Cardano blockchain)
- [ ] **v0.7** — Automated fix suggestions
- [ ] **v1.0** — Web service — upload contracts, pay in ADA, receive certified report

---

## About

AikenGuard is developed by [Kipepeo Wallet](https://github.com/KipepeoWallet) — a sovereign mobile wallet for Africa built on Cardano.

Built with ❤️ for the Cardano community.

---

## License

MIT