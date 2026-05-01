# 🦋 Kipepeo

> *"Kipepeo" means **butterfly** in Swahili — transformation, lightness, freedom.*
> *"Kipepeo" signifie **papillon** en swahili — transformation, légèreté, liberté.*

---

**[EN]** A sovereign mobile wallet on Cardano for everyday citizens in Kenya and East Africa. Simple as M-Pesa — but *you* own everything.

**[FR]** Un wallet mobile souverain sur Cardano pour les citoyens ordinaires au Kenya et en Afrique de l'Est. Aussi simple que M-Pesa — mais *tu* possèdes tout.

---

[![Cardano](https://img.shields.io/badge/Cardano-Mainnet-blue?style=flat-square&logo=cardano)](https://cardano.org)
[![Aiken](https://img.shields.io/badge/Smart%20Contracts-Aiken-purple?style=flat-square)](https://aiken-lang.org)
[![Tests](https://img.shields.io/badge/Tests-89%20PASS-green?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey?style=flat-square)](LICENSE)
[![PALM Ready](https://img.shields.io/badge/PALM-Ready-brightgreen?style=flat-square)](https://palmeconomy.io)
[![Fund15](https://img.shields.io/badge/Project%20Catalyst-Fund%2015-orange?style=flat-square)](https://projectcatalyst.io)

---

## The problem / Le problème

**[EN]** 54% of Africans have no bank account. M-Pesa solves payments — but keeps control. IOG built the rails with Atala PRISM, then shut it down overnight. Every solution so far replaced one controller with another.

**[FR]** 54% des Africains n'ont pas de compte bancaire. M-Pesa règle le paiement — mais garde le contrôle. IOG a construit les rails avec Atala PRISM, puis a fermé du jour au lendemain. Chaque solution jusqu'ici a remplacé un contrôleur par un autre.

---

## The solution / La solution

**[EN]** Kipepeo puts the full financial stack in one wallet — payments, identity, assets, micro-shares — with no company in between. The contracts are on-chain. Nobody can shut this down. Not even us.

**[FR]** Kipepeo met toute la pile financière dans un seul wallet — paiements, identité, actifs, micro-actions — sans aucune entreprise entre l'utilisateur et ses fonds. Les contrats sont on-chain. Personne ne peut éteindre ça. Pas même nous.

---

## What's built / Ce qui est construit

| Smart Contract | Description | Status |
|---|---|---|
| `micro_payment` | Instant payments — matatu, vendors, parking | ✅ 89 tests PASS |
| `recurring_escrow` | Rent, pension, contributions — automated | ✅ 89 tests PASS |
| `identity_vault` | DID + credentials — Hyperledger Identus | ✅ 89 tests PASS |
| `asset_guard` | Large amount protection, configurable thresholds | ✅ 89 tests PASS |

**Stack:**
- Smart contracts — [Aiken](https://aiken-lang.org)
- Identity — [Hyperledger Identus](https://github.com/hyperledger/identus) (open source successor to Atala PRISM)
- Stablecoins — DJED / iUSD / USDCx
- Privacy layer — [Midnight](https://midnight.network) (ZK proofs)
- Blockchain — [Cardano](https://cardano.org)

---

## Use cases / Cas d'usage

**[EN]** Designed for real life in East Africa — not for VC decks.

**[FR]** Conçu pour la vraie vie en Afrique de l'Est — pas pour des pitch decks.

- 🚌 **Matatu** — tap & pay in seconds / payer en secondes
- 🏪 **Market vendors** — receive payments, no data plan needed / recevoir sans forfait data
- 🎓 **School records** — blockchain-verified diplomas / diplômes vérifiables on-chain
- 🏠 **Land titles** — sovereign property ownership / titre foncier souverain
- 🌾 **Farmers** — payment + identity + micro-credit from on-chain history
- 🍞 **SME micro-shares** — bakery, café, farm — local equity tokenized

---

## 🌿 PALM Ready

**[EN]** Kipepeo is **PALM Ready** — designed to integrate natively with the [PALM Economy / Palmyra](https://palmeconomy.io) platform (zenGate Global).

PALM certifies the commodity → Kipepeo pays the producer → the farmer owns their identity and assets.

**[FR]** Kipepeo est **PALM Ready** — conçu pour s'intégrer nativement avec la plateforme [PALM Economy / Palmyra](https://palmeconomy.io) (zenGate Global).

PALM certifie la commodité → Kipepeo paie le producteur → le fermier possède son identité et ses actifs.

```
Farmer / Fermier
    ↓
PALM  →  certifies crop / certifie la récolte  (B2B layer)
    ↓
Kipepeo  →  receives payment, stores DID  (B2C layer)
    ↓
On-chain history  →  micro-credit, land title, SME shares
```

No bridge needed. Same chain. Cardano.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Kipepeo Wallet (mobile)         │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│  │  Pay     │ │  ID/DID  │ │   Assets    │  │
│  │ DJED/iUSD│ │ Identus  │ │ RWA / Shares│  │
│  │  USDCx   │ │ Midnight │ │ Land titles │  │
│  └──────────┘ └──────────┘ └─────────────┘  │
└────────────────────┬────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │     Cardano Mainnet     │
        │  4 Aiken smart contracts│
        │  Immutable — always on  │
        └─────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │    PALM / Palmyra       │
        │  Commodity traceability │
        │  B2B layer — zenGate    │
        └─────────────────────────┘
```

---

## Roadmap

| Milestone | Description | Status |
|---|---|---|
| M0 | 4 Aiken contracts — 89 tests PASS | ✅ Done |
| M1 | Testnet deployment | 🔄 In progress |
| M2 | Project Catalyst Fund 15 submission | 📋 Pending testnet |
| M3 | 50 pilot users — Nairobi | ⏳ Planned |
| M4 | PALM Economy integration | ⏳ Planned |
| M5 | Mainnet + first tokenized RWA | ⏳ Planned |
| M6 | Land titles + SME micro-shares | 🌱 Vision |

---

## Why Cardano / Pourquoi Cardano

**[EN]** Bitcoin exists without Satoshi. Cardano exists without Hoskinson. Kipepeo can exist without us — that's real decentralization.

**[FR]** Bitcoin existe sans Satoshi. Cardano existe sans Hoskinson. Kipepeo peut exister sans nous — c'est ça la vraie décentralisation.

- Proof-of-Stake — low energy, low fees
- Native assets — no complex smart contract overhead for tokens
- Aiken — safe, auditable smart contract language
- Hyperledger Identus — open source DID, no corporate dependency
- Governance — Project Catalyst funds builders directly

---

## Positioning / Positionnement

| | M-Pesa | IOG / Atala | World Mobile | **Kipepeo** |
|---|---|---|---|---|
| Who controls? | Safaricom + Kenya Gov | IOG (closed 2024) | Shareholders | **Nobody — on-chain** |
| Identity | No | Shut down | No | **Self-sovereign DID** |
| Assets | No | No | No | **Land, SME, RWA** |
| Works offline? | Partial | N/A | Needs their nodes | **Yes** |
| Can be shut down? | Yes | Yes (proven) | Yes | **No** |

---

## Project Catalyst Fund 15

**[EN]** Kipepeo is submitting to [Project Catalyst Fund 15](https://projectcatalyst.io). We are looking for:

- Community reviewers before submission
- Co-proposers with Africa ground experience
- Stake pool operators in Kenya / Tanzania

**[FR]** Kipepeo soumet au [Project Catalyst Fund 15](https://projectcatalyst.io). Nous cherchons :

- Reviewers communautaires avant soumission
- Co-proposeurs avec expérience terrain en Afrique
- Stake pool operators au Kenya / Tanzanie

---

## Key partners & contacts / Partenaires & contacts

| Organization | Role | Link |
|---|---|---|
| WADA | West Africa Cardano community | [@WadaADA](https://twitter.com/WadaADA) |
| iceaddis | Pan-African incubator (Ariob program) | [iceaddis.com](https://iceaddis.com) |
| PALM Economy | Commodity traceability — PALM Ready integration | [palmeconomy.io](https://palmeconomy.io) |
| Project Catalyst | Funding — Fund 15 | [projectcatalyst.io](https://projectcatalyst.io) |
| Hyperledger Identus | Open source DID framework | [github.com/hyperledger/identus](https://github.com/hyperledger/identus) |

---

## Contributing / Contribuer

**[EN]** This project is in active development. If you're a builder, community connector, or stake pool operator in East Africa — open an issue or reach out directly.

**[FR]** Ce projet est en développement actif. Si tu es builder, connecteur communautaire, ou stake pool operator en Afrique de l'Est — ouvre une issue ou contacte-nous directement.

```bash
git clone https://github.com/kipepeo-ada/kipepeo
cd kipepeo
# Smart contracts in /contracts — Aiken
# See CONTRIBUTING.md for setup
```

---

## License

Apache 2.0 — same as Hyperledger Identus. Open. Forever.

---

## Contact

- X / Twitter: `@kipepeo_ada`
- Cardano Forum: coming soon
- Email: coming soon

---

> *"M-Pesa gave you a phone with a leash. Kipepeo gives you the keys."*
>
> *"M-Pesa t'a donné un téléphone avec une laisse. Kipepeo te donne les clés."*

---

*Built on [Cardano](https://cardano.org) · Powered by community · Owned by nobody*
