# JurisAST

**Formally Verified Information Flow Control for Multi-Agent Systems via Neuro-Symbolic Execution Firewalls**

[![Tests](https://img.shields.io/badge/tests-324%20passed-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![SMT: Z3](https://img.shields.io/badge/SMT-Microsoft%20Z3-blueviolet.svg)](https://github.com/Z3Prover/z3)
[![Status: Experimental](https://img.shields.io/badge/status-experimental%20%2F%20alpha-orange.svg)](#disclaimer)

> [!WARNING]
> ### ⚠️ DISCLAIMER: EXPERIMENTAL & UNDER ACTIVE DEVELOPMENT
> **JurisAST is currently in active development and early testing. It has NOT been comprehensively tested or validated for production use.**
> - **Do NOT trust or rely on this project for production systems, real-world security enforcement, or legally binding compliance (GDPR, EU AI Act, PCI-DSS).**
> - The codebase is an early experimental implementation and may contain bugs, unverified edge cases, or breaking API changes.
> - This project is shared publicly for **research, peer review, and community testing only**. Use at your own risk.

> **Decoupling reasoning from verification**: Pydantic AI extracts an agent's multi-step intent into a strict Abstract Syntax Tree (AST), and a Microsoft Z3 SMT solver mathematically proves that the execution graph complies with cross-border data sovereignty laws (e.g., GDPR, EU AI Act, PCI-DSS) in **< 5ms** before any external API is triggered.

---

## Target Domains

- **RegTech** — Automated regulatory compliance (GDPR Art. 44-49, EU AI Act Art. 10/12)
- **FinTech** — High-frequency financial pipelines, PCI-DSS v4.0 cardholder protection
- **Autonomous Enterprise Systems** — Multi-agent orchestration with cross-border data sovereignty

---

## The JurisAST Triad

1. **Pillar A: Pydantic-Driven AST Taint Propagation**  
   Data provenance is anchored outside probabilistic prompt context via typed `SecurityLabel` product lattices and immutable `TaintedValue[T]` containers.
2. **Pillar B: Latency-Free Non-Interference Proofs (Z3 Solver & Policy Engine)**  
   Deterministic mathematical verification via assumption-based incremental SMT solving in `< 5ms`, with unsat core attribution identifying exact violating regulatory constraints.
3. **Pillar C: Symbolic Declassification via Constrained Decoding**  
   Strict schema enforcement bounds Shannon mutual information transfer ($I(X;Y) \le \log_2(|\mathcal{Y}|)$), enabling safe low-entropy extraction (e.g., boolean flags) without exfiltration risk.

---

## 📚 Documentation Index

| Guide | Description |
|:---|
|:---|
| 📖 [**Developer Quickstart**](docs/quickstart.md) | Step-by-step tutorial on labels, taint tracking, AST construction, Z3 solving, and regulatory policies |
| 🏛️ [**System Architecture**](docs/architecture.md) | In-depth technical architecture, neuro-symbolic firewall concept, and sequence diagrams |
| 📜 [**API Reference**](docs/api_reference.md) | Complete reference for all classes, methods, and types in `jurisast-core`, `jurisast-pydantic`, and `jurisast-policies` |
| ⚖️ [**Regulatory Mapping**](docs/regulatory_mapping.md) | Formal translation of GDPR, EU AI Act, and PCI-DSS rules into lattice invariants and policy sets |
| 📐 [**Formal Verification**](docs/formal_verification.md) | Mathematical specification of product lattices, non-interference theorems, and Shannon bounding |
| 🚀 [**Real-World Examples**](examples/README.md) | Two end-to-end runnable demos: M&A data exfiltration prevention and GDPR-compliant FinTech cross-border flows |
| 🤝 [**Contributing Guide**](CONTRIBUTING.md) | Setup, formatting, type checking, and pull request workflows |
| 🔒 [**Security Policy**](SECURITY.md) | Threat model, defense-in-depth architecture, and vulnerability reporting |

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/Startups-Initiatives/JurisAST-Agents.git
cd JurisAST-Agents

# Activate virtual environment
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # Linux/macOS

# Install in development mode
pip install -e ".[dev]"

# Run all 324 unit, property, and integration tests
pytest tests/ -v

# Run real-world examples (requires Gemini API key)
# pydantic-ai >= 2.x uses GOOGLE_API_KEY
set GOOGLE_API_KEY=your_key_here        # Windows
# export GOOGLE_API_KEY=your_key_here   # Linux/macOS
python examples/enterprise_ma_agent/app.py
python examples/fintech_support_agent/app.py
```

### Basic Usage Example (Firewall with GDPR Policy)

```python
from jurisast_core.labels import Jurisdiction, Classification
from jurisast_policies import GDPR_DATA_SOVEREIGNTY
from jurisast_pydantic.capability import JurisASTFirewall
from jurisast_pydantic.decorators import tainted_source, tainted_sink

# 1. Initialize firewall with pre-built GDPR sovereignty policy
firewall = JurisASTFirewall(
    policies=GDPR_DATA_SOVEREIGNTY,
    agent_id="fintech_agent",
)

@tainted_source(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
def fetch_eu_customer(customer_id: str) -> str:
    return "EU Citizen Financial Record"

@tainted_sink(target_jurisdiction=Jurisdiction.US, max_classification=Classification.PII)
def send_to_us_analytics(payload: str) -> str:
    return "sent"

# Record retrieved source
firewall.record_tool_result("fetch_eu_customer", {}, "EU Citizen Financial Record", fetch_eu_customer)

# 2. Verify before executing external call
# ⚡ JurisAST mathematically intercepts and BLOCKS the illicit cross-border flow in < 2ms!
# Raises TaintViolationError: "IFC violation for tool 'send_to_us_analytics': [GDPR Article 44 / 45] ..."
firewall.verify_tool_call(
    tool_name="send_to_us_analytics",
    tool_args={"payload": "EU Citizen Financial Record"},
    tool_callable=send_to_us_analytics,
)
```

---

## Project Structure

```
JurisAST-Agents/
├── docs/                       # Comprehensive documentation suite
│   ├── architecture.md         # System architecture & sequence diagrams
│   ├── api_reference.md        # Core library API reference
│   ├── regulatory_mapping.md   # GDPR, EU AI Act & PCI-DSS mapping
│   ├── formal_verification.md  # Mathematical specifications & proofs
│   └── quickstart.md           # Developer quickstart tutorial
├── examples/                   # Real-world runnable demos
│   ├── README.md               # Overview: Before vs. After JurisAST
│   ├── enterprise_ma_agent/    # Demo 1: M&A prompt-injection prevention
│   │   ├── app.py              # Pydantic AI agent + JurisAST firewall
│   │   └── README.md           # Real-world context, Samsung/JPMorgan case
│   └── fintech_support_agent/  # Demo 2: GDPR-compliant EU→US flows
│       ├── app.py              # Declassification: EU PII → safe error codes
│       └── README.md           # Meta €1.2B fine context, flow diagram
├── libs/
│   ├── jurisast-core/          # Core IFC engine (labels, taint, AST IR, Z3 solver, policies, declassifier)
│   ├── jurisast-pydantic/      # Pydantic AI integration layer (firewall, decorators, extractors)
│   └── jurisast-policies/      # Pre-built regulatory policies (GDPR, EU AI Act, PCI-DSS, PolicyBuilder)
├── tests/
│   ├── unit/                   # 287 unit tests (labels, taint, AST, solver, policies, declassifier, etc.)
│   ├── property/               # 20 property-based tests (Hypothesis algebraic lattice laws & soundness)
│   └── integration/            # 14 end-to-end firewall integration tests
├── CONTRIBUTING.md             # Development guidelines
├── SECURITY.md                 # Security & threat model
├── pyproject.toml              # Root monorepo configuration
└── README.md
```

---

## Disclaimer

> **IMPORTANT**: JurisAST is an experimental software project released under the MIT License on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> - The software is currently in active development and early testing.
> - The authors and maintainers have not yet conducted comprehensive end-to-end production verification across all possible real-world environments.
> - **Do NOT rely on JurisAST for production compliance, legal certifications, or mission-critical data protection.** You are solely responsible for testing, validating, and auditing any deployment for your specific security and regulatory needs.

---

## License

MIT License. Copyright (c) 2026 JurisAST Contributors.
