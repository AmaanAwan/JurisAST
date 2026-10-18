# JurisAST

**Formally Verified Information Flow Control for Multi-Agent Systems via Neuro-Symbolic Execution Firewalls**

[![Tests](https://img.shields.io/badge/tests-385%20passed-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![SMT: Z3](https://img.shields.io/badge/SMT-Microsoft%20Z3-blueviolet.svg)](https://github.com/Z3Prover/z3)
[![Status: Experimental](https://img.shields.io/badge/status-experimental%20%2F%20alpha-orange.svg)](#disclaimer)

> [!WARNING]
> ### ⚠️ DISCLAIMER: EXPERIMENTAL & UNDER ACTIVE DEVELOPMENT
> **JurisAST is currently in active development and early testing. It has NOT been comprehensively tested or validated for production use.**
> - **Do NOT trust or rely on this project for production systems, real-world security enforcement, or legally binding compliance (GDPR, EU AI Act, PCI-DSS, HIPAA, CCPA, ITAR).**
> - The codebase is an early experimental implementation and may contain bugs, unverified edge cases, or breaking API changes.
> - This project is shared publicly for **research, peer review, and community testing only**. Use at your own risk.

> **Decoupling reasoning from verification**: Pydantic AI extracts an agent's multi-step intent into a strict Abstract Syntax Tree (AST), and a Microsoft Z3 SMT solver mathematically proves that the execution graph complies with cross-border data sovereignty and safety laws (e.g., GDPR, EU AI Act, PCI-DSS, HIPAA, CCPA, DORA, ITAR, Colorado AI Act, ISO 42001) in **< 5ms** before any external API or chat prose is emitted.

---

## Target Domains

- **RegTech & Data Privacy** — Automated regulatory compliance (GDPR Art. 44-49, CCPA/CPRA, APAC PIPL/DPDPA)
- **AI Governance & Safety** — EU AI Act (Art. 10/12), Colorado AI Act (SB 24-205), ISO/IEC 42001 & NIST AI RMF
- **FinTech & Resilience** — High-frequency financial pipelines, PCI-DSS v4.0 cardholder isolation, DORA operational resilience
- **HealthTech & Life Sciences** — HIPAA § 164.312/514 ePHI containment and Safe Harbor de-identification
- **Defense & Dual-Use Tech** — ITAR (22 CFR 120-130) & EAR (15 CFR 730-774) technical data non-export
- **Autonomous Enterprise Systems** — Multi-agent orchestration with cross-border data sovereignty

---

## The JurisAST Triad

1. **Pillar A: Pydantic-Driven AST Taint Propagation & Field Projections**  
   Data provenance is anchored outside probabilistic prompt context via typed `SecurityLabel` product lattices and immutable `TaintedValue[T]` containers. `TaintedRecord` and `ProjectionNode` isolate subfields to eliminate monotonic label creep.
2. **Pillar B: Latency-Free Non-Interference Proofs & Conversational Firewall**  
   Deterministic mathematical verification via assumption-based incremental SMT solving in `< 5ms`. `ChatOutputSinkNode` actively intercepts conversational prose, preventing LLMs from exfiltrating sensitive context in chat responses.
3. **Pillar C: Tripartite Symbolic Declassification via Constrained Decoding & HITL**  
   Strict schema enforcement and slotted templates bound Shannon mutual information transfer ($I(X;Y) \le \sum \log_2(|S_i|)$). Unbounded free-text summaries are authenticated via cryptographic HMAC-SHA256 human-in-the-loop attestations.

---

## 📚 Documentation Index

| Guide | Description |
|:---|:---|
| 📖 [**Developer Quickstart**](docs/quickstart.md) | Step-by-step tutorial on labels, taint tracking, AST construction, Z3 solving, conversational sinks, and regulatory policies |
| 🏛️ [**System Architecture**](docs/architecture.md) | In-depth technical architecture, neuro-symbolic firewall concept, sequence diagrams, and threat model |
| 📜 [**API Reference**](docs/api_reference.md) | Complete reference for all classes, methods, and types in `jurisast-core`, `jurisast-pydantic`, and `jurisast-policies` |
| 🛠️ [**Issues & Engineering Playbook**](docs/issues_and_resolutions.md) | Exhaustive record of 14 major issues, root causes, SMT mathematical solutions, and verification steps |
| ⚖️ [**Regulatory Mapping**](docs/regulatory_mapping.md) | Formal translation of GDPR, EU AI Act, and PCI-DSS rules into lattice invariants and policy sets |
| 📐 [**Formal Verification**](docs/formal_verification.md) | Mathematical specification of product lattices, non-interference theorems, SMT encodings, and Shannon bounding |
| 🚀 [**Real-World Examples**](examples/README.md) | Live Gemini 2.5 Flash validation demo, enterprise M&A data exfiltration prevention, and GDPR FinTech flows |
| 📊 [**Benchmarks & Evaluation**](docs/benchmarks.md) | Empirical evaluation: JurisAST Z3 firewall vs. Gemini LLM-as-a-Judge and heuristic baselines |
| 🧪 [**Empirical Benchmarking Protocols**](docs/empirical_benchmarking_protocols.md) | Phase-by-phase empirical suite: AgentDojo Banking, TaintBench Memory, Declassification Fuzzing, White-Box Red-Teaming |
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

# Run all 385 unit, property, and integration tests
pytest tests/ -v

# Run real-world examples (requires Gemini API key)
set GEMINI_API_KEY=your_key_here        # Windows
# export GEMINI_API_KEY=your_key_here   # Linux/macOS
python examples/live_gemini_enhancements_demo.py
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
