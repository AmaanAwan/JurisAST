# Security Policy — JurisAST

## Supported Versions

| Version | Supported | Notes |
|:---|:---|:---|
| `0.1.x` | ⚠️ Pre-Release | Active experimental development — NOT yet audited or production-tested |

> [!CAUTION]
> ### ⚠️ Pre-Release & Research Advisory
> JurisAST is currently in **active development and experimental testing**. It has **not yet undergone independent security audits, penetration testing, or comprehensive production verification**. 
> - **Do NOT trust or rely on JurisAST as a primary or sole defense mechanism** in production systems dealing with real-world sensitive data, financial assets, or regulatory obligations.
> - Until rigorous field validation is complete, treat this codebase as an experimental research tool.

---

## Threat Model & Security Architecture

JurisAST is specifically engineered to mitigate security vulnerabilities arising from the integration of Large Language Models (LLMs) into autonomous multi-agent pipelines:

### 1. Indirect Prompt Injection
- **Threat**: Untrusted external documents (web pages, emails, database records) contain embedded adversarial instructions directing the LLM to invoke exfiltration tools.
- **Defense**: Provenance tracking anchors taint metadata outside the LLM context window. Regardless of what the LLM generates, the Z3 firewall deterministically blocks unauthorized sink calls before network dispatch.

### 2. Multi-Hop Laundering
- **Threat**: An agent passes sensitive data to a secondary helper agent in an attempt to wash taint labels.
- **Defense**: `AgentHandoffNode` preserves and joins security labels across multi-agent boundaries.

### 3. Fail-Closed Default
- In the event of a solver timeout, unexpected SMT exception, or parsing error, JurisAST defaults to **fail-closed** (`fail_closed=True`), aborting the execution to prevent unverified data transmission.

---

## Reporting a Vulnerability

If you discover a security vulnerability or bypass in JurisAST, please report it privately:

1. **Do NOT** open a public GitHub issue.
2. Email the maintainers with:
   - Detailed description of the vulnerability
   - Reproduction steps or proof-of-concept script
   - Expected vs. actual behavior
3. We will respond within **48 hours** with an initial assessment and timeline for a patch.
