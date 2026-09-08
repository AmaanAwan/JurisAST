# Contributing to JurisAST

Thank you for your interest in contributing to **JurisAST**! This document provides guidelines for development, testing, code quality, and submitting pull requests.

---

## Development Setup

### 1. Prerequisites
- Python 3.11 or higher
- Git

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/Startups-Initiatives/JurisAST-Agents.git
cd JurisAST-Agents

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # Linux/macOS

# Install development dependencies
pip install -e ".[dev]"
```

---

## Code Quality & Standards

We enforce strict type safety and code quality standards across the monorepo:

### 1. Formatting & Linting
We use `ruff` for linting and formatting.
```bash
# Run linter
ruff check .

# Fix auto-fixable issues
ruff check --fix .

# Format code
ruff format .
```

### 2. Static Type Checking
All code must pass strict `mypy` checks without type errors.
```bash
mypy libs/
```

---

## Testing Guidelines

JurisAST uses a dual testing approach:
1. **Deterministic Unit Tests (`tests/unit/`)**: Fast, edge-case coverage for model parsing, errors, and algorithms.
2. **Property-Based Verification (`tests/property/`)**: `hypothesis`-driven algebraic proofs verifying mathematical lattice axioms and Z3 theorem prover soundness.

### Running Tests
```bash
# Run all unit tests
pytest tests/unit/ -v

# Run property-based tests
pytest tests/property/ -v

# Run the complete test suite
pytest tests/ -v

# Run with coverage report
pytest --cov=jurisast_core tests/
```

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive prefixes: `feat/`, `fix/`, `docs/`, `refactor/`, `perf/`.
2. **Test Coverage**: Every new feature or bug fix MUST include corresponding unit and/or property tests.
3. **Commit Messages**: Follow Conventional Commits format (`feat: add policy compiler`, `fix: handle empty compartment set`).
4. **Documentation**: Update docstrings and relevant markdown files in `docs/` for any public API changes.
