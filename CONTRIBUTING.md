# Contributing to RedTeam Agent

Thank you for your interest in contributing. This document covers the contribution workflow, coding standards, and how to propose new security rules.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Types of Contributions](#types-of-contributions)
- [Adding Semgrep Rules](#adding-semgrep-rules)
- [Adding Joern CPG Scripts](#adding-joern-cpg-scripts)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)

---

## Getting Started

1. **Fork** the repository and clone your fork
2. Create a branch: `git checkout -b feat/my-new-rule`
3. Make your changes
4. Run tests and linting (see below)
5. Open a pull request against `main`

---

## Development Setup

```bash
# Python agent
pip install -e ".[dev]"

# Run the full test suite
pytest tests/ -v --cov=src/redteam

# Lint (ruff) + type checking (mypy)
ruff check src/ tests/
mypy src/

# Validate all Semgrep rules (requires semgrep installed)
semgrep --config src/redteam/semgrep_rules/ --validate

# Start all services locally
docker compose up --build -d
```

---

## Types of Contributions

### Bug Reports

Open an issue using the **Bug Report** template. Include:
- Steps to reproduce
- Expected vs actual behaviour
- Logs (`docker compose logs agent`)
- Version / commit SHA

### Feature Requests

Open an issue using the **Feature Request** template. Describe:
- The use case
- How it fits the pipeline
- Any implementation ideas

### Rule Proposals

Open an issue with `[rule-proposal]` in the title. See the [Adding Semgrep Rules](#adding-semgrep-rules) section below.

---

## Adding Semgrep Rules

Semgrep rules live in `src/redteam/semgrep_rules/`. Each file maps to one language or cross-language concern.

### Rule Requirements

1. **Use taint-mode for injection classes** where possible (SQLi, XSS, command injection). Direct patterns are acceptable fallbacks for obvious one-liners.
2. **Include `metadata`**: `cwe`, `owasp`, and optionally `references`.
3. **Write a `message`** that explains the vulnerability AND gives a concrete fix.
4. **Add a section comment** grouping related rules.
5. **Test the rule** against a synthetic vulnerable snippet before submitting.

### Rule Structure Template

```yaml
- id: lang-vulnerability-class
  languages: [lang]
  severity: ERROR  # ERROR = critical/high, WARNING = medium/low
  message: >
    One-sentence description of the vulnerability.
    One sentence explaining the correct fix.
  metadata:
    cwe: CWE-89
    owasp: "A03:2021 – Injection"
  pattern-either:
    - pattern: ...
    - pattern: ...
```

### Adding a New Language File

If you're adding rules for a language not yet covered, create `src/redteam/semgrep_rules/<lang>-security.yaml` and open a PR. Update the rules table in `README.md`.

---

## Adding Joern CPG Scripts

Joern scripts live in `src/redteam/joern_scripts/` and use Joern's Scala DSL.

### Script Requirements

1. Accept `cpgFile: String` and `outputFile: String` parameters.
2. Write a JSON array to `outputFile` — each element must have at minimum:
   `{"file": "...", "line": N, "method": "...", "enclosing_method": "...", "severity": "...", "rule": "..."}`
3. Use `.distinct` to deduplicate combined result sets.
4. Prefer **parameter-level taint** (`cpg.method.parameter`) over broad identifier matching to reduce false positives.
5. Add the new script to `_SCRIPT_RULE_MAP` in `src/redteam/analysis/joern_runner.py`.

### Testing Your Script

```bash
# Build a CPG for a test repo
joern-parse /path/to/test/repo --output /tmp/test.cpg

# Run your script
joern --script src/redteam/joern_scripts/my_script.sc \
      --param cpgFile=/tmp/test.cpg \
      --param outputFile=/tmp/out.json

cat /tmp/out.json | python -m json.tool
```

---

## Code Standards

### Python

- **Formatter/linter**: `ruff` (line length 100, Python 3.12 target)
- **Types**: `mypy --strict` must pass with no new errors
- **Tests**: Add tests for any new analysis logic in `tests/`
- **No hardcoded secrets**: CI will block commits containing secret patterns

### Commits

Use conventional commit format:
```
feat: add ruby-security semgrep rules
fix: reduce false positives in ai_code_detector method validity scorer
docs: update README semgrep rules table
test: add tests for prototype pollution joern script
```

---

## Pull Request Process

1. Ensure `pytest tests/ -v` passes
2. Ensure `ruff check src/ tests/` passes
3. Ensure `semgrep --config src/redteam/semgrep_rules/ --validate` passes (if you added/changed rules)
4. Fill out the PR template completely
5. Link any related issues
6. A maintainer will review within a few days

For large changes (new pipeline stage, new UI page), open an issue first to discuss the approach.
