# Vulnchain

**Autonomous AI-powered security auditing for software teams.**

Vulnchain scans any Git repository and produces a prioritised vulnerability report with attack chains, a STRIDE threat model, and an AI-generated code risk score — all in one `docker compose up`. No SaaS account, no API tokens beyond your own Claude key.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/your-org/vulnchain/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/vulnchain/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-compose-blue.svg)](docker-compose.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## Why Vulnchain?

| Feature | Vulnchain | Semgrep OSS | CodeQL | Snyk |
|---------|:---:|:---:|:---:|:---:|
| Multi-engine SAST (Semgrep + CPG taint) | ✅ | ❌ | partial | ❌ |
| Joern inter-procedural taint (13 scripts) | ✅ | ❌ | ✅ | ❌ |
| AI-generated code detection | ✅ | ❌ | ❌ | ❌ |
| LLM code review (Claude) | ✅ | ❌ | ❌ | ❌ |
| Attack chain synthesis | ✅ | ❌ | ❌ | ❌ |
| STRIDE threat model | ✅ | ❌ | ❌ | ❌ |
| CVE scanning (OSV) | ✅ | ❌ | ❌ | ✅ |
| 10-language Semgrep rules (135+ rules) | ✅ | partial | ❌ | partial |
| Universal secrets scanner (18 patterns) | ✅ | partial | ❌ | ✅ |
| SARIF output | ✅ | ✅ | ✅ | ✅ |
| Fully self-hosted, no auth required | ✅ | ✅ | ❌ | ❌ |

---

## How It Works

```
GitHub Webhook (Rust :9000)
        │  push / PR event
        ▼
  Agent API (Python / FastAPI :8080)
        │  spawns LangGraph pipeline
        ▼
┌─────────────────────────────────────────────────────┐
│                   Scan Pipeline                      │
│                                                     │
│  clone_repo → parse_ast → run_semgrep               │
│      → detect_ai_code → run_joern                   │
│      → scan_dependencies → llm_code_review          │
│      → generate_threat_model                        │
│      → synthesize_attack_chains → generate_report   │
└─────────────────────────────────────────────────────┘
        │
        ▼
  PostgreSQL 16  ←→  Next.js Dashboard (:3000)
```

### Services

| Service     | Stack                 | Port | Purpose                       |
|-------------|-----------------------|------|-------------------------------|
| `agent`     | Python 3.12 / FastAPI | 8080 | Scan pipeline + REST API      |
| `webhook`   | Rust / Axum           | 9000 | GitHub webhook receiver       |
| `dashboard` | Next.js 14            | 3000 | Web UI — findings + reports   |
| `db`        | PostgreSQL 16         | 5432 | Persistence                   |

---

## Quick Start

### Requirements

- Docker + Docker Compose v2
- An [Anthropic API key](https://console.anthropic.com/)

```bash
git clone https://github.com/your-org/vulnchain
cd vulnchain
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY at minimum
docker compose up --build -d
```

First build takes ~5–10 min (downloads Joern, Java 21, Semgrep, Rust toolchain, Node modules).

### Run your first scan

```bash
# Trigger via API
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/digininja/DVWA"}'

# → {"scan_id": "...", "status": "accepted"}

# Poll for results
curl http://localhost:8080/api/scans/<scan_id>

# Or open the dashboard
open http://localhost:3000
```

### CLI (without Docker)

```bash
pip install -e ".[dev]"
export ANTHROPIC_API_KEY=sk-ant-...
export DATABASE_URL=postgresql://vulnchain:vulnchain@localhost:5432/vulnchain

vulnchain scan https://github.com/digininja/DVWA
vulnchain serve --port 8080
```

---

## Scan Pipeline — Step by Step

| Step | What it does |
|------|-------------|
| **clone_repo** | Clones target repo or checks out a specific commit/PR SHA |
| **parse_ast** | Tree-sitter: extracts languages, imports, function names, route definitions for architecture fingerprinting |
| **run_semgrep** | 135+ local rules across 10 languages — taint-mode for multi-hop injection flows, no auth required |
| **detect_ai_code** | 6-scorer heuristic engine detects AI-generated code: commit metadata, burstiness, security antipatterns, comment density, placeholder strings, phantom methods |
| **run_joern** | 13 CPG taint scripts for inter-procedural analysis: SQLi, SSRF, SSTI, prototype pollution, JWT confusion, XXE, deserialization, LDAP, and more |
| **scan_dependencies** | Parses all lockfiles, batch-queries [OSV API](https://osv.dev) for CVEs, fingerprints framework versions |
| **llm_code_review** | Sends high-risk files to Claude with prepended line numbers; anchors findings to actual code via evidence-snippet search |
| **generate_threat_model** | Claude generates a full STRIDE threat model grounded in discovered architecture and findings, mapped to OWASP Top 10 2021 and CWE IDs |
| **synthesize_attack_chains** | Claude combines findings into realistic multi-step exploits (e.g. SQL injection → credential dump → admin takeover) with CVSS estimates |
| **generate_report** | Assembles Markdown + SARIF output, ready for GitHub Security tab import |

---

## Semgrep Rules (135+ rules, 10 languages, no auth)

All rules live in `src/vulnchain/semgrep_rules/`. Run locally with no Semgrep account.

| File | Language | Rules | Key Coverage |
|------|----------|-------|-------------|
| `python-security.yaml` | Python | 22 | SQLi, command injection, path traversal, pickle/shelve deserialization, XXE, Jinja2/Mako SSTI, SSRF, zip slip, LDAP injection, subprocess shell injection |
| `java-security.yaml` | Java | 19 | SQLi, SpEL injection, command injection, path traversal, SSRF, XXE, deserialization (ObjectInputStream/XMLDecoder), Log4Shell, Thymeleaf/FreeMarker/Velocity SSTI, open redirect, LDAP, weak ciphers |
| `php-security.yaml` | PHP | 19 | SQLi taint, XSS taint, command injection, eval/assert RCE, file inclusion, XXE, session fixation, unserialize, extract(), type juggling, preg_replace /e, open redirect, LDAP, weak hashes |
| `go-security.yaml` | Go | 11 | SQLi, command injection, path traversal, SSRF, TLS `InsecureSkipVerify`, hardcoded secrets, insecure random, open redirect, template injection, weak ciphers |
| `javascript-security.yaml` | JavaScript | 12 | Prototype pollution, NoSQL injection, ReDoS, postMessage origin bypass, path traversal, `innerHTML` XSS, JWT no-algorithm, `eval` |
| `csharp-security.yaml` | C# | 12 | SQLi, command injection, path traversal, SSRF, XXE, BinaryFormatter/NetDataContractSerializer deserialization, Json.NET TypeNameHandling, LDAP, ViewState MAC bypass, weak ciphers |
| `ruby-security.yaml` | Ruby | 14 | SQLi (ActiveRecord + raw Arel), command injection, `eval`, mass assignment, path traversal, SSRF, ERB SSTI, open redirect, `Marshal.load`, `html_safe` XSS, weak hashes, ReDoS |
| `typescript-security.yaml` | TypeScript | 6 | Lodash prototype pollution, unsafe `JSON.parse as Type`, `req.body as any` bypass, JWT algorithm confusion, hardcoded secrets |
| `secrets-universal.yaml` | All | 18 | AWS (AKIA), GCP (AIza), GitHub PAT, GitLab token, Stripe, Slack, SendGrid, Twilio, SSH private keys, credentials in URLs, JWT tokens, OpenAI/Anthropic/Hugging Face keys |
| `swift-security.yaml` | Swift | 3 | Hardcoded credentials, insecure HTTP, `allowsArbitraryLoads` |

**Total: 136 rules across 10 languages**

---

## Joern CPG Scripts (inter-procedural taint analysis)

Joern builds a Code Property Graph for the entire repo and runs inter-procedural data-flow analysis — catching vulnerabilities that span multiple files and function calls that pattern-matching tools miss.

| Script | Rule ID | Severity | Coverage |
|--------|---------|----------|---------|
| `tainted_sql.sc` | `tainted-sql-injection` | critical | User input → SQL sinks across call boundaries |
| `command_injection.sc` | `tainted-command-injection` | critical | User input → exec/system/popen |
| `path_traversal.sc` | `tainted-path-traversal` | high | User input → file open/read sinks |
| `ssrf.sc` | `tainted-ssrf` | high | User input → HTTP client URL arguments |
| `template_injection.sc` | `template-injection-ssti` | critical | User input → Thymeleaf/FreeMarker/Velocity/Jinja2/Pug/EJS render |
| `xxe_injection.sc` | `xxe-injection` | high | User input → XML parser without DTD guard |
| `insecure_deserialization.sc` | `insecure-deserialization` | critical | User input → ObjectInputStream/XMLDecoder/pickle/unserialize |
| `ldap_injection.sc` | `ldap-injection` | high | User input → LDAP filter without escaping |
| `open_redirect.sc` | `open-redirect` | medium | User URL → sendRedirect/Response.Redirect |
| `data_leak.sc` | `sensitive-data-in-logs` | high | Password/token parameters → log sinks |
| `missing_auth.sc` | `missing-authorization` | high | Endpoints missing authentication checks |
| `prototype_pollution.sc` | `prototype-pollution` | high | req.body → lodash merge/set/deepMerge |
| `jwt_algorithm_confusion.sc` | `jwt-algorithm-confusion` | critical | Algorithm from JWT header → decode call; `algorithms=None` |

---

## AI-Generated Code Detection

The `detect_ai_code` step flags files that show statistical signatures of AI generation. This matters because [Veracode's 2025 GenAI Code Security Report](https://www.veracode.com/resources/state-of-software-security-genai) found **45% of AI-generated code introduces security flaws** — at a higher rate than human-written code.

Six independent scorers are combined with learned weights:

| Scorer | Weight | What it measures |
|--------|--------|-----------------|
| Commit signals | 30% | AI tool attribution in commit messages (Copilot, Cursor, Codeium); large atomic dumps (200+ additions, 0 deletions) |
| Code patterns | 25% | Over-explanatory docstrings; empty stub functions; broad `except Exception`; TODO placeholders; **burstiness** (low line-length CV < 0.35 — AAAI 2024) |
| Security antipatterns | 25% | `verify=False`, `InsecureSkipVerify`, placeholder secrets (`"changeme"`, `"your-secret-key"`), SHA256 for passwords, JWT `verify_signature=False`, timing-unsafe `==` |
| Comment density | 10% | >20% comment-to-code ratio — AI over-documentation |
| Placeholder strings | 5% | `example.com`, `localhost`, `dummy_key`, `foo`/`bar` literals |
| Method validity | 5% | High ratio of called method names not found in stdlib or imports |

Files scoring ≥ 0.40 are flagged with a confidence score and the triggering signals listed in the report.

**Research basis:** arxiv:2601.17406 (97.2% F1 AI fingerprinting), AAAI 2024 burstiness metric (AUC 0.56 → 0.87), Veracode 2025 GenAI Code Security Report.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/scans` | List scans (`?page=1&page_size=20`) |
| `POST` | `/api/scans` | Trigger a scan: `{"repo_url": "..."}` |
| `GET` | `/api/scans/{id}` | Scan details with findings + attack chains |
| `GET` | `/api/scans/{id}/report` | Full Markdown report |
| `GET` | `/api/stats` | Aggregate stats + 30-day trend |
| `GET` | `/api/repos` | Distinct repositories scanned |
| `GET` | `/api/repos/{name}/trend` | Per-repo finding trend |
| `POST` | `/internal/scan` | Internal — used by the webhook service |

### Finding Object

```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "source": "semgrep | joern | llm_review | dependency",
  "rule_id": "php-sql-injection-taint",
  "severity": "critical | high | medium | low | info",
  "file_path": "src/login.php",
  "line_start": 42,
  "message": "User input flows into SQL query without sanitization",
  "fix_suggestion": "Use prepared statements with PDO or MySQLi bind_param()",
  "is_ai_generated": false,
  "ai_confidence": null,
  "cve_id": null
}
```

### Attack Chain Object

```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "title": "SQL Injection to Admin Takeover",
  "combined_severity": "critical",
  "steps": ["Step 1: Extract credentials via SQLi", "Step 2: Crack MD5 hash offline", "Step 3: Login as admin"],
  "finding_ids": ["php-sql-injection-taint", "php-weak-hash"],
  "business_impact": "Full database read/write, admin session hijack, potential RCE",
  "cvss_score": 9.1
}
```

---

## GitHub PR Scanning (Automatic)

1. Create a GitHub App with `pull_request` events + `contents: read` + `pull_requests: write` permissions
2. Install on your org/repo
3. Set `GITHUB_APP_ID`, `GITHUB_WEBHOOK_SECRET`, `GITHUB_APP_PRIVATE_KEY_PATH` in `.env`
4. Point the webhook to `http://<your-host>:9000/webhook`

The Rust webhook service verifies HMAC-SHA256 signatures, creates a scan record, and forwards to the agent. When the scan completes, a comment is posted on the PR with a findings summary.

---

## Project Structure

```
vulnchain/
├── LICENSE
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── docker-compose.yml
├── Dockerfile.agent
├── pyproject.toml
├── .env.example
│
├── src/vulnchain/
│   ├── main.py                    # CLI entrypoint (typer)
│   ├── config.py                  # Pydantic settings
│   ├── agent/
│   │   ├── graph.py               # LangGraph pipeline
│   │   ├── nodes.py               # Pipeline step implementations
│   │   ├── state.py               # ScanState TypedDict
│   │   ├── prompts.py             # LLM prompt templates
│   │   └── pr_comment.py          # GitHub PR comment formatter
│   ├── analysis/
│   │   ├── semgrep_scanner.py     # Semgrep subprocess wrapper
│   │   ├── joern_runner.py        # Joern CPG runner (13 scripts)
│   │   ├── ai_code_detector.py    # AI-generated code detector (6 scorers)
│   │   ├── dependency_scanner.py  # OSV CVE + tech fingerprinting
│   │   ├── ast_parser.py          # Tree-sitter file analysis
│   │   └── models.py              # Dataclasses (Finding, JoernFinding, etc.)
│   ├── semgrep_rules/             # 136 local Semgrep rules (10 languages)
│   ├── joern_scripts/             # 13 Joern CPG taint analysis scripts
│   ├── api/
│   │   └── app.py                 # FastAPI app + endpoints
│   ├── db/
│   │   ├── connection.py          # asyncpg connection pool
│   │   ├── models.py              # SQLAlchemy ORM models
│   │   └── migrations/            # SQL migration files
│   ├── ingestion/                 # Repo cloning + file reading
│   └── reporting/                 # Markdown + SARIF report generators
│
├── dashboard/                     # Next.js 14 frontend
│   ├── src/app/
│   │   ├── page.tsx               # Scans list + stats
│   │   └── scan/[id]/page.tsx     # Scan detail page
│   └── src/components/
│       ├── FindingsTable.tsx      # Severity/source badges
│       └── AttackChainCard.tsx    # Attack chain display
│
├── vulnchain-webhook/               # Rust webhook receiver
│   ├── src/
│   │   ├── main.rs                # Axum server setup
│   │   ├── webhook.rs             # GitHub webhook + HMAC-SHA256 verification
│   │   ├── github.rs              # GitHub API client (app auth)
│   │   └── db.rs                  # DB helpers
│   └── Cargo.toml
│
└── tests/                         # pytest test suite
    ├── test_semgrep_scanner.py
    ├── test_ai_detector.py
    └── conftest.py
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://vulnchain:vulnchain@localhost:5432/vulnchain` | PostgreSQL connection string |
| `ANTHROPIC_API_KEY` | — | **Required.** Used for LLM review, threat model, attack chains |
| `LLM_MODEL` | `claude-sonnet-4-6` | Claude model ID |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `GITHUB_APP_ID` | `0` | GitHub App ID (optional) |
| `GITHUB_WEBHOOK_SECRET` | — | HMAC-SHA256 secret for webhook verification |
| `GITHUB_APP_PRIVATE_KEY_PATH` | `./github-app.pem` | Path to GitHub App private key PEM |
| `AGENT_URL` | `http://agent:8080` | Internal agent URL used by webhook service |
| `SCAN_SANDBOX_DIR` | `/tmp/vulnchain-scans` | Where repos are cloned |
| `MAX_REPO_SIZE_MB` | `500` | Reject repos larger than this |
| `SEMGREP_TIMEOUT_SECONDS` | `120` | Semgrep per-scan timeout |
| `JOERN_TIMEOUT_SECONDS` | `300` | Joern per-scan timeout (JVM startup ~15s) |
| `LOG_LEVEL` | `INFO` | Python log level |

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=src/vulnchain

# Lint + typecheck
ruff check src/ tests/
mypy src/

# Validate all Semgrep rules
semgrep --config src/vulnchain/semgrep_rules/ --validate

# Rebuild just the agent after code changes
docker compose up --build -d agent

# Tail logs
docker compose logs -f agent
```

---

## Troubleshooting

**`DB connection error` on agent startup**
The `depends_on: condition: service_healthy` in `docker-compose.yml` handles ordering. If you see this, run `docker compose ps` and wait for `db` to show `healthy`.

**Semgrep exits code 7**
A registry token is interfering. Ensure `SEMGREP_APP_TOKEN` is not set in your environment — the scanner runs local-only.

**Joern times out on large repos**
Increase `JOERN_TIMEOUT_SECONDS`. Joern failures are non-fatal; the pipeline continues with all other findings.

**LLM findings missing line numbers**
The pipeline searches for each evidence snippet in the actual file to anchor line numbers. If the evidence field from Claude doesn't match any real code, line defaults to 0. Check agent logs for `[anchor_line]`.

**`findings_source_check` constraint violation**
Old DB schema. Restart the agent — it drops and recreates this constraint on startup.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas we especially want help with:
- New Semgrep rules (open an issue with `[rule-proposal]` in the title)
- New Joern CPG scripts for additional vulnerability classes
- Dashboard improvements
- Performance benchmarks against real vulnerable repos (DVWA, WebGoat, OWASP Juice Shop)

---

## Security

If you discover a security vulnerability in Vulnchain itself, please follow the process in [SECURITY.md](SECURITY.md). Do not open a public issue.

---

## License

[MIT](LICENSE) — Copyright (c) 2024 Vulnchain Contributors
