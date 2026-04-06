# Changelog

All notable changes to RedTeam Agent are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.1.0] — 2024-04-06

### Added

**Core pipeline**
- LangGraph scan pipeline: `clone_repo → parse_ast → run_semgrep → detect_ai_code → run_joern → scan_dependencies → llm_code_review → generate_threat_model → synthesize_attack_chains → generate_report`
- FastAPI agent service with scan management REST API
- Rust/Axum webhook service with HMAC-SHA256 GitHub signature verification
- PostgreSQL persistence for scans, findings, attack chains
- Next.js 14 dashboard — findings table, attack chain cards, 30-day trend charts
- SARIF output for GitHub Security tab integration

**Semgrep rules (136 rules, 10 languages)**
- `python-security.yaml` — 22 rules: SQLi, command injection, path traversal, XXE, Jinja2/Mako SSTI, SSRF, zip slip, LDAP, subprocess shell injection, pickle/shelve deserialization
- `java-security.yaml` — 19 rules: SQLi, SpEL injection, command injection, path traversal, SSRF, XXE, ObjectInputStream/XMLDecoder deserialization, Log4Shell (CVE-2021-44228), Thymeleaf/FreeMarker/Velocity SSTI, LDAP, weak ciphers
- `php-security.yaml` — 19 rules: SQLi taint, XSS taint, command injection, eval RCE, file inclusion, XXE, session fixation, unserialize, extract(), type juggling, preg_replace /e, LDAP
- `go-security.yaml` — 11 rules: SQLi, command injection, path traversal, SSRF, TLS InsecureSkipVerify, hardcoded secrets, insecure random, template injection
- `javascript-security.yaml` — 12 rules: Prototype pollution (lodash), NoSQL injection, ReDoS, postMessage origin bypass, path traversal, innerHTML XSS
- `csharp-security.yaml` — 12 rules: SQLi, command injection, path traversal, SSRF, BinaryFormatter/NetDataContractSerializer deserialization, Json.NET TypeNameHandling, LDAP, ViewState MAC
- `ruby-security.yaml` — 14 rules: SQLi (ActiveRecord + Arel), command injection, eval, mass assignment, path traversal, SSRF, ERB SSTI, Marshal.load, html_safe XSS, weak hashes
- `typescript-security.yaml` — 6 rules: Prototype pollution, unsafe type assertions, JWT algorithm confusion
- `secrets-universal.yaml` — 18 patterns: AWS, GCP, GitHub PAT, GitLab, Stripe, Slack, SendGrid, Twilio, SSH private keys, credentials in URLs, OpenAI/Anthropic/Hugging Face keys
- `swift-security.yaml` — 3 rules: Hardcoded credentials, insecure HTTP

**Joern CPG taint analysis (13 scripts)**
- `tainted_sql.sc` — inter-procedural SQLi detection
- `command_injection.sc` — user input → exec/system/popen
- `path_traversal.sc` — user input → file open/read
- `ssrf.sc` — user input → HTTP client URL
- `template_injection.sc` — SSTI: Thymeleaf, FreeMarker, Velocity, Jinja2, Pug, EJS
- `xxe_injection.sc` — user input → XML parser without DTD guard
- `insecure_deserialization.sc` — user input → ObjectInputStream/pickle/unserialize
- `ldap_injection.sc` — user input → LDAP filter without escaping
- `open_redirect.sc` — user URL → sendRedirect/Response.Redirect
- `data_leak.sc` — password/token parameters → log sinks
- `missing_auth.sc` — endpoints missing authentication checks
- `prototype_pollution.sc` — req.body → lodash merge/set/deepMerge (CVE-2025-13465)
- `jwt_algorithm_confusion.sc` — algorithm from JWT header → decode call

**AI-generated code detection (6 independent scorers)**
- Commit signals: AI tool attribution, large atomic dumps
- Code patterns: over-explanatory docstrings, empty stubs, broad catches, burstiness (AAAI 2024)
- Security antipatterns: verify=False, placeholder secrets, weak password hashing, JWT no-verify
- Comment density: >20% comment ratio
- Placeholder strings: example.com, localhost, dummy literals
- Method validity: phantom method detection

**Dependency CVE scanning**
- OSV API integration for Python, Node.js, PHP, Go, Ruby, Java ecosystems
- Framework version fingerprinting

**CI / open source infrastructure**
- GitHub Actions CI: Python lint/types/tests, Semgrep rule validation, secrets scanning (gitleaks), Rust build/clippy, Docker build
- Release workflow: GHCR image publishing on tag
- Issue templates: bug report, feature request, rule proposal
- `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE` (MIT)

[0.1.0]: https://github.com/your-org/redteam-agent/releases/tag/v0.1.0
