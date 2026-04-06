# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| Older tags | Security fixes backported on a best-effort basis |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in RedTeam Agent, please report it via one of these channels:

1. **GitHub Private Vulnerability Reporting** (preferred): Use the
   [Security tab → Report a vulnerability](https://github.com/your-org/redteam-agent/security/advisories/new)
   feature on this repository.

2. **Email**: Send details to `security@your-org.com` with the subject line
   `[SECURITY] RedTeam Agent vulnerability`.

### What to Include

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code or commands, if possible)
- The version/commit you tested against
- Any suggested fix, if you have one

### What to Expect

- **Acknowledgement** within 48 hours
- **Initial assessment** within 5 business days
- **Fix and coordinated disclosure** within 90 days for valid reports
- Credit in the release notes (if desired)

## Scope

The following are **in scope**:

- The Python agent (`src/redteam/`)
- The Rust webhook service (`redteam-webhook/`)
- The Next.js dashboard (`dashboard/`)
- Docker configuration and container security

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report upstream to OSV, GitHub Advisory)
- Findings produced *by* the scanner against external repos (that's the point)
- Social engineering or phishing attempts

## Security Design Notes

- The agent clones repos into isolated `/tmp/redteam-scans/<scan_id>/` directories
- No user-supplied code is executed — Tree-sitter, Semgrep, and Joern analyse files statically
- The Rust webhook service verifies GitHub HMAC-SHA256 signatures before processing any event
- `ANTHROPIC_API_KEY` and `GITHUB_APP_PRIVATE_KEY_PATH` must never be committed — see `.gitignore`
- The database does not store repository source code, only findings metadata
