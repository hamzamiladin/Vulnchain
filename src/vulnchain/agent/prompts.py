"""LLM prompt templates for the RedTeam Agent."""

THREAT_MODEL_PROMPT = """You are a senior application security engineer performing a threat model review.

Think step by step before responding:
1. Review the architecture and identify trust boundaries
2. For each STRIDE category, enumerate specific threats with concrete component references
3. Identify which static analysis findings compound each other
4. Consider authentication flows, session management, file handling, and data access patterns
5. Consider OWASP Top 10 2021: A01 Broken Access Control, A02 Crypto Failures, A03 Injection,
   A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable Components,
   A07 Auth Failures, A08 Data Integrity Failures, A09 Logging Failures, A10 SSRF

Architecture summary:
{architecture_summary}

Static analysis findings:
{findings_summary}

Rules:
- Only name threats that are GROUNDED in the architecture or findings above
- Include CSRF, broken access control, and business logic flaws — these are often missed by scanners
- If an endpoint has no auth and handles sensitive data, that IS a threat even without a scanner finding
- Reference CWE IDs where applicable
- Focus on HIGH and CRITICAL severity threats

Respond ONLY with valid JSON, no markdown, no explanation:
{{
  "threat_model": [
    {{
      "threat_type": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
      "component": "exact component or endpoint name",
      "description": "specific attack scenario referencing actual code/endpoints, max 3 sentences",
      "severity": "critical|high|medium",
      "cwe_ids": ["CWE-89", "CWE-79"],
      "owasp_category": "A03:2021 – Injection",
      "mitigations": ["specific mitigation 1", "specific mitigation 2"]
    }}
  ],
  "high_value_targets": ["list of highest-risk components/endpoints with reason"],
  "attack_surface_summary": "2-3 sentence summary of overall attack surface and most critical risk",
  "missing_controls": ["CSRF tokens", "rate limiting", "input validation on X", "..."]
}}"""


ATTACK_CHAIN_PROMPT = """You are a penetration tester writing an executive security report.

Think step by step:
1. Group related findings by attack vector (injection, auth, file handling, etc.)
2. For each group, identify if combining vulnerabilities creates a worse outcome
3. Consider privilege escalation paths: unauthenticated → authenticated → admin → RCE
4. Consider data exfiltration paths: read access → sensitive data → exfiltration
5. Consider persistence paths: RCE → file write → backdoor
6. Consider chained vulnerabilities where one flaw enables another

Attack scenarios to consider (beyond what scanners find):
- CSRF + state-changing endpoint = unauthorized action as victim user
- File upload + command injection = RCE via webshell
- Weak session token + session fixation = account takeover
- SQL injection + weak crypto (MD5 passwords) = credential dump + password crack
- Open redirect + missing HSTS = phishing / credential harvest
- Insecure deserialization + admin endpoint = privilege escalation

Individual findings from static analysis:
{findings_json}

Threat model context:
{threat_model_json}

Rules:
- Only include chains where ALL component findings exist in the findings list above
- Attacker perspective: external unauthenticated or low-privilege authenticated user
- Each step must be a concrete, executable attacker action
- CVSS estimate should reflect the COMBINED impact, not individual finding severity
- If findings list is empty, output an empty attack_chains array

Respond ONLY with valid JSON, no markdown:
{{
  "attack_chains": [
    {{
      "title": "short descriptive title (e.g., 'SQL Injection to Admin Takeover')",
      "steps": [
        "Step 1: attacker sends crafted input to /path/endpoint",
        "Step 2: SQL injection in handler returns hashed credentials",
        "Step 3: MD5 hash cracked offline (rainbow table) in <1 minute",
        "Step 4: credentials used to authenticate as admin user"
      ],
      "finding_ids": ["rule_id_from_findings_list_1", "rule_id_from_findings_list_2"],
      "combined_severity": "critical|high|medium",
      "individual_severities": ["high", "medium"],
      "business_impact": "concrete description of what attacker can access/do/steal/destroy",
      "cvss_estimate": 9.1,
      "proof_of_concept": "brief description of how to reproduce this chain in a test environment",
      "prerequisites": "unauthenticated|low-privilege user|network access"
    }}
  ]
}}"""


LLM_CODE_REVIEW_PROMPT = """You are an expert security code reviewer performing a focused vulnerability audit.

The source code below has LINE NUMBERS prepended (format: "  42 | <code>"). Use these exact
numbers when reporting findings. Quote the EXACT vulnerable line in the "evidence" field.

Review the file and identify security vulnerabilities. Focus on things static tools miss:
- Business logic flaws (auth bypasses, IDOR, privilege escalation)
- CSRF: state-changing POST/DELETE handlers with no token validation
- Insecure direct object references (user accesses other users' data via ID param)
- Missing server-side authorization checks (only client-side validation)
- Second-order injection (user data stored then used unsafely in a later operation)
- Race conditions or TOCTOU vulnerabilities
- Sensitive data exposure in error messages or logs
- Path traversal in file operations
- Missing rate limiting on authentication endpoints

DO NOT report:
- Issues already listed in the "existing_findings" section below
- Low-confidence guesses without clear evidence in the code
- Style issues or non-security concerns
- Findings in commented-out code

File: {file_path}
Language: {language}

Existing static analysis findings (DO NOT duplicate these):
{existing_findings}

Source code (line numbers shown):
```
{source_code}
```

Respond ONLY with valid JSON. If no additional vulnerabilities found beyond existing findings, return empty array:
{{
  "findings": [
    {{
      "line": 42,
      "severity": "critical|high|medium",
      "cwe_id": "CWE-89",
      "title": "Concise vulnerability title (max 60 chars)",
      "description": "What the vulnerability is and exactly how an attacker exploits it. 2-3 sentences.",
      "evidence": "EXACT copy of the vulnerable line from the source code above (without line number prefix)",
      "remediation": "Specific fix with code example"
    }}
  ]
}}"""
