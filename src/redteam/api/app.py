"""FastAPI REST API endpoints for the dashboard."""

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from redteam.config import get_settings

logger = logging.getLogger(__name__)

_CREATE_STMTS = [
    """
    CREATE TABLE IF NOT EXISTS scans (
        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        repo_url        TEXT NOT NULL,
        commit_sha      TEXT,
        repo_name       TEXT NOT NULL,
        pr_number       INTEGER,
        status          TEXT NOT NULL DEFAULT 'pending',
        started_at      TIMESTAMPTZ,
        completed_at    TIMESTAMPTZ,
        error_message   TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        source          TEXT NOT NULL,
        rule_id         TEXT NOT NULL,
        severity        TEXT NOT NULL,
        file_path       TEXT NOT NULL,
        line_start      INTEGER,
        line_end        INTEGER,
        message         TEXT NOT NULL,
        fix_suggestion  TEXT,
        is_ai_generated BOOLEAN NOT NULL DEFAULT false,
        ai_confidence   FLOAT,
        raw_json        JSONB,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_chains (
        id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        title               TEXT NOT NULL,
        combined_severity   TEXT NOT NULL,
        steps               JSONB NOT NULL DEFAULT '[]',
        finding_ids         JSONB NOT NULL DEFAULT '[]',
        business_impact     TEXT NOT NULL DEFAULT '',
        cvss_score          FLOAT,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
]

# Schema evolution — idempotent column additions/renames for existing databases
_EVOLVE_STMTS = [
    # Rename pr_sha → commit_sha (previous schema used pr_sha)
    """
    DO $$ BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'scans' AND column_name = 'pr_sha'
        ) THEN
            ALTER TABLE scans RENAME COLUMN pr_sha TO commit_sha;
        END IF;
    END $$
    """,
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS commit_sha TEXT",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS error_message TEXT",
    # Expand source constraint to include llm_review and future sources
    # Drop both possible constraint names (postgres auto-name vs our name)
    """
    DO $$ BEGIN
        ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_source_check;
        ALTER TABLE findings DROP CONSTRAINT IF EXISTS ck_findings_source;
        ALTER TABLE findings ADD CONSTRAINT ck_findings_source
            CHECK (source IN ('semgrep','joern','ai_detector','llm_review','dependency','progpilot','pysa'));
    EXCEPTION WHEN others THEN NULL;
    END $$
    """,
    # Convert finding_ids from UUID[] to JSONB if on old schema
    """
    DO $$ BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'attack_chains'
              AND column_name = 'finding_ids'
              AND data_type = 'ARRAY'
        ) THEN
            ALTER TABLE attack_chains ALTER COLUMN finding_ids TYPE JSONB
                USING to_jsonb(ARRAY[]::TEXT[]);
        END IF;
    END $$
    """,
]


@asynccontextmanager
async def _lifespan(app: FastAPI):
    from redteam.db.connection import close_pool, get_conn
    async with get_conn() as conn:
        for stmt in _CREATE_STMTS:
            await conn.execute(stmt)
        for stmt in _EVOLVE_STMTS:
            await conn.execute(stmt)
    logger.info("Database schema ensured")
    yield
    await close_pool()


def create_app() -> FastAPI:
    settings = get_settings()
    api = FastAPI(title="RedTeam Agent API", version="0.1.0", lifespan=_lifespan)

    api.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @api.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/api/scans")
    async def list_scans(
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
    ) -> dict[str, Any]:
        from redteam.db.connection import get_conn
        offset = (page - 1) * page_size
        async with get_conn() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM scans")
            rows = await conn.fetch(
                """
                SELECT s.*,
                    COUNT(f.id) AS findings_count,
                    COUNT(CASE WHEN f.severity IN ('critical','high') THEN 1 END) AS critical_high_count,
                    COUNT(ac.id) AS chain_count
                FROM scans s
                LEFT JOIN findings f ON f.scan_id = s.id
                LEFT JOIN attack_chains ac ON ac.scan_id = s.id
                GROUP BY s.id ORDER BY s.created_at DESC LIMIT $1 OFFSET $2
                """,
                page_size, offset,
            )
        return {"total": total, "page": page, "page_size": page_size, "scans": [dict(r) for r in rows]}

    @api.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict[str, Any]:
        from redteam.db.connection import get_conn
        async with get_conn() as conn:
            scan = await conn.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")
            findings = await conn.fetch(
                "SELECT * FROM findings WHERE scan_id = $1 ORDER BY severity, created_at", scan_id
            )
            chains = await conn.fetch(
                "SELECT * FROM attack_chains WHERE scan_id = $1 ORDER BY combined_severity", scan_id
            )
        return {"scan": dict(scan), "findings": [dict(f) for f in findings], "attack_chains": [dict(c) for c in chains]}

    @api.get("/api/scans/{scan_id}/report")
    async def get_report(scan_id: str) -> dict[str, str]:
        from redteam.db.connection import get_conn
        async with get_conn() as conn:
            scan = await conn.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")
        return {"report": "Report not available — regenerate from findings."}

    @api.get("/api/stats")
    async def get_stats() -> dict[str, Any]:
        from redteam.db.connection import get_conn
        async with get_conn() as conn:
            total_scans = await conn.fetchval("SELECT COUNT(*) FROM scans") or 0
            total_findings = await conn.fetchval("SELECT COUNT(*) FROM findings") or 0
            critical_findings = await conn.fetchval(
                "SELECT COUNT(*) FROM findings WHERE severity IN ('critical','high')"
            ) or 0
            daily_rows = await conn.fetch(
                """
                SELECT DATE(created_at) AS date, COUNT(*) AS count
                FROM findings
                WHERE created_at >= now() - interval '30 days'
                GROUP BY DATE(created_at)
                ORDER BY date ASC
                """
            )
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "daily": [{"date": str(r["date"]), "count": r["count"]} for r in daily_rows],
        }

    @api.get("/api/repos")
    async def list_repos() -> dict[str, Any]:
        from redteam.db.connection import get_conn
        async with get_conn() as conn:
            rows = await conn.fetch(
                """
                SELECT DISTINCT ON (repo_url) repo_url, repo_name, status, created_at,
                    (SELECT COUNT(*) FROM findings WHERE scan_id = id) AS last_scan_findings
                FROM scans ORDER BY repo_url, created_at DESC
                """
            )
        return {"repos": [dict(r) for r in rows]}

    @api.get("/api/repos/{repo_name}/trend")
    async def repo_trend(repo_name: str) -> dict[str, Any]:
        from redteam.db.connection import get_conn
        async with get_conn() as conn:
            rows = await conn.fetch(
                """
                SELECT s.id, s.created_at, s.pr_number,
                    COUNT(f.id) AS finding_count,
                    COUNT(CASE WHEN f.severity = 'critical' THEN 1 END) AS critical_count,
                    COUNT(CASE WHEN f.severity = 'high' THEN 1 END) AS high_count
                FROM scans s LEFT JOIN findings f ON f.scan_id = s.id
                WHERE s.repo_name = $1
                GROUP BY s.id ORDER BY s.created_at ASC LIMIT 50
                """,
                repo_name,
            )
        return {"repo_name": repo_name, "trend": [dict(r) for r in rows]}

    class TriggerScanRequest(BaseModel):
        repo_url: str
        pr_number: Optional[int] = None
        commit_sha: Optional[str] = None

    @api.post("/api/scans", status_code=202)
    async def trigger_scan(request: TriggerScanRequest) -> dict[str, str]:
        from redteam.db.connection import get_conn
        scan_id = str(uuid.uuid4())
        repo_name = request.repo_url.rstrip("/").split("/")[-1]

        async with get_conn() as conn:
            await conn.execute(
                "INSERT INTO scans (id, repo_url, repo_name, pr_number, commit_sha, status) VALUES ($1,$2,$3,$4,$5,'pending')",
                scan_id, request.repo_url, repo_name, request.pr_number, request.commit_sha,
            )

        asyncio.create_task(_run_scan_background(scan_id, request.repo_url, request.pr_number, request.commit_sha))
        return {"scan_id": scan_id, "status": "accepted"}

    class InternalScanRequest(BaseModel):
        scan_id: str
        clone_url: str
        sha: Optional[str] = None

    @api.post("/internal/scan", status_code=202)
    async def internal_trigger_scan(request: InternalScanRequest) -> dict[str, str]:
        """Called by the webhook service after creating the scan DB record."""
        from redteam.db.connection import get_conn
        async with get_conn() as conn:
            exists = await conn.fetchval("SELECT 1 FROM scans WHERE id = $1", request.scan_id)
            if not exists:
                raise HTTPException(status_code=404, detail="Scan record not found")
        asyncio.create_task(_run_scan_background(request.scan_id, request.clone_url, None, request.sha))
        return {"scan_id": request.scan_id, "status": "accepted"}

    async def _run_scan_background(
        scan_id: str,
        repo_url: str,
        pr_number: Optional[int],
        commit_sha: Optional[str],
    ) -> None:
        from redteam.agent.graph import build_graph
        from redteam.db.connection import get_conn

        graph = build_graph()
        initial_state = {
            "repo_url": repo_url, "pr_number": pr_number, "commit_sha": commit_sha,
            "scan_id": scan_id, "is_local": False, "repo_path": "",
            "source_files": [], "commit_history": [], "ast_results": [],
            "semgrep_findings": [], "ai_code_segments": [], "joern_findings": [],
            "dependency_findings": [], "tech_profile": {},
            "llm_review_findings": [],
            "threat_model": None, "attack_chains": [],
            "report_markdown": "", "report_sarif": {}, "error": None,
        }
        try:
            async with get_conn() as conn:
                await conn.execute(
                    "UPDATE scans SET status='running', started_at=$1 WHERE id=$2",
                    datetime.now(tz=timezone.utc), scan_id,
                )
            final_state = await graph.ainvoke(initial_state)
            status = "failed" if final_state.get("error") else "done"

            async with get_conn() as conn:
                await conn.execute(
                    "UPDATE scans SET status=$1, completed_at=$2, error_message=$3 WHERE id=$4",
                    status, datetime.now(tz=timezone.utc), final_state.get("error"), scan_id,
                )
                for f in final_state.get("semgrep_findings", []):
                    await conn.execute(
                        "INSERT INTO findings (scan_id,source,rule_id,severity,file_path,line_start,line_end,message,fix_suggestion,raw_json) VALUES ($1,'semgrep',$2,$3,$4,$5,$6,$7,$8,$9)",
                        scan_id, f.rule_id, f.severity, f.file_path, f.line_start, f.line_end, f.message, f.fix_suggestion, json.dumps(f.raw),
                    )
                for f in final_state.get("joern_findings", []):
                    await conn.execute(
                        "INSERT INTO findings (scan_id,source,rule_id,severity,file_path,line_start,message,raw_json) VALUES ($1,'joern',$2,$3,$4,$5,$6,$7)",
                        scan_id, f.rule_id, f.severity, f.file_path, f.line, f"CPG: {f.method_name}", json.dumps(f.raw),
                    )
                for f in final_state.get("dependency_findings", []):
                    await conn.execute(
                        "INSERT INTO findings (scan_id,source,rule_id,severity,file_path,line_start,message,raw_json) VALUES ($1,'dependency',$2,$3,$4,0,$5,$6)",
                        scan_id,
                        f.cve_id,
                        f.severity,
                        f.manifest_file,
                        f"{f.package_name}@{f.installed_version}: {f.title}"
                        + (f" (fixed: {f.fixed_version})" if f.fixed_version else ""),
                        json.dumps({
                            "package": f.package_name,
                            "version": f.installed_version,
                            "ecosystem": f.ecosystem,
                            "cve_id": f.cve_id,
                            "cvss_score": f.cvss_score,
                            "fixed_version": f.fixed_version,
                            "description": f.description,
                        }),
                    )
                for f in final_state.get("llm_review_findings", []):
                    await conn.execute(
                        "INSERT INTO findings (scan_id,source,rule_id,severity,file_path,line_start,message,raw_json) VALUES ($1,'llm_review',$2,$3,$4,$5,$6,$7)",
                        scan_id,
                        f.get("cwe_id", "llm-review"),
                        f.get("severity", "medium"),
                        f.get("file_path", "unknown"),
                        f.get("line", 0),
                        f"{f.get('title', '')} — {f.get('description', '')}",
                        json.dumps(f),
                    )
                for chain in final_state.get("attack_chains", []):
                    await conn.execute(
                        "INSERT INTO attack_chains (scan_id,title,combined_severity,steps,finding_ids,business_impact,cvss_score) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                        scan_id, chain.title, chain.combined_severity,
                        json.dumps(chain.steps), json.dumps(chain.finding_ids), chain.business_impact, chain.cvss_estimate,
                    )
        except Exception as exc:
            logger.error("Background scan %s failed: %s", scan_id, exc)
            try:
                from redteam.db.connection import get_conn as _gc
                async with _gc() as conn:
                    await conn.execute(
                        "UPDATE scans SET status='failed', completed_at=$1, error_message=$2 WHERE id=$3",
                        datetime.now(tz=timezone.utc), str(exc), scan_id,
                    )
            except Exception:
                logger.error("Failed to update scan status to failed for %s", scan_id)

    return api
