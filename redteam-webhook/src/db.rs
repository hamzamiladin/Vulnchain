use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    // Create scans table (idempotent)
    sqlx::query(
        r#"
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
        "#,
    )
    .execute(pool)
    .await?;

    // Create findings table (idempotent)
    sqlx::query(
        r#"
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
        "#,
    )
    .execute(pool)
    .await?;

    // Create attack_chains table (idempotent)
    sqlx::query(
        r#"
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
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn create_scan(
    pool: &PgPool,
    repo_url: &str,
    commit_sha: &str,
    repo_name: &str,
    pr_number: i64,
) -> Result<Uuid> {
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO scans (repo_url, commit_sha, repo_name, pr_number, status)
        VALUES ($1, $2, $3, $4, 'pending')
        RETURNING id
        "#,
    )
    .bind(repo_url)
    .bind(commit_sha)
    .bind(repo_name)
    .bind(pr_number as i32)
    .fetch_one(pool)
    .await?;
    Ok(id)
}
