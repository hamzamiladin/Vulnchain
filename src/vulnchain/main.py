"""RedTeam Agent CLI entrypoint."""

import asyncio
import logging
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

app = typer.Typer(
    name="vulnchain",
    help="RedTeam Agent — AI-powered security auditing.",
    add_completion=False,
)
console = Console()


def _setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@app.command("scan")
def cmd_scan(
    target: str = typer.Argument(..., help="Repository URL or local path to scan"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    local: bool = typer.Option(False, "--local"),
    pr_number: int | None = typer.Option(None, "--pr"),
    pr_sha: str | None = typer.Option(None, "--sha"),
    log_level: str = typer.Option("INFO", "--log-level"),
) -> None:
    """Scan a repository for security vulnerabilities."""
    _setup_logging(log_level)
    scan_id = str(uuid.uuid4())
    console.print(Panel(f"[bold green]RedTeam Agent[/bold green]\nScan ID: {scan_id}\nTarget: {target}"))

    async def _run() -> None:
        from vulnchain.agent.graph import build_graph

        graph = build_graph()
        initial_state = {
            "repo_url": target,
            "pr_number": pr_number,
            "commit_sha": pr_sha,
            "scan_id": scan_id,
            "is_local": local,
            "repo_path": "",
            "source_files": [],
            "commit_history": [],
            "ast_results": [],
            "semgrep_findings": [],
            "ai_code_segments": [],
            "joern_findings": [],
            "threat_model": None,
            "attack_chains": [],
            "report_markdown": "",
            "report_sarif": {},
            "error": None,
        }

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
        ) as progress:
            task = progress.add_task("Running scan pipeline...", total=None)
            final_state = await graph.ainvoke(initial_state)
            progress.update(task, description="Scan complete.")

        if final_state.get("error"):
            console.print(f"[bold red]Scan failed:[/bold red] {final_state['error']}")
            raise typer.Exit(code=1)

        report = final_state.get("report_markdown", "")
        if output:
            output.write_text(report, encoding="utf-8")
            console.print(f"[green]Report written to:[/green] {output}")
        else:
            console.print(report)

        table = Table(title="Scan Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right")
        table.add_row("Semgrep findings", str(len(final_state.get("semgrep_findings", []))))
        table.add_row("Joern findings", str(len(final_state.get("joern_findings", []))))
        table.add_row("Attack chains", str(len(final_state.get("attack_chains", []))))
        table.add_row("AI code segments", str(len(final_state.get("ai_code_segments", []))))
        console.print(table)

    asyncio.run(_run())


@app.command("results")
def cmd_results(scan_id: str = typer.Argument(...)) -> None:
    """Show scan results from the database."""
    _setup_logging()

    async def _run() -> None:
        from vulnchain.db.connection import get_conn

        async with get_conn() as conn:
            scan = await conn.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
            if not scan:
                console.print(f"[red]Scan not found:[/red] {scan_id}")
                raise typer.Exit(code=1)
            findings = await conn.fetch(
                "SELECT * FROM findings WHERE scan_id = $1 ORDER BY severity, created_at", scan_id
            )
            chains = await conn.fetch("SELECT * FROM attack_chains WHERE scan_id = $1", scan_id)

        console.print(
            Panel(
                f"[bold]Scan {scan_id}[/bold]\nStatus: {scan['status']}\n"
                f"Repo: {scan['repo_url']}\nFindings: {len(findings)}\nChains: {len(chains)}"
            )
        )

        if findings:
            table = Table(title="Findings")
            table.add_column("Severity")
            table.add_column("Source")
            table.add_column("Rule")
            table.add_column("File:Line")
            table.add_column("Message")
            for f in findings:
                table.add_row(
                    f["severity"],
                    f["source"],
                    f["rule_id"],
                    f"{f['file_path']}:{f['line_start'] or ''}",
                    f["message"][:80],
                )
            console.print(table)

    asyncio.run(_run())


@app.command("list")
def cmd_list(limit: int = typer.Option(10, "--limit", "-n")) -> None:
    """List recent scans from the database."""
    _setup_logging()

    async def _run() -> None:
        from vulnchain.db.connection import get_conn

        async with get_conn() as conn:
            rows = await conn.fetch(
                "SELECT id, repo_name, status, created_at, "
                "(SELECT COUNT(*) FROM findings WHERE scan_id = scans.id) AS finding_count "
                "FROM scans ORDER BY created_at DESC LIMIT $1",
                limit,
            )
        table = Table(title=f"Recent Scans (last {limit})")
        table.add_column("ID", style="dim")
        table.add_column("Repo")
        table.add_column("Status")
        table.add_column("Findings")
        table.add_column("Created")
        for row in rows:
            table.add_row(
                str(row["id"])[:8] + "...",
                row["repo_name"],
                row["status"],
                str(row["finding_count"]),
                str(row["created_at"]),
            )
        console.print(table)

    asyncio.run(_run())


@app.command("serve")
def cmd_serve(
    port: int = typer.Option(8000, "--port", "-p"),
    host: str = typer.Option("0.0.0.0", "--host"),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """Start the FastAPI REST API server."""
    _setup_logging()
    import uvicorn

    from vulnchain.api.app import create_app

    console.print(f"[green]Starting RedTeam API server on {host}:{port}[/green]")
    uvicorn.run(create_app(), host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
