"""Repository cloning and source file collection."""

import logging
import os
import shutil
from pathlib import Path

import git
from git import Repo

from vulnchain.config import get_settings
from vulnchain.ingestion.models import CommitInfo, SourceFile

logger = logging.getLogger(__name__)

LANGUAGE_MAP: dict[str, str] = {
    ".cs": "csharp",
    ".csx": "csharp",
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".php": "php",
    ".swift": "swift",
    ".rs": "rust",
    ".go": "go",
    ".java": "java",
}

SKIP_DIRS: frozenset[str] = frozenset([
    "node_modules", ".git", "bin", "obj", "dist", "build",
    ".next", "vendor", "__pycache__", ".venv", "venv",
    ".tox", "coverage", ".mypy_cache", ".ruff_cache",
])

MAX_FILE_SIZE_BYTES = 500 * 1024  # 500 KB


class RepoIngestionError(Exception):
    """Raised when repo cloning or file collection fails."""


def _sandbox_dir(scan_id: str) -> Path:
    settings = get_settings()
    sandbox = settings.scan_sandbox_dir / scan_id
    sandbox.mkdir(parents=True, exist_ok=True)
    return sandbox


def clone_repo(repo_url: str, scan_id: str) -> Path:
    """
    Clone a remote git repository into the scan sandbox.

    Clones to /tmp/vulnchain-scans/{scan_id}/repo — never to the project directory.
    """
    target_dir = _sandbox_dir(scan_id) / "repo"

    if target_dir.exists():
        shutil.rmtree(target_dir)

    logger.info("Cloning %s → %s", repo_url, target_dir)
    try:
        Repo.clone_from(repo_url, str(target_dir), depth=50, no_single_branch=True)
    except git.exc.GitCommandError as exc:
        raise RepoIngestionError(f"Failed to clone {repo_url}: {exc}") from exc

    return target_dir


def open_local_repo(local_path: str, scan_id: str) -> Path:
    """Validate and return path to a local repository."""
    path = Path(local_path).resolve()
    if not path.is_dir():
        raise RepoIngestionError(f"Local path does not exist: {path}")
    return path


def collect_source_files(repo_path: Path) -> list[SourceFile]:
    """Walk the repository and collect all supported source files."""
    source_files: list[SourceFile] = []

    for root, dirs, files in os.walk(repo_path):
        # Prune skip directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

        for filename in files:
            file_path = Path(root) / filename
            ext = file_path.suffix.lower()

            if ext not in LANGUAGE_MAP:
                continue

            size = file_path.stat().st_size
            if size > MAX_FILE_SIZE_BYTES:
                logger.debug("Skipping large file %s (%d bytes)", file_path, size)
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("Cannot read %s: %s", file_path, exc)
                continue

            source_files.append(SourceFile(
                path=file_path,
                relative_path=str(file_path.relative_to(repo_path)),
                language=LANGUAGE_MAP[ext],
                content=content,
                size_bytes=size,
            ))

    logger.info("Collected %d source files from %s", len(source_files), repo_path)
    return source_files


def collect_commit_history(repo_path: Path, max_commits: int = 100) -> list[CommitInfo]:
    """Extract recent commit history from a git repository."""
    try:
        repo = Repo(str(repo_path), search_parent_directories=True)
    except git.exc.InvalidGitRepositoryError:
        logger.warning("Not a git repository: %s", repo_path)
        return []

    commits: list[CommitInfo] = []
    try:
        for commit in repo.iter_commits(max_count=max_commits):
            try:
                stats = commit.stats
                files_changed = list(stats.files.keys())
                total = stats.total
            except Exception:  # noqa: BLE001
                files_changed = []
                total = {"insertions": 0, "deletions": 0}

            commits.append(CommitInfo(
                sha=commit.hexsha,
                message=commit.message.strip(),
                author=str(commit.author.name),
                author_email=str(commit.author.email),
                timestamp=int(commit.committed_date),
                files_changed=files_changed,
                additions=total.get("insertions", 0),
                deletions=total.get("deletions", 0),
            ))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error reading commit history: %s", exc)

    return commits


def cleanup_scan_dir(scan_id: str) -> None:
    """Remove the scan sandbox directory to free disk space."""
    settings = get_settings()
    sandbox = settings.scan_sandbox_dir / scan_id
    if sandbox.exists():
        shutil.rmtree(sandbox)
        logger.info("Cleaned up scan directory: %s", sandbox)
