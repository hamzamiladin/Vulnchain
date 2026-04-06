"""Data models for the ingestion subsystem."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SourceFile:
    """Represents a single source file collected from a repository."""

    path: Path
    relative_path: str
    language: str
    content: str
    size_bytes: int


@dataclass
class CommitInfo:
    """Represents a git commit."""

    sha: str
    message: str
    author: str
    author_email: str
    timestamp: int  # Unix timestamp
    files_changed: list[str] = field(default_factory=list)
    additions: int = 0
    deletions: int = 0
